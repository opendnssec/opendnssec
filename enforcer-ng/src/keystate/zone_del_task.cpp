/*
 * Copyright (c) 2011 Surfnet 
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2011 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "shared/duration.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "keystate/zone_del_task.h"
#include "keystate/write_signzone_task.h"
#include "keystate/zonelist_task.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "daemon/clientpipe.h"
#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <fcntl.h>

static const char *module_str = "zone_del_task";

static bool 
delete_zone_from_zones_file(const std::string& zone_name, engineconfig_type *config, int sockfd) {

	::ods::keystate::ZoneListDocument  zonelistDoc;
	bool zone_not_found = true;
	bool file_not_found = true;	

	// The find out if the zones.xml file exists
	// This may be the first ever zone, or something could have happened to the file...	
	if (!load_zones_file(zonelistDoc, file_not_found, config, sockfd)) {
		ods_log_info("[%s] Can't load internal zone list ", module_str);
		if (file_not_found) {
			// It simply doesn't exist, so do a bulk export instead and we are done
			return perform_write_zones_file(sockfd, config);			
		}
		else {
			// If we can't load it and it isn't because it doesn't exist then bail
			ods_log_info("[%s] Can't load internal zone list ", module_str);
			return false;
		}			
	}

	// Now lets find the zone so we can remove it..
	// TODO: Is there a better way to do this search (load into a set)?
	::ods::keystate::ZoneList* zone_list = zonelistDoc.mutable_zonelist();
	for (int i=0; i < zone_list->zones_size(); ++i) {
		if (zone_name.compare(zone_list->zones(i).name())  == 0) {
			// According to the Google protobuf documentation this is how you remove elements
			// if you DON'T need to preserve the order. I don't believe the order matters
			// in this internal zone list file so I will do it this way as it is more efficient
			// than the alternative.
			zone_list->mutable_zones()->SwapElements(i, zone_list->zones_size() - 1);
			zone_list->mutable_zones()->RemoveLast();			
			zone_not_found = false;
			break;
		}
	}

	if (zone_not_found) {
		ods_log_error_and_printf(sockfd, module_str, "ERROR: Zone %s not found in zones.xml", zone_name.c_str());
		return false;
	}

	// And now lets spit it out to disk
	ods_log_debug("[%s] Incrementing contents of zone list to delete zone %s", module_str, zone_name.c_str());
	return dump_zones_file(zonelistDoc, config, sockfd);
}


int 
perform_zone_del(int sockfd, engineconfig_type *config, const char *zone, int need_write_xml, bool quiet, bool export_files)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return 1; // error already reported.

	std::string qzone;
    bool is_del_succeed = false;
    ::ods::keystate::EnforcerZone enfzone;
    if (strlen(zone) > 0) {
        if (!OrmQuoteStringValue(conn, std::string(zone), qzone)) {
            const char *emsg = "quoting zone value failed";
            ods_log_error_and_printf(sockfd,module_str,emsg);
            return 1;
        }
    }
	
	{	OrmTransactionRW transaction(conn);
		if (!transaction.started()) {
			const char *emsg = "could not start database transaction";
			ods_log_error_and_printf(sockfd,module_str,emsg);
			return 1;
		}
		
        if (qzone.empty()) {
            OrmResultRef rows;
            std::vector<std::string> del_zones;
            bool ok = OrmMessageEnum(conn, enfzone.descriptor(), rows);
            if (!ok) {
                transaction.rollback();
                ods_log_error("[%s] enum enforcer zone failed", module_str);
                return 1;
            }

            for (bool next=OrmFirst(rows); next; next = OrmNext(rows)) {
                OrmContextRef context;
                if (!OrmGetMessage(rows, enfzone, true, context)) {
                    rows.release();
                    transaction.rollback();
                    ods_log_error("[%s] retrieving zone from database failed");
                    return 1;
                }

                del_zones.push_back(enfzone.name());
            }
            rows.release();

            for (std::vector<std::string>::iterator it = del_zones.begin(); 
                    it != del_zones.end(); ++it) {
	            std::string del_zone;
                if (!OrmQuoteStringValue(conn, std::string(*it), del_zone)) {
                    transaction.rollback();
                    const char *emsg = "quoting zone value failed";
                    ods_log_error_and_printf(sockfd,module_str,emsg);
                    return 1;
                }
                if (!OrmMessageDeleteWhere(conn,
                            ::ods::keystate::EnforcerZone::descriptor(),
                            "name = %s",
                            del_zone.c_str())) {
                    transaction.rollback();
                    const char *emsg = "unable to delete zone %s";
                    ods_log_error_and_printf(sockfd,module_str,emsg, it->c_str());
                    return 1;
                }

                is_del_succeed = true;
            }
        }
        else {
            //find the zone
            OrmResultRef rows;
            if (!OrmMessageEnumWhere(conn, 
                        ::ods::keystate::EnforcerZone::descriptor(),
                        rows,
                        "name = %s",
                        qzone.c_str())) {
                transaction.rollback();
                ods_log_error_and_printf(sockfd, module_str, 
                        "unable to find zone %s", qzone.c_str());
                return 1;
            }

            if (!OrmFirst(rows)) {
                rows.release();
                transaction.rollback();
                ods_log_error_and_printf(sockfd, module_str, 
                        "Couldn't find zone %s", qzone.c_str());
                return 1;
            }

            rows.release();

            if (!OrmMessageDeleteWhere(conn,
                        ::ods::keystate::EnforcerZone::descriptor(),
                        "name = %s",
                        qzone.c_str()))
            {
                transaction.rollback();
                const char *emsg = "unable to delete zone %s";
                ods_log_error_and_printf(sockfd,module_str,emsg,qzone.c_str());
                return 1;
            }

            is_del_succeed = true;
        }
		
		if (!transaction.commit()) {
			const char *emsg = "committing delete of zone %s to database failed";
			ods_log_error_and_printf(sockfd,module_str,emsg,qzone.c_str());
			return 1;
		}
    }


    if (!is_del_succeed)
		return 1; 

	// TODO: In 1.4 the signconf is renamed to avoid future clashes

	// Now lets write out the required files - the internal list and optionally the zonelist.xml	
	if (export_files) {
		// This command can be used to delete a specific zone or all zones
		// If is it just for a single zone, we can do an incremental change
		if (strlen(zone) > 0) {
			if (!delete_zone_from_zones_file(std::string(zone), config, sockfd)) {
	        	ods_log_error_and_printf(sockfd, module_str, 
	                "failed to increment contents of internal zone list file");
			}
		}
		else {
			// we need to do a bulk export to empty out the zone list
			perform_write_zones_file(sockfd, config);
		}

		// For the external list, we always to a bulk export 
 	   if (need_write_xml) {
			if (!perform_zonelist_export_to_file(config->zonelist_filename,config)) {
	        	ods_log_error_and_printf(sockfd, module_str, 
	                	"failed to write zonelist.xml");
			}
			if (!quiet) {
				if (qzone.empty()) {
					client_printf(sockfd, "Deleted all zones in database and zonelist.xml updated.\n");
				} else {
					client_printf(sockfd, "Deleted zone: %s in database and zonelist.xml updated.\n", zone);
				}
			}
		} else if (!quiet) {
			if (qzone.empty()) {
				client_printf(sockfd, "Deleted all zones in database only. Use the --xml flag or run \"ods-enforcer zonelist export\" if an update of zonelist.xml is required.\n", zone);
			} else {
				client_printf(sockfd, "Deleted zone: %s in database only. Use the --xml flag or run \"ods-enforcer zonelist export\" if an update of zonelist.xml is required.\n", zone);
			}
		}
	}

	ods_log_info("[%s] deleted Zone: %s", module_str, zone);
	return 0;
}
