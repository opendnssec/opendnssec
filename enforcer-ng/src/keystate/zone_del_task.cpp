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
#include "shared/str.h"
#include "keystate/zone_del_task.h"
#include "keystate/write_signzone_task.h"
#include "keystate/zonelist_task.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"

#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <fcntl.h>

static const char *module_str = "zone_del_task";

int 
perform_zone_del(int sockfd, engineconfig_type *config, const char *zone, int need_write_xml, bool quiet)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return 1; // error already reported.

	std::string qzone;
    bool is_del_succeed = false;
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
            ::ods::keystate::EnforcerZone enfzone;
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


	// Now lets write out the required files - the internal list and optionally the zonelist.xml
	// Note at the moment we re-export the whole file in zonelist.xml format here but this should be optimised....
    if (is_del_succeed) {
		if (!perform_write_signzone_file(sockfd, config)) {
        	ods_log_error_and_printf(sockfd, module_str, 
                "failed to write internal zonelist");
		}

 	   if (need_write_xml) {
			if (!perform_zonelist_export_to_file(config->zonelist_filename,config)) {
	        	ods_log_error_and_printf(sockfd, module_str, 
	                	"failed to write zonelist.xml");
			}
			if (!quiet) {
				if (qzone.empty()) {
					ods_printf(sockfd, "Deleted all zones in database and zonelist.xml updated.\n");
				} else {
					ods_printf(sockfd, "Deleted zone: %s in database and zonelist.xml updated.\n", zone);
				}
			}
		} else if (!quiet) {
			if (qzone.empty()) {
				ods_printf(sockfd, "Deleted all zones in database only. Use the --xml flag or run \"ods-enforcer zonelist export\" if an update of zonelist.xml is required.\n", zone);
			} else {
				ods_printf(sockfd, "Deleted zone: %s in database only. Use the --xml flag or run \"ods-enforcer zonelist export\" if an update of zonelist.xml is required.\n", zone);
			}
		}
	}
	return 0;
}
