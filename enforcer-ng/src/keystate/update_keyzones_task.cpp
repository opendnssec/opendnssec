/*
 * $Id$
 *
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

#include "keystate/update_keyzones_task.h"
#include "keystate/zone_del_task.h"
#include "shared/file.h"
#include "shared/duration.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"
#include "xmlext-pb/xmlext-wr.h"

#include <memory>
#include <vector>
#include <fcntl.h>

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"
#include "keystate/write_signzone_task.h"

static const char *module_str = "update_keyzones_task";

static bool
load_zonelist_xml(int sockfd, const char * zonelistfile,
				  std::auto_ptr< ::ods::keystate::ZoneListDocument >&doc)
{
	// Create a zonefile and load it with zones from the xml zonelist.xml
	doc.reset(new ::ods::keystate::ZoneListDocument);
	if (doc.get() == NULL) {
		ods_log_error_and_printf(sockfd,module_str,
								 "out of memory allocating ZoneListDocument");
		return false;
	}
	
	if (!read_pb_message_from_xml_file(doc.get(), zonelistfile)) {
		ods_log_error_and_printf(sockfd,module_str,
								 "unable to read the zonelist.xml file");
		return false;
	}
		
	if (!doc->has_zonelist()) {
        ods_printf(sockfd, "[%s] no zonelist found in zonelist.xml file\n",
                    module_str);
        return true;
	}
		
	const ::ods::keystate::ZoneList  &zonelist = doc->zonelist();
	if (zonelist.zones_size() <= 0) {
        ods_printf(sockfd, "[%s] no zones found in zonelist\n", module_str);
        return true;
	}
	
	if (!zonelist.IsInitialized()) {
		ods_log_error_and_printf(sockfd,module_str,
								 "a zone in the zonelist is missing mandatory "
								 "information");
		return false;
	}

	return true;
}

static int
get_zones_from_db(OrmConnRef *conn, std::map<std::string, bool> zones_db)
{
	OrmResultRef result;
	::ods::keystate::EnforcerZone enfzone;
	int err = !OrmMessageEnum(*conn, enfzone.descriptor(), result);
	if (err) return 0;
	for (bool next=OrmFirst(result); next; next = OrmNext(result)) {
		OrmContextRef context;
		if (!OrmGetMessage(result, enfzone, true, context)) {
			err = 1;
			break;
		}
		zones_db[enfzone.name()] = true;
	}
	result.release();
	return err;
}

int 
perform_update_keyzones(int sockfd, engineconfig_type *config)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	std::auto_ptr< ::ods::keystate::ZoneListDocument > zonelistDoc;
	if (!load_zonelist_xml(sockfd, config->zonelist_filename, zonelistDoc))
		return 0; // errors have already been reported.

	ods_printf(sockfd, "zonelist filename set to %s\n", 
		config->zonelist_filename);

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return 0;  // errors have already been reported.

	//TODO: SPEED: We should create an index on the EnforcerZone.name column
		
	// Go through the list of zones from the zonelist to determine if we need
	// to insert new zones to the keystates.
	std::map<std::string, bool> zoneimported;
	
	/* first make a map with all current zones
	 * then iterate new zones to filter current */
	
	std::map<std::string, bool> zones_db;
	std::map<std::string, bool> zones_import;
	std::map<std::string, bool> zones_delete;
	std::map<std::string, bool> zones_new;
	std::map<std::string, bool> zones_update;
	typedef std::map<std::string, bool>::iterator item;
	
	get_zones_from_db(&conn, zones_db);
	for (int i=0; i<zonelistDoc->zonelist().zones_size(); ++i) {
		const ::ods::keystate::ZoneData &zl_zone = 
				zonelistDoc->zonelist().zones(i);
		zones_import[zl_zone.name()] = true;
	}
	for (item iterator = zones_import.begin(); iterator != zones_import.end(); iterator++) {
       if (zones_db[iterator->first])
			zones_delete[iterator->first] = true;
	}
	for (item iterator = zones_db.begin(); iterator != zones_db.end(); iterator++) {
       if (!zones_update[iterator->first])
			zones_update[iterator->first] = true;
		else
			zones_new[iterator->first] = true;
	}

	//non-empty zonelist
	if (zonelistDoc->has_zonelist()) {
		OrmTransactionRW transaction(conn);
		if (!transaction.started()) {
			ods_log_error_and_printf(sockfd, module_str,
				"error starting a database transaction for updating zones");
			return 0;
		}
		for (int i=0; i<zonelistDoc->zonelist().zones_size(); ++i) {
			const ::ods::keystate::ZoneData &zl_zone = 
				zonelistDoc->zonelist().zones(i);
			//~ zoneimported[zl_zone.name()] = true;
			ods_printf(sockfd, "Zone %s found in zonelist.xml;" 
				" policy set to %s\n", zl_zone.name().c_str(),
				zl_zone.policy().c_str());

			std::string qzone;
			if (!OrmQuoteStringValue(conn, zl_zone.name(), qzone)) {
				ods_log_error_and_printf(sockfd, module_str,
					"quoting a string failed");
				return 0;
			}

			/* Lookup zone in database */
			::ods::keystate::EnforcerZone ks_zone;
			OrmResultRef rows;
			/* check if qzone in zones_update */
			bool update = zones_update[qzone];
			if (update)
				if (!OrmMessageEnumWhere(conn, ks_zone.descriptor(), rows,
					"name = %s",qzone.c_str()))
				{
					ods_log_error_and_printf(sockfd, module_str,
						"zone lookup by name failed");
					return 0;
				}

			OrmContextRef context;
			if (OrmFirst(rows)) {
				/* Zone already in database, retrieve it. */
				ods_printf(sockfd, "Zone: %s found in database,"
					" update it\n", zl_zone.name().c_str());
				if (!OrmGetMessage(rows, ks_zone, true, context)) {
					ods_log_error_and_printf(sockfd, module_str,
							"zone retrieval failed");
					return 0;
				}
			}
			/* Update the zone with information from the zonelist entry */
			ks_zone.set_name(zl_zone.name());
			ks_zone.set_policy(zl_zone.policy());
			ks_zone.set_signconf_path(
					zl_zone.signer_configuration());
			ks_zone.mutable_adapters()->CopyFrom(
					zl_zone.adapters());

			if (OrmFirst(rows)) {
				/* update */
				if (!OrmMessageUpdate(context)) {
					ods_log_error_and_printf(sockfd, module_str,
						"zone update failed");
					return 0;
				}
			} else {
				/* insert */
				ks_zone.set_signconf_needs_writing( false );
				ods_printf(sockfd, "Zone: %s not found in database,"
					" insert it\n", zl_zone.name().c_str());
				pb::uint64 zoneid;
				if (!OrmMessageInsert(conn, ks_zone, zoneid)) {
					ods_log_error_and_printf(sockfd, module_str,
						"inserting zone into the database failed");
					return 0;
				}
			}
			rows.release();
        }
		if (!transaction.commit()) {
			ods_log_error_and_printf(sockfd, module_str,
				"committing zone to the database failed");
			return 0;
		}
    }

    std::vector<std::string> non_exist_zones;
    //delete non-exist zone
    {  
        OrmTransaction transaction(conn);
        if (!transaction.started()) {
            ods_log_error_and_printf(sockfd, module_str, 
                    "starting database transaction failed");
            return 0;
        }
    
        {   OrmResultRef rows;
            ::ods::keystate::EnforcerZone enfzone;
    
            bool ok = OrmMessageEnum(conn, enfzone.descriptor(), rows);
            if (!ok) {
                ods_log_error_and_printf(sockfd, module_str, 
                        "zone enumaration failed");
                return 0;
            }
    
            for (bool next=OrmFirst(rows); next; next = OrmNext(rows)) {
                 OrmContextRef context;
                 if (!OrmGetMessage(rows, enfzone, true, context)) {
                     rows.release();
                     ods_log_error_and_printf(sockfd, module_str, 
                             "retrieving zone from database failed");
                     return 0;
                 }

                 //zone is not in zonelist.xml, then delete it
                 if (!zones_import[enfzone.name()]) {
                     non_exist_zones.push_back(enfzone.name());
                 }
            }
            
            rows.release();
        }

        if (!transaction.commit()) {
            ods_log_error_and_printf(sockfd, module_str,
                    "committing zone enumeration select failed");
            return 0;
        }
    }

    if (!non_exist_zones.empty()) {
        int del_zone_count = non_exist_zones.size();
        for (int i = 0; i < del_zone_count; ++i) {
            ods_printf(sockfd, "Zone: %s not exist in zonelist.xml, "
                    "delete it from database\n",
                    non_exist_zones[i].c_str());
            perform_zone_del(sockfd, config, 
                    non_exist_zones[i].c_str(),
                    0);
        }
    }

    //write signzones.xml
    if (!perform_write_signzone_file(sockfd, config))
        ods_log_error_and_printf(sockfd, module_str, 
                "failed to write signzones file");

    return 1;
}
