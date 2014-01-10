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
#include "policy/kasp.pb.h"
#include "xmlext-pb/xmlext-rd.h"
#include "xmlext-pb/xmlext-wr.h"

#include <memory>
#include <vector>
#include <fcntl.h>
#include <set>

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

/* Load zones from database
 * conn: Open connection to the database
 * zones_db: set to add zones from database to.
 * return: 0 on succes, 1 on error.
 * */
static int
get_zones_from_db(OrmConnRef *conn, std::set<std::string> &zones_db)
{
	OrmResultRef result;
	::ods::keystate::EnforcerZone enfzone;
	int err = !OrmMessageEnum(*conn, enfzone.descriptor(), result);
	if (err) return 1;
	for (bool next=OrmFirst(result); next; next = OrmNext(result)) {
		OrmContextRef context;
		if (!OrmGetMessage(result, enfzone, false, context)) {
			err = 1;
			break;
		}
		zones_db.insert(enfzone.name());
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
	
	/* Preprocess zones in zonelist and database to speed up insertion.
	 * Unordered sets would be even better, but then we need to
	 * compile with c++11.
	 * */
	std::set<std::string> zones_db, zones_import, zones_delete;
	typedef std::set<std::string>::iterator item;
	
	if (get_zones_from_db(&conn, zones_db)) {
		ods_log_error_and_printf(sockfd, module_str, "error reading database");
		return 0;
	}
	for (int i=0; i<zonelistDoc->zonelist().zones_size(); ++i) {
		const ::ods::keystate::ZoneData &zl_zone = 
			zonelistDoc->zonelist().zones(i);
		zones_import.insert(zl_zone.name());
	}
	for (item iterator = zones_db.begin(); iterator != zones_db.end(); iterator++) {
       if (!zones_import.count(*iterator))
			zones_delete.insert(*iterator);
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
			ods_printf(sockfd, "Zone %s found in zonelist.xml;" 
				" with policy set to %s\n", zl_zone.name().c_str(),
				zl_zone.policy().c_str());
				
				
			// Now lets query for the policy to check it exists
			std::string qpolicy;
			if (!OrmQuoteStringValue(conn, std::string(zl_zone.policy().c_str()), qpolicy)) {
				ods_log_error_and_printf(sockfd, module_str,
										 "quoting a string failed");
				return 0;
			}			
			
			OrmResultRef rows;
			::ods::kasp::Policy ks_policy;
			if (!OrmMessageEnumWhere(conn, ks_policy.descriptor(), rows,
									 "name = %s",qpolicy.c_str()))
			{
				ods_log_error_and_printf(sockfd, module_str,
										 "policy lookup by name for %s failed", qpolicy.c_str());
				return 0;
			}
		
			// if OrmFirst failes, no policy with the queried name is 
			// present
			if (!OrmFirst(rows)) {
				ods_log_error_and_printf(sockfd,
										 module_str,
										 "Failed to Import zone %s; "
										 "Error, can't find policy : %s",
										 zl_zone.name().c_str(), zl_zone.policy().c_str());
				return 0;
			}				
			rows.release();

			// Now lets process the zone
			std::string qzone;
			if (!OrmQuoteStringValue(conn, zl_zone.name(), qzone)) {
				ods_log_error_and_printf(sockfd, module_str,
					"quoting a string failed");
				return 0;
			}

			/* Lookup zone in database.
			 * We first lookup the zone in a set. Doing this gives us
			 * a near O(n) complexity. The enum function slows down
			 * as DB size increases. */
			::ods::keystate::EnforcerZone ks_zone;
			if (zones_db.count(zl_zone.name())) {
				if (!OrmMessageEnumWhere(conn, ks_zone.descriptor(), rows,
					"name = %s", qzone.c_str()))
				{
					ods_log_error_and_printf(sockfd, module_str,
						"zone lookup by name failed");
					return 0;
				}
			}

			OrmContextRef context;
			if (OrmFirst(rows)) {
				/* Zone already in database, retrieve it. */
				ods_printf(sockfd, "Zone %s found in database. ", zl_zone.name().c_str());
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
			ks_zone.set_signconf_needs_writing( true );

			if (OrmFirst(rows)) {
				/* update */
				if (!OrmMessageUpdate(context)) {
					ods_log_error_and_printf(sockfd, module_str,
						"zone update failed");
					return 0;
				}
				ods_printf(sockfd, "Updated zone %s in database\n", zl_zone.name().c_str());
			} else {
				/* insert */
				ods_printf(sockfd, "Zone %s not found in database. ", zl_zone.name().c_str());
				pb::uint64 zoneid;
				if (!OrmMessageInsert(conn, ks_zone, zoneid)) {
					ods_log_error_and_printf(sockfd, module_str,
						"inserting zone into the database failed");
					return 0;
				}
				ods_printf(sockfd, "Added zone %s to database\n", zl_zone.name().c_str());
			}
			rows.release();
        }
		if (!transaction.commit()) {
			ods_log_error_and_printf(sockfd, module_str,
				"committing zone to the database failed");
			return 0;
		}
    }

	for (item iterator = zones_delete.begin(); iterator != zones_delete.end(); iterator++) {
		ods_printf(sockfd, "Zone %s not found in zonelist.xml\n", iterator->c_str());			
		perform_zone_del(sockfd, config, iterator->c_str(), 0, true);
		ods_printf(sockfd, "Deleted zone %s from database\n", iterator->c_str());		
	}

	/* write internal zonelist */
	if (!perform_write_signzone_file(sockfd, config)) {
		ods_log_error_and_printf(sockfd, module_str, 
			"failed to write internal zonelist");
		return 0;
	}
	return 1;
}
