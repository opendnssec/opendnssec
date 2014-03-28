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

#include "keystate/zone_add_task.h"
#include "keystate/zonelist_task.h"
#include "shared/file.h"
#include "shared/duration.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "policy/kasp.pb.h"
#include "xmlext-pb/xmlext-rd.h"

#include <memory>
#include <fcntl.h>
#include <cstring>

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"
#include "keystate/write_signzone_task.h"

static const char *module_str = "zone_add_task";

static bool 
add_zone_to_zones_file(::ods::keystate::EnforcerZone &ks_zone, engineconfig_type *config, int sockfd) {

	::ods::keystate::ZoneListDocument  zonelistDoc;
	bool file_not_found = true;

	// Find out if the zones.xml file exists
	// This may be the first ever zone, or something could have happened to the file...	
	if (!load_zones_file(zonelistDoc, file_not_found, config, sockfd)) {
		if (file_not_found) {
			// It simply doesn't exist, so do a bulk export instead and we are done
			return perform_write_zones_file(sockfd, config);			
		}
		else {
			// If we can't load it and it isn't because it doesn't exist then bail
			ods_log_error("[%s] Can't load internal zone list ", module_str);
			return false;
		}			
	}

	// Now lets see if the zone exists. We must do this to make sure we don't add it twice
	// TODO: Is there a better way to do this search (load data into a set)?
	const ::ods::keystate::ZoneList &zonelist = zonelistDoc.zonelist();
	for (int i=0; i < zonelist.zones_size(); ++i) {
		if (ks_zone.name().compare(zonelist.zones(i).name())  == 0) {
			// Found it, something is wrong. We could delete and re-add but lets bail with an error
			ods_log_error_and_printf(sockfd, module_str, "ERROR: Zone %s already exists in zones.xml",
					ks_zone.name().c_str());
			return false;			
		}
	}

	// All good, so lets add the new zone into the list
    std::auto_ptr< ::ods::keystate::ZoneData > zonedata(new ::ods::keystate::ZoneData);
    zonedata->set_name(ks_zone.name());
    zonedata->set_policy(ks_zone.policy());
    zonedata->set_signer_configuration( ks_zone.signconf_path());
    zonedata->mutable_adapters()->CopyFrom(ks_zone.adapters());
    ::ods::keystate::ZoneData *added_zonedata = zonelistDoc.mutable_zonelist()->add_zones();
    added_zonedata->CopyFrom(*zonedata);

	// And now lets spit it out to disk
	ods_log_debug("[%s] Incrementing contents of zone list to add zone %s", module_str, ks_zone.name().c_str());	
	return dump_zones_file(zonelistDoc, config, sockfd);
}


int 
perform_zone_add(int sockfd,
				 engineconfig_type *config,
				 const char *zone,
				 const char *policy,
				 const char *signerconf,
				 const char *ad_input_file,
				 const char *ad_output_file,
				 const char *ad_input_type,
				 const char *ad_input_config,
				 const char *ad_output_type,
				 const char *ad_output_config,
                 int need_write_xml)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	::ods::keystate::EnforcerZone ks_zone;

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return 1;  // errors have already been reported.

	{	OrmTransactionRW transaction(conn);
		if (!transaction.started()) {
			ods_log_error_and_printf(sockfd, module_str,
				"starting a database transaction for adding a zone failed");
			return 1;
		}
		
		std::string qzone;
		std::string qpolicy;
		if (!OrmQuoteStringValue(conn, std::string(zone), qzone)) {
			ods_log_error_and_printf(sockfd, module_str,
									 "quoting a string failed");
			return 1;
		}
		if (!OrmQuoteStringValue(conn, std::string(policy), qpolicy)) {
			ods_log_error_and_printf(sockfd, module_str,
									 "quoting a string failed");
			return 1;
		}		

		{	OrmResultRef rows;
			
			if (!OrmMessageEnumWhere(conn, ks_zone.descriptor(), rows,
									 "name = %s",qzone.c_str()))
			{
				ods_log_error_and_printf(sockfd, module_str,
										 "zone lookup by name failed");
				return 1;
			}
		
			// if OrmFirst succeeds, a zone with the queried name is 
			// already present
			if (OrmFirst(rows)) {
				ods_log_error_and_printf(sockfd,
										 module_str,
										 "Failed to Import zone %s; "
                                         "it already exists",
										 zone);
				return 1;
			}

			// Now lets query for the policy
			rows.release();
			
			::ods::kasp::Policy ks_policy;
			if (!OrmMessageEnumWhere(conn, ks_policy.descriptor(), rows,
									 "name = %s",qpolicy.c_str()))
			{
				ods_log_error_and_printf(sockfd, module_str,
										 "policy lookup by name for %s failed", qpolicy.c_str());
				return 1;
			}
		
			// if OrmFirst failes, no policy with the queried name is 
			// present
			if (!OrmFirst(rows)) {
				ods_log_error_and_printf(sockfd,
										 module_str,
										 "Failed to Import zone %s; "
										 "Error, can't find policy : %s",
										 zone, policy);
				return 1;
			}


			// query no longer needed, so let's release it.
			rows.release();
			
			// setup information the enforcer will need.
			ks_zone.set_name( zone );
			ks_zone.set_policy( policy );
			ks_zone.set_signconf_path( signerconf );
			if (*ad_input_file) {
				//ks_zone.mutable_adapters()->mutable_input()->set_file(ad_input_file);
				::ods::keystate::Adapter *input =
					ks_zone.mutable_adapters()->mutable_input();
				input->set_type("File");
				input->set_adapter(ad_input_file);
			}
			if (*ad_output_file) {
				//ks_zone.mutable_adapters()->mutable_output()->set_file(ad_output_file);
				::ods::keystate::Adapter *output =
					ks_zone.mutable_adapters()->mutable_output();
				output->set_type("File");
				output->set_adapter(ad_output_file);
			}
			if (*ad_input_type) {
				::ods::keystate::Adapter *input =
					ks_zone.mutable_adapters()->mutable_input();
				input->set_type("DNS");
				input->set_adapter(ad_input_config);
			}
			if (*ad_output_type) {
				::ods::keystate::Adapter *output =
					ks_zone.mutable_adapters()->mutable_output();
				output->set_type("DNS");
				output->set_adapter(ad_output_config);
			}
			
			// Let the enforcer make this decision		
			ks_zone.set_signconf_needs_writing( false );
			
			pb::uint64 zoneid;
			if (!OrmMessageInsert(conn, ks_zone, zoneid)) {
				ods_log_error_and_printf(sockfd, module_str,
								"inserting zone into the database failed");
				return 1;
			}
			
			if (!transaction.commit()) {
				ods_log_error_and_printf(sockfd, module_str,
								"committing zone to the database failed");
				return 1;
			}
		}
	}

	// Now lets write out the required files.
	// Firstly lets do an incremental update on the internal zones.xml file. 
	// We judge this as safe as only the enforcer should write to this file.
    if (!add_zone_to_zones_file(ks_zone, config, sockfd)) {
        ods_log_error_and_printf(sockfd, module_str, 
                "failed to increment contents of internal zone list file");
			return 1;
	}
	
	// Then if the --xml flag was used do a bulk export to zonelist.xml. This is not efficient, but is the only way to
	// ensure this file is a consistent with the database, which is what this flag means.	
    if (need_write_xml) {
		if (!perform_zonelist_export_to_file(config->zonelist_filename,config)) {
        	ods_log_error_and_printf(sockfd, module_str, 
                	"failed to write zonelist.xml");
		}
		ods_printf(sockfd, "Imported zone: %s into database and zonelist.xml updated.\n", zone);
	} else {
		ods_printf(sockfd, "Imported zone: %s into database only. Use the --xml flag or run \"ods-enforcer zonelist export\" if an update of zonelist.xml is required.\n", zone);
	}
	
	ods_log_info("[%s] added Zone: %s", module_str, zone);
	return 0;
}
