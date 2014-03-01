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

void 
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

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return;  // errors have already been reported.

	{	OrmTransactionRW transaction(conn);
		if (!transaction.started()) {
			ods_log_error_and_printf(sockfd, module_str,
				"starting a database transaction for adding a zone failed");
			return;
		}
		
		std::string qzone;
		std::string qpolicy;
		if (!OrmQuoteStringValue(conn, std::string(zone), qzone)) {
			ods_log_error_and_printf(sockfd, module_str,
									 "quoting a string failed");
			return;
		}
		if (!OrmQuoteStringValue(conn, std::string(policy), qpolicy)) {
			ods_log_error_and_printf(sockfd, module_str,
									 "quoting a string failed");
			return;
		}		

		{	OrmResultRef rows;
			
			::ods::keystate::EnforcerZone ks_zone;
			if (!OrmMessageEnumWhere(conn, ks_zone.descriptor(), rows,
									 "name = %s",qzone.c_str()))
			{
				ods_log_error_and_printf(sockfd, module_str,
										 "zone lookup by name failed");
				return;
			}
		
			// if OrmFirst succeeds, a zone with the queried name is 
			// already present
			if (OrmFirst(rows)) {
				ods_log_error_and_printf(sockfd,
										 module_str,
										 "Failed to Import zone %s; "
                                         "it already exists",
										 zone);
				return;
			}

			// Now lets query for the policy
			rows.release();
			
			::ods::kasp::Policy ks_policy;
			if (!OrmMessageEnumWhere(conn, ks_policy.descriptor(), rows,
									 "name = %s",qpolicy.c_str()))
			{
				ods_log_error_and_printf(sockfd, module_str,
										 "policy lookup by name for %s failed", qpolicy.c_str());
				return;
			}
		
			// if OrmFirst failes, no policy with the queried name is 
			// present
			if (!OrmFirst(rows)) {
				ods_log_error_and_printf(sockfd,
										 module_str,
										 "Failed to Import zone %s; "
										 "Error, can't find policy : %s",
										 zone, policy);
				return;
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
				return;
			}
			
			if (!transaction.commit()) {
				ods_log_error_and_printf(sockfd, module_str,
								"committing zone to the database failed");
				return;
			}
		}
	}

	// Now lets write out the required files - the internal list and optionally the zonelist.xml
	// Note at the moment we re-export the whole file in zonelist.xml format here but this should be optimised....
    if (!perform_write_signzone_file(sockfd, config)) {
        ods_log_error_and_printf(sockfd, module_str, 
                "failed to write internal zonelist");
	}

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

}
