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

#include "update_kasp_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "utils/kc_helper.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "kasp.pb.h"

#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <memory>
#include <fcntl.h>

static const char *module_str = "update_kasp_task";

static bool
load_kasp_xml(int sockfd, const char * policiesfile,
			  std::auto_ptr< ::ods::kasp::KaspDocument >&doc)
{
	// Create a kasp document and load it with policies from the kasp.xml file
	doc.reset(new ::ods::kasp::KaspDocument);
	if (doc.get() == NULL) {
		ods_log_error_and_printf(sockfd,module_str,
								 "out of memory allocating KaspDocument");
		return false;
	}
	
	if (!read_pb_message_from_xml_file(doc.get(), policiesfile)) {
		ods_log_error_and_printf(sockfd, module_str,
								 "reading and processing kasp.xml file failed");
		return false;
	}
	
	if (!doc->has_kasp()) {
		ods_log_error_and_printf(sockfd, module_str,
								 "no policies found in kasp.xml file");
		return false;
	}
	
	const ::ods::kasp::KASP  &kasp = doc->kasp();
	if (kasp.policies_size() <= 0) {
		ods_log_error_and_printf(sockfd, module_str,
								 "no policies found in kasp.xml file");
		return false;
	}
	
	if (!kasp.IsInitialized()) {
		ods_log_error_and_printf(sockfd, module_str,
								 "a policy loaded from kasp.xml file is "
								 "lacking essential information");
		return false;
	}
	
	return true;
}


bool 
perform_update_kasp(int sockfd, engineconfig_type *config)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	if (check_kasp(config->policy_filename, NULL, 0, 0)) {
		ods_log_error_and_printf(sockfd, module_str,
			"Unable to validate '%s' consistency.", config->policy_filename);
		return false;
	}

	std::auto_ptr< ::ods::kasp::KaspDocument > kaspDoc;
	if (!load_kasp_xml(sockfd, config->policy_filename, kaspDoc))
		return false; // errors have already been reported.
	
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return false;  // errors have already been reported.

	//TODO: SPEED: We should create an index on the Policy.name column
	
	OrmTransactionRW transaction(conn);
	if (!transaction.started()) {
		ods_log_error_and_printf(sockfd, module_str,
								 "starting a database transaction for "
								 "updating a policy failed");
		return false;
	}	
	
    // Go through the list of policies from the kasp.xml file to determine
	// if we need to insert new policies to the policies table.
    for (int i=0; i<kaspDoc->kasp().policies_size(); ++i) {
        const ::ods::kasp::Policy &policy = kaspDoc->kasp().policies(i);
		
		{			
			std::string qpolicy;
			ods_log_debug("policy %s found ", policy.name().c_str());
			if (!OrmQuoteStringValue(conn, policy.name(), qpolicy)) {
				ods_log_error_and_printf(sockfd, module_str,
										 "quoting a string failed");
				return false;
			}
			
			//TODO: We should do an update for existing policies. 
			//TODO: As I would hope this failed due to foreign key violations!!
			
			// delete the existing policy from the database
			if (!OrmMessageDeleteWhere(conn, policy.descriptor(),
									   "name=%s",qpolicy.c_str())) {
				ods_log_error_and_printf(sockfd, module_str,
										 "failed to delete policy with "
										 "name %s",policy.name().c_str());
				return false;
			}
				
			// insert the policy we read from the kasp.xml file.
			pb::uint64 policyid;
			if (!OrmMessageInsert(conn, policy, policyid)) {
				ods_log_error_and_printf(sockfd, module_str,
							"inserting policy into the database failed");
				return false;
			}
		}
    }
	// commit the update policy to the database.
	if (!transaction.commit()) {
		ods_log_error_and_printf(sockfd, module_str,
								 "committing policy to the database failed");
		return false;
	}
	
	ods_log_info("[%s] kasp loaded from %s", module_str, config->policy_filename);
	ods_printf(sockfd,"kasp loaded from %s\n", config->policy_filename);	

	return true;
}
