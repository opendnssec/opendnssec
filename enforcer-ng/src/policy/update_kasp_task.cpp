#include "update_kasp_task.h"
#include "shared/file.h"
#include "shared/duration.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "kasp.pb.h"

#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <memory.h>
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


void 
perform_update_kasp(int sockfd, engineconfig_type *config)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    std::auto_ptr< ::ods::kasp::KaspDocument > kaspDoc;
	if (!load_kasp_xml(sockfd, config->policy_filename, kaspDoc))
		return; // errors have already been reported.
	
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return;  // errors have already been reported.

	//TODO: SPEED: We should create an index on the Policy.name column
	
    // Go through the list of policies from the kasp.xml file to determine
	// if we need to insert new policies to the policies table.
    for (int i=0; i<kaspDoc->kasp().policies_size(); ++i) {
        const ::ods::kasp::Policy &policy = kaspDoc->kasp().policies(i);
		
		{	OrmTransactionRW transaction(conn);
			if (!transaction.started()) {
				ods_log_error_and_printf(sockfd, module_str,
										 "starting a database transaction for "
										 "updating a policy failed");
				return;
			}
			
			std::string qpolicy;
			if (!OrmQuoteStringValue(conn, policy.name(), qpolicy)) {
				ods_log_error_and_printf(sockfd, module_str,
										 "quoting a string failed");
				return;
			}
			
			// delete the existing policy from the database
			if (!OrmMessageDeleteWhere(conn, policy.descriptor(),
									   "name=%s",qpolicy.c_str())) {
				ods_log_error_and_printf(sockfd, module_str,
										 "failed to delete policy with "
										 "name %s",policy.name().c_str());
				return;
			}
				
			// insert the policy we erad from the kasp.xml file.
			pb::uint64 policyid;
			if (!OrmMessageInsert(conn, policy, policyid)) {
				ods_log_error_and_printf(sockfd, module_str,
							"inserting policy into the database failed");
				return;
			}
			
			// commit the update policy to the database.
			if (!transaction.commit()) {
				ods_log_error_and_printf(sockfd, module_str,
										 "committing policy to the database failed");
				return;
			}
		}
    }
}
