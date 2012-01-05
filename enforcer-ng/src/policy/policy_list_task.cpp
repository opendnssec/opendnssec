#include "shared/duration.h"
#include "shared/file.h"
#include "policy/policy_list_task.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "kasp.pb.h"

#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <fcntl.h>
#include <memory>

static const char *module_str = "policy_list_task";

void 
perform_policy_list(int sockfd, engineconfig_type *config)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return; // errors have already been reported.
	
	{	OrmTransaction transaction(conn);
		
		if (!transaction.started()) {
			ods_log_error_and_printf(sockfd, module_str,
									 "database transaction failed");
			return;
		}
		
		{	OrmResultRef rows;
			::ods::kasp::Policy policy;
			if (!OrmMessageEnum(conn,policy.descriptor(),rows)) {
				ods_log_error_and_printf(sockfd, module_str,
										"database policy enumeration failed\n");
				return;
			}
			
			if (!OrmFirst(rows)) {
				ods_log_debug("[%s] policy list completed", module_str);
				ods_printf(sockfd,
						   "Database set to: %s\n"
						   "I have no policies configured\n"
						   ,config->datastore);
				return;
			}
			
			ods_printf(sockfd,
						   "Database set to: %s\n"
						   "Policies:\n"
						   "Policy:                         "
						   "Description:"
						   "\n"
						   ,config->datastore);
			
			// Enumerate the hsm keys referenced in the database
			for (bool next=true; next; next=OrmNext(rows)) {

				if (!OrmGetMessage(rows, policy, true)) {
					ods_log_error_and_printf(sockfd, module_str,
										"reading policy from database failed");
					return;
				}
					
				ods_printf(sockfd,"%-31s %-48s\n",policy.name().c_str(),
						   policy.description().c_str());
			}
        }
    }
    ods_log_debug("[%s] policy list completed", module_str);
}
