extern "C" {
#include "policies_task.h"
#include "shared/file.h"
#include "shared/duration.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "kasp.pb.h"

#include "xmlext-pb/xmlext.h"


#include <fcntl.h>

static const char *policies_task_str = "policies_task";

void 
perform_policies(int sockfd, engineconfig_type *config)
{
    char buf[ODS_SE_MAXLINE];
	const char *policyfile = config->policy_filename;
    const char *datastore = config->datastore;
    
	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    /*
	// Dump the meta-information of the KaspDocument.
	::google::protobuf::Message *msg  = new ::ods::kasp::KaspDocument;
	recurse_dump_descriptor(msg->GetDescriptor());
	delete msg;
     */
	
	// Create a policy and fill it up with some data.
	::ods::kasp::KaspDocument *doc  = new ::ods::kasp::KaspDocument;
	if (read_pb_message_from_xml_file(doc, policyfile)) {
		if (doc->has_kasp()) {
			const ::ods::kasp::KASP &kasp = doc->kasp();
			if (kasp.policies_size() > 0) {
				if (kasp.IsInitialized()) {
                                        
                    std::string datapath(datastore);
                    datapath += ".policy.pb";
                    int fd = open(datapath.c_str(),O_WRONLY|O_CREAT, 0644);
                    if (doc->SerializeToFileDescriptor(fd)) {
                        ods_log_debug("[%s] policies have been imported", 
                                      policies_task_str);
                        (void)snprintf(buf, ODS_SE_MAXLINE, "import of policies completed.\n");
                        ods_writen(sockfd, buf, strlen(buf));
                    } else {
                        (void)snprintf(buf, ODS_SE_MAXLINE, "error: policies file could not be written.\n");
                        ods_writen(sockfd, buf, strlen(buf));
                    }
                    close(fd);
				} else {
                    (void)snprintf(buf, ODS_SE_MAXLINE, "error: a policy in the policies is missing mandatory information.\n");
                    ods_writen(sockfd, buf, strlen(buf));
                }
			} else {
                (void)snprintf(buf, ODS_SE_MAXLINE, "warning: no policies found in policies list.\n");
                ods_writen(sockfd, buf, strlen(buf));
            }
		} else {
            (void)snprintf(buf, ODS_SE_MAXLINE, "warning: no policies list found in kasp.xml file.\n");
            ods_writen(sockfd, buf, strlen(buf));
        }
    } else {
        (void)snprintf(buf, ODS_SE_MAXLINE, "warning: unable to read the kasp.xml file.\n");
        ods_writen(sockfd, buf, strlen(buf));
    }
	delete doc;
}

static task_type * 
policies_task_perform(task_type *task)
{
    perform_policies(-1,(engineconfig_type *)task->context);
    
    task_cleanup(task);
    return NULL;
}

task_type *
policies_task(engineconfig_type *config)
{
    task_id policies_task_id = task_register_how("policies_task_perform",
                                                 policies_task_perform);
	return task_create(policies_task_id,time_now(),"policies",
                       (void*)config,policies_task_perform);
}
