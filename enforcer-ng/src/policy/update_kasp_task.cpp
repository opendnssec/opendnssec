extern "C" {
#include "update_kasp_task.h"
#include "shared/file.h"
#include "shared/duration.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "kasp.pb.h"

#include "xmlext-pb/xmlext-rd.h"


#include <fcntl.h>

static const char *update_kasp_task_str = "update_kasp_task";

void 
perform_update_kasp(int sockfd, engineconfig_type *config)
{
    char buf[ODS_SE_MAXLINE];
	const char *policyfile = config->policy_filename;
    const char *datastore = config->datastore;
    
	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
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
                                      update_kasp_task_str);
                    } else {
                        (void)snprintf(buf, ODS_SE_MAXLINE, "error: policies"
                                       " file could not be written.\n");
                        ods_writen(sockfd, buf, strlen(buf));
                    }
                    close(fd);
				} else {
                    (void)snprintf(buf, ODS_SE_MAXLINE, "error: a policy in "
                                   "the policies is missing mandatory "
                                   "information.\n");
                    ods_writen(sockfd, buf, strlen(buf));
                }
			} else {
                (void)snprintf(buf, ODS_SE_MAXLINE, "warning: no policies "
                               "found in policies list.\n");
                ods_writen(sockfd, buf, strlen(buf));
            }
		} else {
            (void)snprintf(buf, ODS_SE_MAXLINE, 
                           "warning: no policies list found in kasp.xml "
                           "file.\n");
            ods_writen(sockfd, buf, strlen(buf));
        }
    } else {
        (void)snprintf(buf, ODS_SE_MAXLINE, "warning: unable to read the "
                       "kasp.xml file.\n");
        ods_writen(sockfd, buf, strlen(buf));
    }
	delete doc;
}

static task_type * 
update_kasp_task_perform(task_type *task)
{
    perform_update_kasp(-1,(engineconfig_type *)task->context);
    
    task_cleanup(task);
    return NULL;
}

task_type *
update_kasp_task(engineconfig_type *config)
{
    task_id what = task_register("update kasp",
                                 "update_kasp_task_perform",
                                 update_kasp_task_perform);
	return task_create(what ,time_now(), "all", (void*)config);
}
