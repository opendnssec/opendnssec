
extern "C" {
#include "shared/duration.h"
#include "shared/file.h"
#include "policy/policy_list_task.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "kasp.pb.h"

#include "xmlext-pb/xmlext.h"

#include <fcntl.h>
#include <memory>

static const char *module_str = "policy_list_task";

void 
perform_policy_list(int sockfd, engineconfig_type *config)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;
    
	GOOGLE_PROTOBUF_VERIFY_VERSION;

    // Load the policylist from the doc file
    std::auto_ptr< ::ods::kasp::KaspDocument >
        kaspDoc(new ::ods::kasp::KaspDocument);
    {
        std::string datapath(datastore);
        datapath += ".policy.pb";
        int fd = open(datapath.c_str(),O_RDONLY);
        if (kaspDoc->ParseFromFileDescriptor(fd)) {
            ods_log_debug("[%s] policies have been loaded",
                          module_str);
        } else {
            ods_log_error("[%s] policies could not be loaded from \"%s\"",
                          module_str,datapath.c_str());
        }
        close(fd);
    }

    int npolicies = kaspDoc->kasp().policies_size();
    if (npolicies == 0) {
        (void)snprintf(buf, ODS_SE_MAXLINE,
                       "Database set to: %s\n"
                       "I have no policies configured\n"
                       ,datastore
                       );
        ods_writen(sockfd, buf, strlen(buf));
    } else {
        (void)snprintf(buf, ODS_SE_MAXLINE,
                       "Database set to: %s\n"
                       "I have %i policies configured\n"
                       "Policies:\n"
                       "Policy:                         "
                       "Description:"
                       "\n"
                       ,datastore,npolicies
                       );
        ods_writen(sockfd, buf, strlen(buf));
        
        for (int i=0; i<npolicies; ++i) {
            const ::ods::kasp::Policy &policy = kaspDoc->kasp().policies(i);
            
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "%-31s %-48s\n",
                           policy.name().c_str(),
                           policy.description().c_str()
                           );
            ods_writen(sockfd, buf, strlen(buf));
        }
    }
    
    ods_log_debug("[%s] policy list completed", module_str);
}

static task_type * 
policy_list_task_perform(task_type *task)
{
    perform_policy_list(-1,(engineconfig_type *)task->context);
    
    task_cleanup(task);
    return NULL;
}

task_type *
policy_list_task(engineconfig_type *config, const char *shortname)
{
    task_id what = task_register(shortname,
                                 "policy_list_task_perform", 
                                 policy_list_task_perform);
	return task_create(what, time_now(), "all",(void*)config);
}
