extern "C" {
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "policy/policy_resalt_task.h"
}
#include "policy/resalt.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "kasp.pb.h"

#include "xmlext-pb/xmlext-rd.h"

#include <fcntl.h>
#include <time.h>

static const char *module_str = "policy_resalt_task";

#define TIME_INFINITE ((time_t)-1)

time_t 
perform_policy_resalt(int sockfd, engineconfig_type *config)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;
    
	GOOGLE_PROTOBUF_VERIFY_VERSION;

    // Load the policyresalt from the doc file
    ::ods::kasp::KaspDocument *kaspDoc = new ::ods::kasp::KaspDocument;
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

    time_t next_reschedule = TIME_INFINITE;
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
                       "Updated:  "
                       "Next resalt scheduled:"
                       "\n"
                       ,datastore,npolicies
                       );
        ods_writen(sockfd, buf, strlen(buf));

        bool bSomePoliciesUpdated = false;
        for (int i=0; i<npolicies; ++i) {
            ::ods::kasp::Policy *policy = 
                kaspDoc->mutable_kasp()->mutable_policies(i);

            
            bool bCurrentPolicyUpdate = false;
            if (PolicyUpdateSalt(*policy) == 1) {
                bCurrentPolicyUpdate = true;
                bSomePoliciesUpdated = true;
            }

            std::string next_resalt_time;
            if (!policy->denial().has_nsec3()) {
                next_resalt_time = "not applicable (no NSEC3)";
            } else {
                time_t resalt_when = policy->denial().nsec3().salt_last_change()
                                    +policy->denial().nsec3().resalt();
                char tbuf[32]; 
                if (!ods_ctime_r(tbuf,sizeof(tbuf),resalt_when)) {
                    next_resalt_time = "invalid date/time";
                } else {
                    next_resalt_time = tbuf;
                    if (next_reschedule == TIME_INFINITE
                        || resalt_when > time_now() 
                            && resalt_when  < next_reschedule
                        )
                    {
                        // Keep the earliest time (in the future) to reschedule.
                        next_reschedule = resalt_when;
                    }
                }
            }
            
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "%-31s %-9s %-48s\n",
                           policy->name().c_str(),
                           bCurrentPolicyUpdate ? "yes" : "no",
                           next_resalt_time.c_str()
                           );
            ods_writen(sockfd, buf, strlen(buf));
        }
        
        if (bSomePoliciesUpdated) {
            std::string datapath(datastore);
            datapath += ".policy.pb";
            int fd = open(datapath.c_str(),O_WRONLY|O_CREAT, 0644);
            if (kaspDoc->SerializeToFileDescriptor(fd)) {
                ods_log_debug("[%s] policies have been updated", 
                              module_str);
                (void)snprintf(buf, ODS_SE_MAXLINE,
                               "Policies have been updated.\n");
                ods_writen(sockfd, buf, strlen(buf));
            } else {
                (void)snprintf(buf, ODS_SE_MAXLINE, 
                               "Error: policies file could not be written.\n");
                ods_writen(sockfd, buf, strlen(buf));
            }
            close(fd);
        }
    }
    ods_log_debug("[%s] policy resalt complete", module_str);
    delete kaspDoc;
    return next_reschedule;
}

static task_type * 
policy_resalt_task_perform(task_type *task)
{
	task->backoff = 0;
    task->when = perform_policy_resalt(-1,(engineconfig_type *)task->context);
    if (task->when != TIME_INFINITE)
        return task; // return task, it needs to be rescheduled.

    // no need to reschedule, cleanup and return NULL.
    task_cleanup(task);
    return NULL;
}

task_type *
policy_resalt_task(engineconfig_type *config, const char *what, const char *who)
{
    task_id what_id = task_register(what,
                                 "policy_resalt_task_perform", 
                                 policy_resalt_task_perform);
	return task_create(what_id, time_now(), who, (void*)config);
}
