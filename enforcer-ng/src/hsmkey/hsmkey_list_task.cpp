extern "C" {
#include "hsmkey/hsmkey_list_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "shared/str.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "hsmkey/hsmkey.pb.h"

#include "xmlext-pb/xmlext.h"


#include <fcntl.h>

static const char *module_str = "hsmkey_list_task";

void 
perform_hsmkey_list(int sockfd, engineconfig_type *config)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;
    
	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    // Load the current list of pre-generated keys
    ::ods::hsmkey::HsmKeyDocument *hsmkeyDoc = 
        new ::ods::hsmkey::HsmKeyDocument;
    {
        std::string datapath(datastore);
        datapath += ".hsmkey.pb";
        int fd = open(datapath.c_str(),O_RDONLY);
        if (hsmkeyDoc->ParseFromFileDescriptor(fd)) {
            ods_log_debug("[%s] HSM key info list has been loaded",
                          module_str);
        } else {
            ods_log_error("[%s] HSM key info list could not be loaded "
                          "from \"%s\"",
                          module_str,datapath.c_str());
        }
        close(fd);
    }


    (void)snprintf(buf, ODS_SE_MAXLINE,
                   "HSM keys:\n"
                   "Id:                                      "
                   "Algorithm: "
                   "Bits:   "
                   "HSM:       "
                   "First use:                 "
                   "\n"
                   );
    ods_writen(sockfd, buf, strlen(buf));
    
    // Enumerate the keys found in the doc file on disk.
    for (int k=0; k<hsmkeyDoc->keys_size(); ++k) {
        const ::ods::hsmkey::HsmKey& key = hsmkeyDoc->keys(k);
        std::string algo  = key.algorithm_name();
        uint32_t bits = key.bits();
        std::string loca = key.locator();
        std::string hsm = key.hsm_name();
        char incep[32];
        if (key.inception() != 0) {
            if (!ods_ctime_r(incep,sizeof(incep),key.inception())) {
                strncpy(incep,"(invalid date/time)",sizeof(incep));
                incep[sizeof(incep)-1] = '\0';
            }
        } else {
            strncpy(incep,"(never)",sizeof(incep));
            incep[sizeof(incep)-1] = '\0';
        }
        (void)snprintf(buf, ODS_SE_MAXLINE, "%-40s %-10s %-7u %-10s %-26s \n",
                       loca.c_str(), algo.c_str(), bits, hsm.c_str(), incep);
        ods_writen(sockfd, buf, strlen(buf));
    }
}

static task_type * 
hsmkey_list_task_perform(task_type *task)
{
    perform_hsmkey_list(-1,(engineconfig_type *)task->context);
    
    task_cleanup(task);
    return NULL;
}

task_type *
hsmkey_list_task(engineconfig_type *config, const char *shortname)
{
    task_id what = task_register(shortname,
                                 "hsmkey_list_task_perform",
                                 hsmkey_list_task_perform);
	return task_create(what, time_now(), "all", (void*)config);
}
