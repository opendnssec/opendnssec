extern "C" {
#include "hsmkey/hsmkey_list_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "hsmkey/hsmkey.pb.h"

#include "xmlext-pb/xmlext.h"


#include <fcntl.h>

static const char *module_str = "hsmkey_list_task";


static void list_all_keys_in_all_hsms(int sockfd, engineconfig_type *config)
{
    char buf[ODS_SE_MAXLINE];
    // hsm_open(config->cfg_filename,NULL,NULL);
    hsm_ctx_t * hsm_ctx = hsm_create_context();
    size_t nkeys;
    hsm_key_t **kl = hsm_list_keys(hsm_ctx, &nkeys);
    
    for (int i=0; i<nkeys; ++i) {
        hsm_key_info_t *kinf = hsm_get_key_info(hsm_ctx,kl[i]);

        (void)snprintf(buf, ODS_SE_MAXLINE, 
                       "key [%s] algorithm=%s (%lu), size=%lu\n",
                       kinf->id,
                       kinf->algorithm_name,kinf->algorithm,
                       kinf->keysize);

        ods_writen(sockfd, buf, strlen(buf));
        
        
        hsm_key_info_free(kinf);
    }

    
    hsm_key_list_free(kl,nkeys);
    hsm_destroy_context(hsm_ctx);
    // hsm_close();
}

void 
perform_hsmkey_list(int sockfd, engineconfig_type *config)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;
    
    list_all_keys_in_all_hsms(sockfd,config);    
    
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

    
    // Enumerate the keys found in the doc file on disk.
    for (int k=0; k<hsmkeyDoc->keys_size(); ++k) {
        const ::ods::hsmkey::HsmKey& key = hsmkeyDoc->keys(k);
        std::string loc = key.locator();
        uint32_t keyalgo = key.algorithm();
        uint32_t keybits = key.bits();
        
        (void)snprintf(buf, ODS_SE_MAXLINE,
                       "key [%s] algorithm= (%u), size=%u\n",
                       loc.c_str(),
                       keyalgo,
                       keybits);
        
        ods_writen(sockfd, buf, strlen(buf));

#if 0
            optional bool candidate_for_sharing = 2 [default = false];
            optional uint32 bits = 3 [default = 2048];
            optional string policy = 4 [default = "default"];
            optional uint32 algorithm = 5 [default = 1];
            optional keyrole role = 6 [default = ZSK];
            repeated string used_by_zones = 7;
            optional uint32 inception = 8;
            optional bool revoke = 9 [default = false];
#endif

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
