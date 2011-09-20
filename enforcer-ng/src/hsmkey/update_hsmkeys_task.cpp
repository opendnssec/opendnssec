#include "hsmkey/update_hsmkeys_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "hsmkey/hsmkey.pb.h"

#include "xmlext-pb/xmlext-rd.h"

#include <map>
#include <fcntl.h>

static const char *module_str = "update_hsmkeys_task";


static void import_all_keys_from_all_hsms(int sockfd, 
                                          ::ods::hsmkey::HsmKeyDocument *doc)
{
    char buf[ODS_SE_MAXLINE];
    hsm_ctx_t * hsm_ctx = hsm_create_context();
    size_t nkeys;
    hsm_key_t **kl = hsm_list_keys(hsm_ctx, &nkeys);

    // Add new hsm keys found in the HSMs to the key list.
    // We don't want nested lookup loops of O(N^2) we create a map to get O(2N)
    std::map<const std::string,::ods::hsmkey::HsmKey*> keymap;
    for (int k=0; k<doc->keys_size(); ++k) {
        ::ods::hsmkey::HsmKey *key = doc->mutable_keys(k);
        keymap[ key->locator() ] = key;
    }

    (void)snprintf(buf, ODS_SE_MAXLINE,
                   "HSM keys:\n"
                   "        "
                   "Algorithm: "
                   "Bits:   "
                   "Id:                                      "
                   "\n"
                   );
    ods_writen(sockfd, buf, strlen(buf));
    for (int i=0; i<nkeys; ++i) {
        hsm_key_t *k = kl[i];
        hsm_key_info_t *kinf = hsm_get_key_info(hsm_ctx,k);

        
        // skip HSM keys that already exist.
        ::ods::hsmkey::HsmKey *key = NULL;
        if (keymap.find( kinf->id ) != keymap.end()) {
            
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "%-7s %-10s %-7ld %-40s\n",
                           "update",
                           kinf->algorithm_name,
                           kinf->keysize,
                           kinf->id
                           );
            ods_writen(sockfd, buf, strlen(buf));
            key = keymap[ kinf->id ];
        } else {
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "%-7s %-10s %-7ld %-40s\n",
                           "import",
                           kinf->algorithm_name,
                           kinf->keysize,
                           kinf->id
                           );
            ods_writen(sockfd, buf, strlen(buf));
            key = doc->add_keys();
            key->set_locator(kinf->id);
            key->set_bits(kinf->keysize);
        }
        
        key->set_key_type( kinf->algorithm_name );
        key->set_repository( k->module->name );
                
        hsm_key_info_free(kinf);
    }
    hsm_key_list_free(kl,nkeys);
    hsm_destroy_context(hsm_ctx);
}

void 
perform_update_hsmkeys(int sockfd, engineconfig_type *config)
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
            ods_log_debug("[%s] HSM key list has been loaded",
                          module_str);
        } else {
            ods_log_error("[%s] HSM key list could not be loaded from \"%s\"",
                          module_str,datapath.c_str());
        }
        close(fd);
    }

    // Go through all the keys in HSMs and import them if they are 
    // not already present
    (void)snprintf(buf, ODS_SE_MAXLINE, "Database set to: %s\n", datastore);
    ods_writen(sockfd, buf, strlen(buf));
    import_all_keys_from_all_hsms(sockfd,hsmkeyDoc);
    
    // Persist the hsmkey doc back to disk as it may have
    // been changed by the enforcer update
    if (hsmkeyDoc->IsInitialized()) {
        std::string datapath(datastore);
        datapath += ".hsmkey.pb";
        int fd = open(datapath.c_str(),O_WRONLY|O_CREAT, 0644);
        if (hsmkeyDoc->SerializeToFileDescriptor(fd)) {
            ods_log_debug("[%s] HSM keys have been updated",
                          module_str);
            
            (void)snprintf(buf, ODS_SE_MAXLINE, 
                           "update of HSM keys completed.\n");
            ods_writen(sockfd, buf, strlen(buf));
        } else {
            (void)snprintf(buf, ODS_SE_MAXLINE, 
                           "error: HSM keys file could not be written.\n");
            ods_writen(sockfd, buf, strlen(buf));
        }
        close(fd);
    } else {
        (void)snprintf(buf, ODS_SE_MAXLINE, 
                       "error: a message in the HSM keys is missing "
                       "mandatory information.\n");
        ods_writen(sockfd, buf, strlen(buf));
    }
    delete hsmkeyDoc;
}

static task_type * 
update_hsmkeys_task_perform(task_type *task)
{
    perform_update_hsmkeys(-1,(engineconfig_type *)task->context);
    
    task_cleanup(task);
    return NULL;
}

task_type *
update_hsmkeys_task(engineconfig_type *config, const char *shortname)
{
    task_id what = task_register(shortname,
                                 "update_hsmkeys_task_perform",
                                 update_hsmkeys_task_perform);
	return task_create(what, time_now(), "all", (void*)config);
}
