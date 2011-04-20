extern "C" {
#include "hsmkey/keypregen_task.h"
#include "shared/file.h"
#include "shared/duration.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "hsmkey/hsmkey.pb.h"

#include "xmlext-pb/xmlext.h"


#include <fcntl.h>

static const char *keypregen_task_str = "keypregen_task";


bool generate_key(int num, unsigned int bits, std::string &locator)
{
    char buf[ODS_SE_MAXLINE];
    snprintf(buf,ODS_SE_MAXLINE,"%.4xe1241707c55f7c4bc35743151e71",num);
    locator.assign(buf);
    return true;
}


void 
perform_keypregen(int sockfd, engineconfig_type *config)
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
                          keypregen_task_str);
        } else {
            ods_log_error("[%s] HSM key info list could not be loaded "
                          "from \"%s\"",
                          keypregen_task_str,datapath.c_str());
        }
        close(fd);
    }
    
    // Check how many of them have been used
    int nfreekeys = 0;
    for (int k=0; k<hsmkeyDoc->keys_size(); ++k) {
        const ::ods::hsmkey::HsmKey& key = hsmkeyDoc->keys(k);
        if (!key.has_inception())
            ++nfreekeys;
    }

    // Generate keys until certain minimum number is available.
    bool bkeysgenerated = false;
    for ( ;nfreekeys<42; ++nfreekeys) {
        
        ::ods::hsmkey::HsmKey* key = hsmkeyDoc->add_keys();
        if (!key) {
            ods_log_error("[%s] Unable to add keys to the key info list",
                          keypregen_task_str);
            break;
        }
        bkeysgenerated = true;

        std::string locator;
        unsigned int bits = nfreekeys&1 ? 1536 : 2048;
        if (generate_key(hsmkeyDoc->keys_size(), bits, locator)) {
            key->set_locator(locator);
            key->set_bits(bits);
        } else {
            ods_log_error("[%s] Error during key generation",
                          keypregen_task_str);
            break;
        }
    }
    
    // Write the list of pre-generated keys back to a pb file.
    if (bkeysgenerated) {
        std::string datapath(datastore);
        datapath += ".hsmkey.pb";
        int fd = open(datapath.c_str(),O_CREAT|O_WRONLY,0644);
        if (hsmkeyDoc->SerializeToFileDescriptor(fd)) {
            ods_log_debug("[%s] HSM key info list has been written",
                          keypregen_task_str);
        } else {
            ods_log_error("[%s] HSM key info list could not be written to \"%s\"",
                          keypregen_task_str,datapath.c_str());
        }
        close(fd);
    }
    
    (void)snprintf(buf, ODS_SE_MAXLINE, "pre-generation of a key collection "
                                        "complete.\n");
    ods_writen(sockfd, buf, strlen(buf));
}

static task_type * 
keypregen_task_perform(task_type *task)
{
    perform_keypregen(-1,(engineconfig_type *)task->context);
    
    task_cleanup(task);
    return NULL;
}

task_type *
keypregen_task(engineconfig_type *config)
{
    task_id keypregen_task_id = task_register_how("keypregen_task_perform",
                                                 keypregen_task_perform);
	return task_create(keypregen_task_id,time_now(),"keypregen",
                       (void*)config,keypregen_task_perform);
}
