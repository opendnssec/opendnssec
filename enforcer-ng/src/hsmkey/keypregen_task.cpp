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
    typedef struct {
        unsigned int bits;
        unsigned int nneeded;
        unsigned int navailable;
    
    } keygencfg_t; 
    keygencfg_t keygencfg[] = {
        {1024,20},
        {1536,15},
        {2048,40}
    };
    const unsigned int nkeygencfg = sizeof(keygencfg)/sizeof(keygencfg_t);
    
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

    
    // Establish the number of keys need to be generated
    int nfreekeys = 0;
    for (int k=0; k<hsmkeyDoc->keys_size(); ++k) {
        const ::ods::hsmkey::HsmKey& key = hsmkeyDoc->keys(k);
        if (!key.has_inception()) {
            // this key is available
            unsigned int keybits = key.bits();
            for (int c=0; c<nkeygencfg; ++c) {
                if (keybits == keygencfg[c].bits) {
                    ++keygencfg[c].navailable;
                    break;
                }
            }
        }
    }
    
    // Generate the keys of different sizes that are needed
    bool bkeysgenerated = false;
    for (int c=0; c<nkeygencfg; ++c) {
        unsigned int nbits = keygencfg[c].bits;
        int ngen = keygencfg[c].nneeded-keygencfg[c].navailable;
        if (ngen <= 0) continue;

        (void)snprintf(buf, ODS_SE_MAXLINE, "generating %d keys of %d bits.\n",
                       ngen,nbits);
        ods_writen(sockfd, buf, strlen(buf));

        // Generate additional keys until certain minimum number is available.
        for ( ;ngen; --ngen) {
            std::string locator;
            if (generate_key(hsmkeyDoc->keys_size(), nbits,locator)) 
            {
                bkeysgenerated = true;
                ::ods::hsmkey::HsmKey* key = hsmkeyDoc->add_keys();
                key->set_locator(locator);
                key->set_bits(nbits);
            } else {
                // perhaps this HSM can't generate keys of this size.
                ods_log_error("[%s] Error during key generation",
                              keypregen_task_str);
                (void)snprintf(buf, ODS_SE_MAXLINE, "unable to generate a key "
                               "of %d bits.\n", nbits);
                ods_writen(sockfd, buf, strlen(buf));
                break;
            }
            ++keygencfg[c].navailable;
        }

        if (ngen==0) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "finished generating %d bit "
                           "keys.\n", nbits);
            ods_writen(sockfd, buf, strlen(buf));
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
    
    (void)snprintf(buf, ODS_SE_MAXLINE, "key pre-generation complete.\n");
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
    task_id what = task_register("keypregen",
                                 "keypregen_task_perform",
                                 keypregen_task_perform);
	return task_create(what, time_now(), "all", (void*)config);
}
