extern "C" {
#include "hsmkey/hsmkey_gen_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "hsmkey/hsmkey.pb.h"
#include "policy/kasp.pb.h"
#include "xmlext-pb/xmlext.h"


#include <fcntl.h>
#include <string.h>
#include <memory>

static const char *module_str = "keypregen_task";

bool generate_keypair(int sockfd,
                      const char *repository,
                      unsigned int keysize,
                      std::string &locator)
{
    char buf[ODS_SE_MAXLINE];
    hsm_key_t *key = NULL;
    hsm_ctx_t *ctx = hsm_create_context();
    
    /* Check for repository before starting using it */
    if (hsm_token_attached(ctx, repository) == 0) {
        hsm_print_error(ctx);
        hsm_destroy_context(ctx);
        return false;
    }
    
    printf("Generating %d bit RSA key in repository: %s\n",
           keysize, repository);
    ods_log_debug("[%s] Generating %d bit RSA key in repository: %s",
                  module_str,keysize,repository);
    (void)snprintf(buf, ODS_SE_MAXLINE,
                   "generating %d bit RSA key in repository: %s\n",
                   keysize,repository);
    ods_writen(sockfd, buf, strlen(buf));
    
    key = hsm_generate_rsa_key(NULL, repository, keysize);
    if (key) {
        hsm_key_info_t *key_info;
        key_info = hsm_get_key_info(NULL, key);
        locator.assign(key_info ? key_info->id : "NULL");
        ods_log_debug("[%s] Key generation successful: %s",
                      module_str,locator.c_str());
        (void)snprintf(buf, ODS_SE_MAXLINE,
                       "key generation successful: %s\n",
                       locator.c_str());
        ods_writen(sockfd, buf, strlen(buf));
        
        hsm_key_info_free(key_info);
#if 0
        hsm_print_key(key);
#endif
        hsm_key_free(key);
    } else {
        ods_log_error("[%s] Key generation failed.", module_str);
        (void)snprintf(buf, ODS_SE_MAXLINE, "key generation failed.\n");
        ods_writen(sockfd, buf, strlen(buf));
        hsm_destroy_context(ctx);
        return false;
    }
    hsm_destroy_context(ctx);
    return true;
}

bool generate_keypairs(int sockfd, ::ods::hsmkey::HsmKeyDocument *hsmkeyDoc,
                       int ngen, int nbits, const char *repository,
                       const char *policy_name,
                       ::google::protobuf::uint32 algorithm,
                       ::ods::hsmkey::keyrole role)
{
    bool bkeysgenerated = false;
    
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, 
                   "generating %d keys of %d bits.\n",
                   ngen,nbits);
    ods_writen(sockfd, buf, strlen(buf));
    
    // Generate additional keys until certain minimum number is 
    // available.
    for ( ;ngen; --ngen) {
        std::string locator;
        if (generate_keypair(sockfd,repository,nbits,locator))
        {
            bkeysgenerated = true;
            ::ods::hsmkey::HsmKey* key = hsmkeyDoc->add_keys();
            key->set_locator(locator);
            key->set_bits(nbits);
            key->set_repository(repository);
            key->set_policy(policy_name);
            key->set_algorithm(algorithm);
            key->set_role(role);
            key->set_key_type("RSA");
        } else {
            // perhaps this HSM can't generate keys of this size.
            ods_log_error("[%s] Error during key generation",
                          module_str);
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "unable to generate a key of %d bits.\n",
                           nbits);
            ods_writen(sockfd, buf, strlen(buf));
            break;
        }
    }
    
    if (ngen==0) {
        (void)snprintf(buf, ODS_SE_MAXLINE,
                       "finished generating %d bit keys.\n", nbits);
        ods_writen(sockfd, buf, strlen(buf));
    }

    return bkeysgenerated;
}

void 
perform_hsmkey_gen(int sockfd, engineconfig_type *config)
{
    const int KSK_PREGEN = 2;
    const int ZSK_PREGEN = 4;
    const int CSK_PREGEN = 4;
        
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;
    
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    

    // Use auto_ptr so we don't forget to delete the KaspDocument
    std::auto_ptr< ::ods::kasp::KaspDocument >
        kaspDoc( new ::ods::kasp::KaspDocument );
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

    // Load the current list of pre-generated keys
    std::auto_ptr< ::ods::hsmkey::HsmKeyDocument >
        hsmkeyDoc( new ::ods::hsmkey::HsmKeyDocument );
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

    bool bkeysgenerated = false;
    
    // We implement policy drive key pre-generation.
    int npolicies = kaspDoc->kasp().policies_size();
    for (int i=0; i<npolicies; ++i) {
        const ::ods::kasp::Policy &policy = kaspDoc->kasp().policies(i);
        
        // handle KSK keys
        for (int iksk=0; iksk<policy.keys().ksk_size(); ++iksk) {
            const ::ods::kasp::Ksk& ksk = policy.keys().ksk(iksk);
            int nfreekeys = 0;
            for (int k=0; k<hsmkeyDoc->keys_size(); ++k) {
                const ::ods::hsmkey::HsmKey& key = hsmkeyDoc->keys(k);
                if (!key.has_inception()) {
                    // this key is available
                    if (key.bits() == ksk.bits()
                        && key.role() == ::ods::hsmkey::KSK
                        && key.policy() == policy.name()
                        && key.repository() == ksk.repository()
                        )
                    {
                        // This key has all the right properties
                        ++nfreekeys;
                    }
                }
            }
            int ngen = KSK_PREGEN-nfreekeys;
            if (ngen>0) {
                int nbits = ksk.bits();
                
                if (generate_keypairs(sockfd, hsmkeyDoc.get(),
                                      ngen, nbits,
                                      ksk.repository().c_str(),
                                      policy.name().c_str(),
                                      ksk.algorithm(),
                                      ::ods::hsmkey::KSK))
                {
                    bkeysgenerated = true;
                }
            }
        }
        
        // handle ZSK keys
        for (int izsk=0; izsk<policy.keys().zsk_size(); ++izsk) {
            const ::ods::kasp::Zsk& zsk = policy.keys().zsk(izsk);
            int nfreekeys = 0;
            for (int k=0; k<hsmkeyDoc->keys_size(); ++k) {
                const ::ods::hsmkey::HsmKey& key = hsmkeyDoc->keys(k);
                if (!key.has_inception()) {
                    // this key is available
                    if (key.bits() == zsk.bits()
                        && key.role() == ::ods::hsmkey::ZSK
                        && key.policy() == policy.name()
                        && key.repository() == zsk.repository()
                        )
                    {
                        // This key has all the right properties
                        ++nfreekeys;
                    }
                }
            }
            int ngen = ZSK_PREGEN-nfreekeys;
            if (ngen>0) {
                int nbits = zsk.bits();
                
                if (generate_keypairs(sockfd, hsmkeyDoc.get(),
                                      ngen, nbits,
                                      zsk.repository().c_str(),
                                      policy.name().c_str(),
                                      zsk.algorithm(),
                                      ::ods::hsmkey::ZSK))
                {
                    bkeysgenerated = true;
                }
            }
        }

        // handle CSK keys
        for (int icsk=0; icsk<policy.keys().csk_size(); ++icsk) {
            const ::ods::kasp::Csk& csk = policy.keys().csk(icsk);
            int nfreekeys = 0;
            for (int k=0; k<hsmkeyDoc->keys_size(); ++k) {
                const ::ods::hsmkey::HsmKey& key = hsmkeyDoc->keys(k);
                if (!key.has_inception()) {
                    // this key is available
                    if (key.bits() == csk.bits()
                        && key.role() == ::ods::hsmkey::CSK
                        && key.policy() == policy.name()
                        && key.repository() == csk.repository()
                        )
                    {
                        // This key has all the right properties
                        ++nfreekeys;
                    }
                }
            }
            int ngen = CSK_PREGEN-nfreekeys;
            if (ngen>0) {
                int nbits = csk.bits();
                
                if (generate_keypairs(sockfd, hsmkeyDoc.get(),
                                      ngen, nbits,
                                      csk.repository().c_str(),
                                      policy.name().c_str(),
                                      csk.algorithm(),
                                      ::ods::hsmkey::CSK))
                {
                    bkeysgenerated = true;
                }
            }
        }
    }
   
    // Write the list of pre-generated keys back to a pb file.
    if (bkeysgenerated) {
        std::string datapath(datastore);
        datapath += ".hsmkey.pb";
        int fd = open(datapath.c_str(),O_CREAT|O_WRONLY,0644);
        if (hsmkeyDoc->SerializeToFileDescriptor(fd)) {
            ods_log_debug("[%s] HSM key info list has been written",
                          module_str);
        } else {
            ods_log_error("[%s] HSM key info list could not be written to \"%s\"",
                          module_str,datapath.c_str());
        }
        close(fd);
    }
}

static task_type * 
hsmkey_gen_task_perform(task_type *task)
{
    perform_hsmkey_gen(-1,(engineconfig_type *)task->context);
    
    task_cleanup(task);
    return NULL;
}

task_type *
hsmkey_gen_task(engineconfig_type *config,const char *shortname)
{
    task_id what = task_register(shortname,
                                 "hsmkey_gen_task_perform",
                                 hsmkey_gen_task_perform);
	return task_create(what, time_now(), "all", (void*)config);
}
