#include "keystate/keystate_export_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"
#include "libhsmdns.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "policy/kasp.pb.h"
#include "xmlext-pb/xmlext-rd.h"

#include <memory>
#include <fcntl.h>

static const char *module_str = "keystate_export_task";

static uint16_t 
dnskey_from_id(std::string &dnskey,
               const char *id,
               ::ods::keystate::keyrole role,
               const char *zone,
               int algorithm,
               int bDS,
               uint32_t ttl)
{
    hsm_key_t *key;
    hsm_sign_params_t *sign_params;
    ldns_rr *dnskey_rr;
    ldns_algorithm algo = (ldns_algorithm)algorithm;
    
    /* Code to output the DNSKEY record  (stolen from hsmutil) */
    hsm_ctx_t *hsm_ctx = hsm_create_context();
    key = hsm_find_key_by_id(hsm_ctx, id);
    
    if (!key) {
        // printf("Key %s in DB but not repository\n", id);
        hsm_destroy_context(hsm_ctx);
        return 0;
    }
    
    /*
     * Sign params only need to be kept around 
     * for the hsm_get_dnskey() call.
     */
    sign_params = hsm_sign_params_new();
    sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zone);
    sign_params->algorithm = algo;
    sign_params->flags = LDNS_KEY_ZONE_KEY;
    if (role == ::ods::keystate::KSK)
        sign_params->flags += LDNS_KEY_SEP_KEY; /*KSK=>SEP*/
    /* Get the DNSKEY record */
    dnskey_rr = hsm_get_dnskey(hsm_ctx, key, sign_params);
    hsm_sign_params_free(sign_params);
    /* Calculate the keytag for this key, we return it. */
    uint16_t keytag = ldns_calc_keytag(dnskey_rr);
    /* Override the TTL in the dnskey rr */
    if (ttl)
        ldns_rr_set_ttl(dnskey_rr, ttl);
    
    char *rrstr;
    if (!bDS) {
#if 0
        ldns_rr_print(stdout, dnskey_rr);
#endif
        rrstr = ldns_rr2str(dnskey_rr);
        dnskey = rrstr;
        LDNS_FREE(rrstr);
    } else {
    
        switch (algo) {
            case LDNS_RSASHA1: // 5
            {
                /* DS record (SHA1) */
                ldns_rr *ds_sha1_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA1);
#if 0
                ldns_rr_print(stdout, ds_sha1_rr);
#endif
                rrstr = ldns_rr2str(ds_sha1_rr);
                dnskey = rrstr;
                LDNS_FREE(rrstr);

                ldns_rr_free(ds_sha1_rr);
                break;
            }
            case LDNS_RSASHA256: // 8 - RFC 5702
            {
        
                /* DS record (SHA256) */
                ldns_rr *ds_sha256_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA256);
#if 0
                ldns_rr_print(stdout, ds_sha256_rr);
#endif
                rrstr = ldns_rr2str(ds_sha256_rr);
                dnskey = rrstr;
                LDNS_FREE(rrstr);

                ldns_rr_free(ds_sha256_rr);
                break;
            }
            default:
                keytag = 0;
        }
    }
    ldns_rr_free(dnskey_rr);
    hsm_key_free(key);
    hsm_destroy_context(hsm_ctx);
    
    return keytag;
}

static const ::ods::kasp::Policy *
find_kasp_policy_for_zone(const ::ods::kasp::KASP &kasp,
                          const ::ods::keystate::EnforcerZone &ks_zone)
{
    // Find the policy associated with the zone.
    for (int p=0; p<kasp.policies_size(); ++p) {
        if (kasp.policies(p).name() == ks_zone.policy()) {
            ods_log_debug("[%s] policy %s found for zone %s",
                          module_str,ks_zone.policy().c_str(),
                          ks_zone.name().c_str());
            return &kasp.policies(p);
        }
    }
    ods_log_error("[%s] policy %s could not be found for zone %s",
                  module_str,ks_zone.policy().c_str(),
                  ks_zone.name().c_str());
    return NULL;
}

void 
perform_keystate_export(int sockfd, engineconfig_type *config, const char *zone,
                        int bds)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;

	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    std::auto_ptr< ::ods::kasp::KaspDocument >
        kaspDoc(new ::ods::kasp::KaspDocument);
    {
        std::string datapath(datastore);
        datapath += ".policy.pb";
        int fd = open(datapath.c_str(),O_RDONLY);
        if (fd != -1) {
            if (kaspDoc->ParseFromFileDescriptor(fd)) {
                ods_log_debug("[%s] policies have been loaded",
                              module_str);
            } else {
                ods_log_error("[%s] policies could not be loaded from \"%s\"",
                              module_str,datapath.c_str());
                (void)snprintf(buf,ODS_SE_MAXLINE, "policies could not be loaded "
                               "from \"%s\"\n", 
                               datapath.c_str());
                ods_writen(sockfd, buf, strlen(buf));
                return;
            }
            close(fd);
        } else {
            ods_log_error("[%s] file \"%s\" could not be opened",
                          module_str,datapath.c_str());
            (void)snprintf(buf,ODS_SE_MAXLINE,
                           "file \"%s\" could not be opened\n", 
                           datapath.c_str());
            ods_writen(sockfd, buf, strlen(buf));
            return;
        }
    }

    std::auto_ptr< ::ods::keystate::KeyStateDocument >
        keystateDoc(new ::ods::keystate::KeyStateDocument);
    {
        std::string datapath(datastore);
        datapath += ".keystate.pb";
        int fd = open(datapath.c_str(),O_RDONLY);
        if (fd!=-1) {
            if (keystateDoc->ParseFromFileDescriptor(fd)) {
                ods_log_debug("[%s] keys have been loaded",
                              module_str);
            } else {
                ods_log_error("[%s] keys could not be loaded from \"%s\"",
                              module_str,datapath.c_str());
                (void)snprintf(buf,ODS_SE_MAXLINE, "keys could not be loaded "
                               "from \"%s\"\n", 
                               datapath.c_str());
                ods_writen(sockfd, buf, strlen(buf));
                return;
            }
            close(fd);
        } else {
            ods_log_error("[%s] file \"%s\" could not be opened",
                          module_str,datapath.c_str());
            (void)snprintf(buf,ODS_SE_MAXLINE,
                           "file \"%s\" could not be opened\n", 
                           datapath.c_str());
            ods_writen(sockfd, buf, strlen(buf));
            return;
        }
    }
    
    bool bSubmitChanged = false;
    bool bRetractChanged = false;
    bool bKeytagChanged = false;
    std::string zname(zone);
    for (int z=0; z<keystateDoc->zones_size(); ++z) {

        const ::ods::keystate::EnforcerZone &enfzone  = keystateDoc->zones(z);
        if (enfzone.name() != zname) 
            continue;
        
        uint32_t dnskey_ttl = 0;
        const ::ods::kasp::Policy *policy = 
            find_kasp_policy_for_zone(kaspDoc->kasp(), enfzone);
        if (policy) {
            dnskey_ttl = policy->keys().ttl();
        }

        for (int k=0; k<enfzone.keys_size(); ++k) {
            const ::ods::keystate::KeyData &key = enfzone.keys(k);
            if (key.role()==::ods::keystate::ZSK)
                continue;
            
            if (key.ds_at_parent()!=::ods::keystate::submit
                && key.ds_at_parent()!=::ods::keystate::submitted
                && key.ds_at_parent()!=::ods::keystate::retract
                && key.ds_at_parent()!=::ods::keystate::retracted
                )
                continue;
            
            std::string dnskey;
            uint16_t keytag = dnskey_from_id(dnskey,key.locator().c_str(),
                                             key.role(),
                                             enfzone.name().c_str(),
                                             key.algorithm(),bds,
                                             dnskey_ttl);
            if (keytag) {
                ods_writen(sockfd, dnskey.c_str(), dnskey.size());
                bSubmitChanged = key.ds_at_parent()==::ods::keystate::submit;
                bRetractChanged = key.ds_at_parent()==::ods::keystate::retract;
                bKeytagChanged = key.keytag()!=keytag;
                if (bSubmitChanged) {
                    ::ods::keystate::KeyData *kd = 
                        keystateDoc->mutable_zones(z)->mutable_keys(k);
                    kd->set_ds_at_parent(::ods::keystate::submitted);
                }
                if (bRetractChanged) {
                    ::ods::keystate::KeyData *kd = 
                        keystateDoc->mutable_zones(z)->mutable_keys(k);
                    kd->set_ds_at_parent(::ods::keystate::retracted);
                }
                if (bKeytagChanged) {
                    ::ods::keystate::KeyData *kd = 
                    keystateDoc->mutable_zones(z)->mutable_keys(k);
                    kd->set_keytag(keytag);
                }
            } else {
                ods_log_error("[%s] unable to find key with id %s",
                              module_str,key.locator().c_str());
                (void)snprintf(buf,ODS_SE_MAXLINE, "key %s not found\n", 
                               key.locator().c_str());
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
    }
    
    if (bSubmitChanged || bRetractChanged || bKeytagChanged) {
        // Persist the keystate zones back to disk as they may have
        // been changed by the enforcer update
        if (keystateDoc->IsInitialized()) {
            std::string datapath(datastore);
            datapath += ".keystate.pb";
            int fd = open(datapath.c_str(),O_WRONLY|O_CREAT, 0644);
            if (fd!=-1) {
                if (keystateDoc->SerializeToFileDescriptor(fd)) {
                    ods_log_debug("[%s] key states have been updated",
                                  module_str);
                } else {
                    ods_log_error("[%s] key states file could not be written",
                                  module_str);
                }
                close(fd);
            } else {
                ods_log_error("[%s] key states file \"%s\"could not be opened "
                              "for writing", module_str,datastore);
            }
        } else {
            ods_log_error("[%s] a message in the key states is missing "
                          "mandatory information", module_str);
        }
    }
}
