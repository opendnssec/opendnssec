#include "keystate/keystate_ds_submit_task.h"
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

static const char *module_str = "keystate_ds_submit_task";

static uint16_t submit_dnskey_by_id(int sockfd,
                                    const char *ds_submit_command,
                                    const char *id,
                                    ::ods::keystate::keyrole role,
                                    const char *zone,
                                    int algorithm,
                                    uint32_t ttl)
{
    char buf[ODS_SE_MAXLINE];

    /* Code to output the DNSKEY record  (stolen from hsmutil) */
    hsm_ctx_t *hsm_ctx = hsm_create_context();
    if (!hsm_ctx) {
        ods_log_error("[%s] Could not connect to HSM", module_str);
        (void)snprintf(buf,ODS_SE_MAXLINE, "Could not connect to HSM\n");
        ods_writen(sockfd, buf, strlen(buf));
        return false;
    }
    hsm_key_t *key = hsm_find_key_by_id(hsm_ctx, id);
    
    if (!key) {
        ods_log_error("[%s] key %s not found in any HSM",
                      module_str,id);
        (void)snprintf(buf,ODS_SE_MAXLINE, "key %s not found in any HSM\n", id);
        ods_writen(sockfd, buf, strlen(buf));
        hsm_destroy_context(hsm_ctx);
        return false;
    }
    
    char *dnskey_rr_str;

    hsm_sign_params_t *sign_params = hsm_sign_params_new();
    sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zone);
    sign_params->algorithm = (ldns_algorithm)algorithm;
    sign_params->flags = LDNS_KEY_ZONE_KEY;
    sign_params->flags += LDNS_KEY_SEP_KEY; /*KSK=>SEP*/
    
    ldns_rr *dnskey_rr = hsm_get_dnskey(hsm_ctx, key, sign_params);
    /* Calculate the keytag for this key, we return it. */
    uint16_t keytag = ldns_calc_keytag(dnskey_rr);
    /* Override the TTL in the dnskey rr */
    if (ttl)
        ldns_rr_set_ttl(dnskey_rr, ttl);
    
#if 0
    ldns_rr_print(stdout, dnskey_rr);
#endif        
    dnskey_rr_str = ldns_rr2str(dnskey_rr);
    
    hsm_sign_params_free(sign_params);
    ldns_rr_free(dnskey_rr);
    hsm_key_free(key);

    /* Replace tab with white-space */
    for (int i = 0; dnskey_rr_str[i]; ++i) {
        if (dnskey_rr_str[i] == '\t') {
            dnskey_rr_str[i] = ' ';
        }
    }
    
    /* We need to strip off trailing comments before we send
     to any clients that might be listening */
    for (int i = 0; dnskey_rr_str[i]; ++i) {
        if (dnskey_rr_str[i] == ';') {
            dnskey_rr_str[i] = '\n';
            dnskey_rr_str[i+1] = '\0';
            break;
        }
    }

    // submit the dnskey rr string to a configured
    // delegation signer submit program.
    if (ds_submit_command && ds_submit_command[0] != '\0') {
        /* send records to the configured command */
        FILE *fp = popen(ds_submit_command, "w");
        if (fp == NULL) {
            keytag = 0;
            ods_log_error("[%s] Failed to run command: %s: %s",
                          module_str,ds_submit_command,strerror(errno));
            (void)snprintf(buf,ODS_SE_MAXLINE,"failed to run command: %s: %s\n",
                           ds_submit_command,strerror(errno));
            ods_writen(sockfd, buf, strlen(buf));
            
        } else {
            int bytes_written = fprintf(fp, "%s", dnskey_rr_str);
            if (bytes_written < 0) {
                keytag = 0;
                ods_log_error("[%s] Failed to write to %s: %s",
                              module_str,ds_submit_command,strerror(errno));
                (void)snprintf(buf,ODS_SE_MAXLINE,"failed to write to %s: %s\n",
                               ds_submit_command,strerror(errno));
                               ods_writen(sockfd, buf, strlen(buf));
                
            } else {
            
                if (pclose(fp) == -1) {
                    keytag = 0;
                    ods_log_error("[%s] Failed to close %s: %s",
                                  module_str,ds_submit_command,strerror(errno));
                    (void)snprintf(buf,ODS_SE_MAXLINE,"failed to close %s: %s\n",
                                   ds_submit_command,strerror(errno));
                    ods_writen(sockfd, buf, strlen(buf));
                    
                } else {
                    (void)snprintf(buf,ODS_SE_MAXLINE, 
                                   "key %s submitted to %s\n", 
                                   id, ds_submit_command);
                    ods_writen(sockfd, buf, strlen(buf));
                }
            }
        }
    } else {
        keytag = 0;
        ods_log_error("[%s] No Delegation Signer Submit Command configured "
                      "in conf.xml.",module_str);
        (void)snprintf(buf,ODS_SE_MAXLINE,
                       "no ds submit command configured in conf.xml.\n");
        ods_writen(sockfd, buf, strlen(buf));
    }
        
    LDNS_FREE(dnskey_rr_str);
    hsm_destroy_context(hsm_ctx);
    // Once the new DS records are seen in DNS please issue the ds-seen 
    // command for zone %s with the following cka_ids %s
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
perform_keystate_ds_submit(int sockfd, engineconfig_type *config,
                           const char *zone, const char *id, int bauto)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;
    const char *ds_submit_command = config->delegation_signer_submit_command;

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
        if (fd != -1) {
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
            }
            close(fd);
        } else {
            ods_log_error("[%s] file \"%s\" could not be opened",
                          module_str,datapath.c_str());
            (void)snprintf(buf,ODS_SE_MAXLINE,
                           "file \"%s\" could not be opened\n", 
                           datapath.c_str());
            ods_writen(sockfd, buf, strlen(buf));
        }
    }

    // Evalutate parameters and submit keys to the parent when instructed
    // to do so.
    if (id || zone || bauto) {
        bool bFlagsChanged = false;
        for (int z=0; z<keystateDoc->zones_size(); ++z) {
            const ::ods::keystate::EnforcerZone &enfzone  = keystateDoc->zones(z);
            for (int k=0; k<enfzone.keys_size(); ++k) {
                const ::ods::keystate::KeyData &key = enfzone.keys(k);

                // Don't ever submit ZSKs to the parent.
                if (key.role()==::ods::keystate::ZSK)
                    continue;

                // Onlyt submit KSKs that have the submit flag set.
                if (key.ds_at_parent()!=::ods::keystate::submit)
                    continue;
                
                // Find the policy for the zone and get the ttl for the dnskey
                uint32_t dnskey_ttl = 0;
                const ::ods::kasp::Policy *policy = 
                find_kasp_policy_for_zone(kaspDoc->kasp(), enfzone);
                if (policy) {
                    dnskey_ttl = policy->keys().ttl();
                }

                if (id) {
                    // --id <id>
                    //     Force submit key to the parent for specific key id.
                    if (key.locator()==id) {
                        // submit key with this id to the parent
                        uint16_t keytag = 
                            submit_dnskey_by_id(sockfd,ds_submit_command,
                                                key.locator().c_str(),
                                                key.role(),
                                                enfzone.name().c_str(),
                                                key.algorithm(),
                                                dnskey_ttl);
                        if (keytag)
                        {
                            bFlagsChanged = true;
                            ::ods::keystate::KeyData *kd = 
                            keystateDoc->mutable_zones(z)->mutable_keys(k);
                            kd->set_ds_at_parent(::ods::keystate::submitted);
                            kd->set_keytag(keytag);
                        }
                    }
                } else {
                    if (zone) {
                        // --zone <zone>
                        //     Force submit key to the parent for specific zone.
                        if (enfzone.name()==zone) {
                            // submit key for this zone to the parent
                            uint16_t keytag = 
                                submit_dnskey_by_id(sockfd,ds_submit_command,
                                                    key.locator().c_str(),
                                                    key.role(),
                                                    enfzone.name().c_str(),
                                                    key.algorithm(),
                                                    dnskey_ttl);
                            if (keytag)
                            {
                                bFlagsChanged = true;
                                ::ods::keystate::KeyData *kd = 
                                keystateDoc->mutable_zones(z)->mutable_keys(k);
                                kd->set_ds_at_parent(::ods::keystate::submitted);
                                kd->set_keytag(keytag);
                            }
                        }
                    } else {
                        // --auto
                        //     Submit all keys to the parent that have
                        //     the submit flag set.
                        uint16_t keytag = 
                            submit_dnskey_by_id(sockfd,ds_submit_command,
                                                key.locator().c_str(),
                                                key.role(),
                                                enfzone.name().c_str(),
                                                key.algorithm(),
                                                dnskey_ttl);
                        if (keytag)
                        {
                            bFlagsChanged = true;
                            ::ods::keystate::KeyData *kd = 
                            keystateDoc->mutable_zones(z)->mutable_keys(k);
                            kd->set_ds_at_parent(::ods::keystate::submitted);
                            kd->set_keytag(keytag);
                        }
                    }
                }
            }
        }
        
        if (bFlagsChanged) {
            // Persist the keystate zones back to disk as they may have
            // been changed by the enforcer update
            if (keystateDoc->IsInitialized()) {
                std::string datapath(datastore);
                datapath += ".keystate.pb";
                int fd = open(datapath.c_str(),O_WRONLY|O_CREAT, 0644);
                if (keystateDoc->SerializeToFileDescriptor(fd)) {
                    ods_log_debug("[%s] key states have been updated",
                                  module_str);
                    
                    (void)snprintf(buf, ODS_SE_MAXLINE,
                                   "update of key states completed.\n");
                    ods_writen(sockfd, buf, strlen(buf));
                } else {
                    (void)snprintf(buf, ODS_SE_MAXLINE,
                                   "error: key states file could not be written.\n");
                    ods_writen(sockfd, buf, strlen(buf));
                }
                close(fd);
            } else {
                (void)snprintf(buf, ODS_SE_MAXLINE,
                               "error: a message in the key states is missing "
                               "mandatory information.\n");
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
        
        return;
    }

    // List the keys with submit flags.
    (void)snprintf(buf, ODS_SE_MAXLINE,
                   "Database set to: %s\n"
                   "Submit Keys:\n"
                   "Zone:                           "
                   "Key role:     "
                   "Id:                                      "
                   "\n"
                   ,datastore
                   );
    ods_writen(sockfd, buf, strlen(buf));
    for (int z=0; z<keystateDoc->zones_size(); ++z) {
        const ::ods::keystate::EnforcerZone &enfzone  = keystateDoc->zones(z);
        for (int k=0; k<enfzone.keys_size(); ++k) {
            const ::ods::keystate::KeyData &key = enfzone.keys(k);
            // Don't suggest ZSKs can be submitted, leave them out of the list.
            if (key.role() == ::ods::keystate::ZSK)
                continue;

            // Only show keys that have the submit flag set.
            if (key.ds_at_parent()!=::ods::keystate::submit)
                continue;
            
            std::string keyrole = keyrole_Name(key.role());
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "%-31s %-13s %-40s\n",
                           enfzone.name().c_str(),
                           keyrole.c_str(),
                           key.locator().c_str()
                           );
            ods_writen(sockfd, buf, strlen(buf));
        }
    }
}

static task_type * 
keystate_ds_submit_task_perform(task_type *task)
{
    perform_keystate_ds_submit(-1,(engineconfig_type *)task->context,NULL,NULL,
                               1);
    task_cleanup(task);
    return NULL;
}

task_type *
keystate_ds_submit_task(engineconfig_type *config, const char *what,
                        const char *who)
{
    task_id what_id = task_register(what, "keystate_ds_submit_task_perform",
                                    keystate_ds_submit_task_perform);
	return task_create(what_id, time_now(), who, (void*)config);
}
