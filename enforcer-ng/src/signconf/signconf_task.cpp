#include <fcntl.h>

extern "C" {
#include "signconf/signconf_task.h"
#include "shared/file.h"
#include "shared/duration.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "xmlext-pb/xmlext.h"
#include "signconf/signconf.pb.h"
#include "policy/kasp.pb.h"
#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-wr.h"



static const char *signconf_task_str = "signconf_task";

void WriteSignConf(const std::string &path, ::signconf::pb::SignerConfigurationDocument *doc)
{
    write_pb_message_to_xml_file(doc,path.c_str());
}

/*
 * ForEvery zone Z in zonelist do
 *   if flag signerConfNeedsWriting is set then
 *      Assign the data from the zone and associated policy to the signer configuration object
 *      Write signer configuration XML file at the correct location taken from zonedata signerconfiguration field in the zone 
 */
void 
perform_signconf(int sockfd, engineconfig_type *config)
{
    char buf[ODS_SE_MAXLINE];
	const char *policyfile = config->policy_filename;
    const char *datastore = config->datastore;
    int fd;
    
	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    // Read the zonelist and policies in from the same directory as 
    // the database, use serialized protocolbuffer for now, but switch 
    // to using database table ASAP.
    
    bool bFailedToLoad = false;
    
    ::kasp::pb::KaspDocument *kaspDoc = new ::kasp::pb::KaspDocument;
    {
        std::string policypb(datastore);
        policypb += ".policy.pb";
        int fd = open(policypb.c_str(),O_RDONLY);
        if (kaspDoc->ParseFromFileDescriptor(fd)) {
            ods_log_debug("[%s] policies have been loaded", 
                          signconf_task_str);
        } else {
            ods_log_error("[%s] policies could not be loaded from \"%s\"", 
                          signconf_task_str,policypb.c_str());
            bFailedToLoad = true;
        }
        close(fd);
    }
    
    ::keystate::pb::KeyStateDocument *keystateDoc = 
        new ::keystate::pb::KeyStateDocument;
    {
        std::string keystatepb(datastore);
        keystatepb += ".keystate.pb";
        int fd = open(keystatepb.c_str(),O_RDONLY);
        if (keystateDoc->ParseFromFileDescriptor(fd)) {
            ods_log_debug("[%s] keystates have been loaded", 
                          signconf_task_str);
        } else {
            ods_log_error("[%s] keystates could not be loaded from \"%s\"", 
                          signconf_task_str,keystatepb.c_str());
            bFailedToLoad = true;
        }
        close(fd);
    }

    if (bFailedToLoad) {
        delete kaspDoc;
        delete keystateDoc;
        ods_log_error("[%s] unable to continue", 
                      signconf_task_str);
        return ;
    }
        
    // Go through all the zones and run the enforcer for every one of them.
    for (int i=0; i<keystateDoc->zones_size(); ++i) {
    
        const ::keystate::pb::EnforcerZone &ks_zone = keystateDoc->zones(i);
        
        if (!ks_zone.signconfneedswriting())
            continue;

        const ::kasp::pb::KASP &
        kasp = kaspDoc->kasp();
        
        //printf("%s\n",zone.name().c_str());
        
        const ::kasp::pb::Policy *policy = NULL;
        
        for (int p=0; p<kasp.policies_size(); ++p) {
            // lookup the policy associated with this zone 
            // printf("%s\n",kasp.policies(p).name().c_str());
            if (kasp.policies(p).name() == ks_zone.policy()) {
                policy = &kasp.policies(p);
                ods_log_debug("[%s] policy %s found for zone %s", 
                              signconf_task_str,policy->name().c_str(),
                              ks_zone.name().c_str());
                break;
            }
        }
        
        if (policy == NULL) {
            ods_log_error("[%s] policy %s could not be found for zone %s", 
                          signconf_task_str,ks_zone.policy().c_str(),
                          ks_zone.name().c_str());
            ods_log_error("[%s] unable to enforce zone %s", 
                          signconf_task_str,ks_zone.name().c_str());
            continue;
        }

        ::signconf::pb::SignerConfigurationDocument *doc  = new ::signconf::pb::SignerConfigurationDocument;
        ::signconf::pb::Zone *sc_zone = doc->mutable_signerconfiguration()->mutable_zone();
        sc_zone->set_name(ks_zone.name());
        
        // Get the Signatures parameters straight from the policy.
        ::signconf::pb::Signatures *sc_sigs = sc_zone->mutable_signatures();
        const ::kasp::pb::Signatures &kp_sigs = policy->signatures();
        
        sc_sigs->set_resign( kp_sigs.resign() );
        sc_sigs->set_refresh( kp_sigs.refresh() );
        sc_sigs->set_valdefault( kp_sigs.valdefault() );
        sc_sigs->set_valdenial( kp_sigs.valdenial() );
        sc_sigs->set_jitter( kp_sigs.jitter() );
        sc_sigs->set_inceptionoffset( kp_sigs.inceptionoffset() );
        
        // Get the Denial parameters straight from the policy
        ::signconf::pb::Denial *sc_denial = sc_zone->mutable_denial();
        const ::kasp::pb::Denial &kp_denial = policy->denial();
        
        if (kp_denial.has_nsec() && kp_denial.has_nsec3()) {
            ods_log_error("[%s] policy %s contains both NSEC and NSEC3 in Denial for zone %s", 
                          signconf_task_str,ks_zone.policy().c_str(),
                          ks_zone.name().c_str());
            // skip to the next zone.
            continue;
        } else {
            if (!kp_denial.has_nsec() && !kp_denial.has_nsec3()) {
                ods_log_error("[%s] policy %s does not contains NSEC or NSEC3 in Denial for zone %s", 
                              signconf_task_str,ks_zone.policy().c_str(),
                              ks_zone.name().c_str());
                // skip to the next zone.
                continue;
            } else {
                // NSEC
                if(!kp_denial.has_nsec())
                    sc_denial->clear_nsec();
                else
                    sc_denial->mutable_nsec();
                
                // NSEC3
                if (!kp_denial.has_nsec3()) 
                    sc_denial->clear_nsec3();
                else {
                    ::signconf::pb::NSEC3 *sc_nsec3 = sc_denial->mutable_nsec3();
                    const ::kasp::pb::NSEC3 &kp_nsec3 = kp_denial.nsec3();
                    if (kp_nsec3.has_optout())
                        sc_nsec3->set_optout( kp_nsec3.optout() );
                    else
                        sc_nsec3->clear_optout();
                    sc_nsec3->set_algorithm( kp_nsec3.algorithm() );
                    sc_nsec3->set_iterations( kp_nsec3.iterations() );
                    sc_nsec3->set_salt( "TODO:GET THE REAL SALT" );
                }
            }
        }

        // Get the Keys from the zone data and add them to the signer 
        // configuration
        ::signconf::pb::Keys *sc_keys = sc_zone->mutable_keys();
        sc_keys->set_ttl( policy->keys().ttl() );

        for (int k=0; k<ks_zone.keys_size(); ++k) {
            const ::keystate::pb::KeyData &ks_key = ks_zone.keys(k);
            ::signconf::pb::Key* sc_key = sc_keys->add_keys();

            // TODO: is this correct ?
            if (ks_key.role() == ::keystate::pb::ZSK)
                sc_key->set_flags( 256 ); // ZSK
            else
                sc_key->set_flags( 257 ); // KSK,CSK
                
            sc_key->set_algorithm( ks_key.algorithm() );
            sc_key->set_locator( ks_key.locator() );
            sc_key->set_ksk( ks_key.role() ==  ::keystate::pb::KSK || ks_key.role() ==  ::keystate::pb::CSK );
            sc_key->set_zsk( ks_key.role() ==  ::keystate::pb::ZSK || ks_key.role() ==  ::keystate::pb::CSK );
            sc_key->set_publish( ks_key.published() );
            sc_key->set_deactivate( !ks_key.active() );
        }
        
        const ::kasp::pb::Zone &kp_zone = policy->zone();
        sc_zone->set_ttl( kp_zone.ttl() );
        sc_zone->set_min( kp_zone.min() );
        sc_zone->set_serial( (::signconf::pb::serial) kp_zone.serial() );

        if (policy->audit_size() > 0)
            sc_zone->set_audit(true);
        else
            sc_zone->clear_audit();

        WriteSignConf(ks_zone.signconfpath(), doc);
        
        delete doc;
    }
    
    delete kaspDoc;
    delete keystateDoc;
}

static task_type * 
signconf_task_perform(task_type *task)
{
    perform_signconf(-1,(engineconfig_type *)task->context);
    
	task->backoff = 0;
    task->when = time_now() + 60;
    return task;
}

task_type *
signconf_task(engineconfig_type *config)
{
    task_id signconf_task_id = task_register_how("signconf_task_perform",
                                                 signconf_task_perform);
	return task_create(signconf_task_id,time_now(),"signconf",
                       (void*)config,signconf_task_perform);
}
