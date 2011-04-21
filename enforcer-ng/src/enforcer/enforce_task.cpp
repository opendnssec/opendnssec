#include <ctime>
#include <iostream>
#include <cassert>
#include <fcntl.h>
#include <map>

#include "policy/kasp.pb.h"
#include "zone/zonelist.pb.h"
#include "keystate/keystate.pb.h"
#include "hsmkey/hsmkey.pb.h"

#include "enforcer/enforcerdata.h"
#include "enforcer/enforcer.h"

// Interface of this cpp file is used by C code, we need to declare
// extern "C" to prevent linking errors.
extern "C" {
#include "enforcer/enforce_task.h"
#include "shared/duration.h"
#include "shared/file.h"
}

#include "enforcer/enforcerzone.h"
#include "enforcer/hsmkeyfactory.h"

static const char *enforce_task_str = "enforce_task";


bool load_pb_from_file(::google::protobuf::Message *)
{
    
}



time_t perform_enforce(int sockfd, engineconfig_type *config)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;
    int fd;

	GOOGLE_PROTOBUF_VERIFY_VERSION;

    // Read the zonelist and policies in from the same directory as
    // the database, use serialized protocolbuffer for now, but switch
    // to using database table ASAP.

    bool bFailedToLoad = false;

    ::ods::kasp::KaspDocument *kaspDoc = new ::ods::kasp::KaspDocument;
    {
        std::string datapath(datastore);
        datapath += ".policy.pb";
        int fd = open(datapath.c_str(),O_RDONLY);
        if (kaspDoc->ParseFromFileDescriptor(fd)) {
            ods_log_debug("[%s] policies have been loaded",
                          enforce_task_str);
        } else {
            ods_log_error("[%s] policies could not be loaded from \"%s\"",
                          enforce_task_str,datapath.c_str());
            bFailedToLoad = true;
        }
        close(fd);
    }

    ::ods::zonelist::ZoneListDocument *zonelistDoc =
        new ::ods::zonelist::ZoneListDocument;
    {
        std::string datapath(datastore);
        datapath += ".zonelist.pb";
        int fd = open(datapath.c_str(),O_RDONLY);
        if (zonelistDoc->ParseFromFileDescriptor(fd)) {
            ods_log_debug("[%s] zonelist has been loaded",
                          enforce_task_str);
        } else {
            ods_log_error("[%s] zonelist could not be loaded from \"%s\"",
                          enforce_task_str,datapath.c_str());
            bFailedToLoad = true;
        }
        close(fd);
    }

    ::ods::keystate::KeyStateDocument *keystateDoc =
    new ::ods::keystate::KeyStateDocument;
    {
        std::string datapath(datastore);
        datapath += ".keystate.pb";
        int fd = open(datapath.c_str(),O_RDONLY);
        if (keystateDoc->ParseFromFileDescriptor(fd)) {
            ods_log_debug("[%s] keystates have been loaded",
                          enforce_task_str);
        } else {
            ods_log_error("[%s] keystates could not be loaded from \"%s\"",
                          enforce_task_str,datapath.c_str());
        }
        close(fd);
    }

    ::ods::hsmkey::HsmKeyDocument *hsmkeyDoc = 
        new ::ods::hsmkey::HsmKeyDocument;
    {
        std::string datapath(datastore);
        datapath += ".hsmkey.pb";
        int fd = open(datapath.c_str(),O_RDONLY);
        if (hsmkeyDoc->ParseFromFileDescriptor(fd)) {
            ods_log_debug("[%s] HSM key info list has been loaded",
                          enforce_task_str);
        } else {
            ods_log_error("[%s] HSM key info list could not be loaded from \"%s\"",
                          enforce_task_str,datapath.c_str());
        }
        close(fd);
    }
    
    
    if (bFailedToLoad) {
        delete kaspDoc;
        delete zonelistDoc;
        delete keystateDoc;
        delete hsmkeyDoc;
        ods_log_error("[%s] unable to continue",
                      enforce_task_str);
        return -1;
    }

    time_t t_when = time_now() + 1 * 365 * 24 * 60 * 60; // now + 1 year

    // Add new zones found in the zonelist to the keystates
    // We don't want nested lookup loops of O(N^2) we create an map to get O(2N)
    std::map< const std::string , const ::ods::keystate::EnforcerZone *> kszonemap;
    for (int z=0; z<keystateDoc->zones_size(); ++z) {
        const ::ods::keystate::EnforcerZone &ks_zone = keystateDoc->zones(z);
        kszonemap[ ks_zone.name() ] = &ks_zone;
    }
    // Go through the list of zones from the zonelist to determine if we need
    // to insert new zones to the keystates.
    for (int i=0; i<zonelistDoc->zonelist().zones_size(); ++i) {
        const ::ods::zonelist::ZoneData &zl_zone = zonelistDoc->zonelist().zones(i);
        // if we can't find the zone in the kszonemap, it is new and we need
        // to add it.
        if (kszonemap.find( zl_zone.name() ) == kszonemap.end()) {
            ::ods::keystate::EnforcerZone *ks_zone = keystateDoc->add_zones();

            // setup information the enforcer will need.
            ks_zone->set_name( zl_zone.name() );
            ks_zone->set_policy( zl_zone.policy() );
            ks_zone->set_signconf_path( zl_zone.signerconfiguration() );

            // Don't add any keys, we let the enforcer do this based on policy.

            // enforcer needs to trigger signer configuration writing.
            ks_zone->set_signconf_needs_writing( true );
        }
    }

    // Hook the key factory into the hsmkeyDoc list of pre-generated 
    // cryptographic keys.
    HsmKeyFactoryPB keyfactory(hsmkeyDoc);
    
    // Go through all the zones and run the enforcer for every one of them.
    for (int z=0; z<keystateDoc->zones_size(); ++z) {

        const ::ods::keystate::EnforcerZone &ks_zone = keystateDoc->zones(z);

        const ::ods::kasp::KASP &kasp = kaspDoc->kasp();

        //printf("%s\n",zone.name().c_str());

        const ::ods::kasp::Policy *policy = NULL;

        for (int p=0; p<kasp.policies_size(); ++p) {
            // lookup the policy associated with this zone
            // printf("%s\n",kasp.policies(p).name().c_str());
            if (kasp.policies(p).name() == ks_zone.policy()) {
                policy = &kasp.policies(p);
                ods_log_debug("[%s] policy %s found for zone %s",
                              enforce_task_str,policy->name().c_str(),
                              ks_zone.name().c_str());
                break;
            }
        }

        if (policy == NULL) {
            ods_log_error("[%s] policy %s could not be found for zone %s",
                          enforce_task_str,ks_zone.policy().c_str(),
                          ks_zone.name().c_str());
            ods_log_error("[%s] unable to enforce zone %s",
                          enforce_task_str,ks_zone.name().c_str());
            continue;
        }

        EnforcerZonePB enfZone(keystateDoc->mutable_zones(z), policy);

        time_t t_next = update(enfZone, time_now(), keyfactory);

        if (t_next == -1)
            continue;
        
        if (t_next < time_now()) {
            ods_log_error("[%s] enforcer asked to be scheduled in the past for "
                          "zone %s", enforce_task_str, ks_zone.name().c_str());
            continue;
        }

        // If this enforcer wants a reschedule earlier than currently
        // set, then use that.
        if (t_next < t_when) {
            t_when = t_next;
            std::cout << std::endl << "Next update scheduled at " <<
            ctime(&t_when) << std::endl;
        }
    }

    // Persist the keystate zones back to disk as they may have
    // been changed by the enforcer update
    if (keystateDoc->IsInitialized()) {
        std::string datapath(datastore);
        datapath += ".keystate.pb";
        int fd = open(datapath.c_str(),O_WRONLY|O_CREAT, 0644);
        if (keystateDoc->SerializeToFileDescriptor(fd)) {
            ods_log_debug("[%s] key states have been updated",
                          enforce_task_str);

            (void)snprintf(buf, ODS_SE_MAXLINE, "update of key states completed.\n");
            ods_writen(sockfd, buf, strlen(buf));
        } else {
            (void)snprintf(buf, ODS_SE_MAXLINE, "error: key states file could not be written.\n");
            ods_writen(sockfd, buf, strlen(buf));
        }
        close(fd);
    } else {
        (void)snprintf(buf, ODS_SE_MAXLINE, "error: a message in the key states is missing mandatory information.\n");
        ods_writen(sockfd, buf, strlen(buf));
    }

    // Persist the hsmkey doc back to disk as it may have
    // been changed by the enforcer update
    if (hsmkeyDoc->IsInitialized()) {
        std::string datapath(datastore);
        datapath += ".hsmkey.pb";
        int fd = open(datapath.c_str(),O_WRONLY|O_CREAT, 0644);
        if (hsmkeyDoc->SerializeToFileDescriptor(fd)) {
            ods_log_debug("[%s] HSM keys have been updated",
                          enforce_task_str);
            
            (void)snprintf(buf, ODS_SE_MAXLINE, "update of HSM keys completed.\n");
            ods_writen(sockfd, buf, strlen(buf));
        } else {
            (void)snprintf(buf, ODS_SE_MAXLINE, "error: HSM keys file could not be written.\n");
            ods_writen(sockfd, buf, strlen(buf));
        }
        close(fd);
    } else {
        (void)snprintf(buf, ODS_SE_MAXLINE, "error: a message in the HSM keys is missing mandatory information.\n");
        ods_writen(sockfd, buf, strlen(buf));
    }
    
    delete kaspDoc;
    delete zonelistDoc;
    delete keystateDoc;
    delete hsmkeyDoc;

    return t_when;
}

static task_type *
enforce_task_perform(task_type *task)
{
    time_t t_when = perform_enforce(-1, (engineconfig_type *)task->context);

    if (t_when == -1) {
        task_cleanup(task);
        return NULL;
    }

	task->backoff = 60;
    task->when = t_when + task->backoff;
    return task;
}

task_type *
enforce_task(engineconfig_type *config)
{
    task_id what = task_register("enforce", 
                                 "enforce_task_perform",
                                 enforce_task_perform);
	return task_create(what, time_now(), "all", (void*)config);
}
