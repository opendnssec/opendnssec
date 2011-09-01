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
#include "daemon/engine.h"
#include "enforcer/enforce_task.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "signconf/signconf_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/allocator.h"
}

#include "enforcer/enforcerzone.h"
#include "enforcer/hsmkeyfactory.h"

static const char *module_str = "enforce_task";


const ::ods::kasp::Policy *
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
    ods_log_error("[%s] unable to enforce zone %s",
                  module_str,ks_zone.name().c_str());

    return NULL;
}

class HsmKeyFactoryCallbacks : public HsmKeyFactoryDelegatePB {
private:
    int _sockfd;
    engine_type *_engine;
    bool _bShouldLaunchKeyGen;
public:
    
    HsmKeyFactoryCallbacks(int sockfd, engine_type *engine)
    : _sockfd(sockfd),_engine(engine), _bShouldLaunchKeyGen(false)
    {
        
    }
    
    ~HsmKeyFactoryCallbacks()
    {
        if (_bShouldLaunchKeyGen) 
            LaunchKeyGen();
    }

    void LaunchKeyGen() const
    {
        /* schedule task */
        task_type *task = hsmkey_gen_task(_engine->config, "pre-generate",
                                          "hsm keys");
        if (!task) {
            ods_log_crit("[%s] failed to create %s task", module_str,
                         "pre-generate");
        } else {
            char buf[ODS_SE_MAXLINE];
            ods_enum_status status = schedule_task_from_thread(_engine->taskq,
                                                               task, 0);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to create %s task", module_str,
                             "pre-generate");
                (void)snprintf(buf, ODS_SE_MAXLINE,
                               "Unable to schedule %s task.\n",
                               "pre-generate");
                ods_writen(_sockfd, buf, strlen(buf));
            } else {
                (void)snprintf(buf, ODS_SE_MAXLINE,
                               "Scheduled %s generator task.\n",
                               "pre-generate");
                ods_writen(_sockfd, buf, strlen(buf));
                engine_wakeup_workers(_engine);
            }
        }
    }
    
    virtual void OnKeyCreated(int bits, const std::string &repository,
                              const std::string &policy, int algorithm,
                              KeyRole role)
    {
        _bShouldLaunchKeyGen = true;
    }
    
    virtual void OnKeyShortage(int bits, const std::string &repository,
                               const std::string &policy, int algorithm,
                               KeyRole role)
    {
        _bShouldLaunchKeyGen = true;
    }
};


time_t perform_enforce(int sockfd, engine_type *engine, int bForceUpdate,
                       task_type* task)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = engine->config->datastore;
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
                          module_str);
        } else {
            ods_log_error("[%s] policies could not be loaded from \"%s\"",
                          module_str,datapath.c_str());
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
                          module_str);
        } else {
            ods_log_error("[%s] keystates could not be loaded from \"%s\"",
                          module_str,datapath.c_str());
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
            ods_log_debug("[%s] HSM key list has been loaded",
                          module_str);
        } else {
            ods_log_error("[%s] HSM key list could not be loaded from \"%s\"",
                          module_str,datapath.c_str());
        }
        close(fd);
    }
    
    if (bFailedToLoad) {
        delete kaspDoc;
        delete keystateDoc;
        delete hsmkeyDoc;
        ods_log_error("[%s] unable to continue",
                      module_str);
        return -1;
    }

    time_t t_now = time_now();
    // when to reschedule next zone for enforcement
    time_t t_when = t_now + 1 * 365 * 24 * 60 * 60; // now + 1 year
    // which zone to reschedule next for enforcement
    std::string z_when;
    
    HsmKeyFactoryCallbacks *hsmKeyFactoryCallbacks = 
        new HsmKeyFactoryCallbacks(sockfd,engine);
    // Hook the key factory into the hsmkeyDoc list of pre-generated 
    // cryptographic keys.
    HsmKeyFactoryPB keyfactory(hsmkeyDoc,hsmKeyFactoryCallbacks);

    // Go through all the zones and call enforcer update for the zone when 
    // its schedule time is earlier or identical to time_now.
    bool bSignerConfNeedsWriting = false;
    for (int z=0; z<keystateDoc->zones_size(); ++z) {
        // Update zone when scheduled time is earlier or identical to time_now.
        time_t t_next = keystateDoc->zones(z).next_change();
        if (t_next == -1 && bForceUpdate == 0)
            continue; // invalid schedule time, skip zone.
        if (t_next <= t_now || bForceUpdate) {
            // TODO: introduce a query where we select all zones that are
            // scheduled with a time t_scheduled <= time_now().
            const ::ods::keystate::EnforcerZone &ks_zone =
                keystateDoc->zones(z);
            const ::ods::kasp::Policy *policy = 
                find_kasp_policy_for_zone(kaspDoc->kasp(),ks_zone);
            EnforcerZonePB enfZone(keystateDoc->mutable_zones(z), policy);
            if (policy) {
                t_next = update(enfZone, time_now(), keyfactory);
                
                if (enfZone.signerConfNeedsWriting())
                    bSignerConfNeedsWriting = true;
                
                if (t_next == -1) {
                    // Enforcer update could not find a date to 
                    // schedule next.
                    (void)snprintf(buf, ODS_SE_MAXLINE, 
                                   "Next update for zone %s NOT scheduled "
                                   "by enforcer !\n",
                                   ks_zone.name().c_str());
                    ods_writen(sockfd, buf, strlen(buf));
                }
            } else {
                // Unable to find a policy for this zone don't schedule
                // it again !
                t_next = -1; 
                
                (void)snprintf(buf, ODS_SE_MAXLINE, 
                               "Next update for zone %s NOT scheduled "
                               "because policy %s is missing !\n",
                               ks_zone.name().c_str(),ks_zone.policy().c_str());
                ods_writen(sockfd, buf, strlen(buf));
            }
            enfZone.setNextChange(t_next);
            if (t_next == -1)
                continue; 
                
            // Invalid schedule time then skip the zone.
            char tbuf[32] = "date/time invalid\n"; // at least 26 bytes
            ctime_r(&t_next,tbuf); // note that ctime_r inserts a \n
            (void)snprintf(buf, ODS_SE_MAXLINE, 
                           "Next update for zone %s scheduled at %s",
                           ks_zone.name().c_str(),
                           tbuf);
            ods_writen(sockfd, buf, strlen(buf));
        }
        
        // Determine whether this zone is going to be scheduled next.
        // If the enforcer wants a reschedule earlier than currently
        // set, then use that.
        if (t_next < t_when) {
            t_when = t_next;
            z_when = keystateDoc->zones(z).name().c_str();
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
    
    delete kaspDoc;
    delete keystateDoc;
    delete hsmkeyDoc;
    
    // Delete the call backs and launch key pre-generation when we ran out 
    // of keys during the enforcement
    delete hsmKeyFactoryCallbacks;
    
    // Launch signer configuration writer task when one of the 
    // zones indicated that it needs to be written.
    if (bSignerConfNeedsWriting) {
        task_type *signconf = signconf_task(engine->config, "signconf",
                                            "signer configurations");
        if (!signconf) {
            ods_log_crit("[%s] failed to create %s task", module_str,
                         "signconf");
        } else {
            char buf[ODS_SE_MAXLINE];
            ods_status status = schedule_task_from_thread(engine->taskq, 
                                                          signconf, 0);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to create %s task", module_str,
                             "signconf");
                (void)snprintf(buf, ODS_SE_MAXLINE,
                               "Unable to schedule %s task.\n",
                               "signconf");
                ods_writen(sockfd, buf, strlen(buf));
            } else {
                (void)snprintf(buf, ODS_SE_MAXLINE,
                               "Scheduled %s task.\n","signconf");
                ods_writen(sockfd, buf, strlen(buf));
                engine_wakeup_workers(engine);
            }
        }
    }
    
    if (!task)
        return -1;
    
    ods_log_assert(task->allocator);
    ods_log_assert(task->who);
    allocator_deallocate(task->allocator,(void*)task->who);
    task->who = allocator_strdup(task->allocator, z_when.c_str());

    
    task->when = std::max(t_when, time_now());
    task->backoff = 0;
    return task->when;
}

static task_type *
enforce_task_perform(task_type *task)
{
    if (perform_enforce(-1, (engine_type *)task->context, 0, task) != -1)
        return task;

    task_cleanup(task);
    return NULL;
}

task_type *
enforce_task(engine_type *engine, const char *what, const char *who)
{
    task_id what_id = task_register(what, 
                                 "enforce_task_perform",
                                 enforce_task_perform);
    return task_create(what_id, time_now(), who, (void*)engine);
}
