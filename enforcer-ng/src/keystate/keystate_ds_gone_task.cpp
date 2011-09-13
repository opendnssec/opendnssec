extern "C" {
#include "keystate/keystate_ds_gone_task.h"
#include "shared/file.h"
#include "shared/duration.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"

#include <memory>
#include <fcntl.h>

static const char *module_str = "keystate_ds_gone_task";

void 
perform_keystate_ds_gone(int sockfd, engineconfig_type *config,
                         const char *zone, const char *id, uint16_t keytag)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;

	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
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
                close(fd);
            } else {
                ods_log_error("[%s] keys could not be loaded from \"%s\"",
                              module_str,datapath.c_str());
                close(fd);
                return;
            }
        } else {
            ods_log_error("[%s] keys could not be loaded from \"%s\"",
                          module_str,datapath.c_str());
            return;
        }
    }
    
    if (!(zone && (id || keytag))) {
    
        // list all keys that have retracted flag set.
        
        (void)snprintf(buf, ODS_SE_MAXLINE,
                       "Database set to: %s\n"
                       "Retracted Keys:\n"
                       "Zone:                           "
                       "Key role:     "
                       "Key tag:      "
                       "Id:                                      "
                       "\n"
                       ,datastore
                       );
        ods_writen(sockfd, buf, strlen(buf));
        
        for (int z=0; z<keystateDoc->zones_size(); ++z) {
            
            const ::ods::keystate::EnforcerZone &enfzone = keystateDoc->zones(z);
            for (int k=0; k<enfzone.keys_size(); ++k) {
                const ::ods::keystate::KeyData &key = enfzone.keys(k);
                
                // ZSKs are never trust anchors so skip them.
                if (key.role() == ::ods::keystate::ZSK)
                    continue;
                
                // Skip KSKs with a zero length id, they are placeholder keys.
                if (key.locator().size()==0)
                    continue;
                
                if (key.ds_at_parent()!=::ods::keystate::retracted)
                    continue;

                std::string keyrole = keyrole_Name(key.role());
                (void)snprintf(buf, ODS_SE_MAXLINE,
                               "%-31s %-13s %13u %-40s\n",
                               enfzone.name().c_str(),
                               keyrole.c_str(),
                               key.keytag(),
                               key.locator().c_str()
                               );
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
        return;
    }

    // Try to change the state of a specific retracted key back to unsubmitted.
    bool id_match = false;
    bool bKeyStateModified = false;
    for (int z=0; z<keystateDoc->zones_size(); ++z) {

        ::ods::keystate::EnforcerZone *enfzone = keystateDoc->mutable_zones(z);
        for (int k=0; k<enfzone->keys_size(); ++k) {
            const ::ods::keystate::KeyData &key = enfzone->keys(k);

            // ZSKs are never trust anchors so skip them.
            if (key.role() == ::ods::keystate::ZSK)
                continue;
            
            // Skip KSKs with a zero length id, they are placeholder keys.
            if (key.locator().size()==0)
                continue;
            
            // Skip when zone doesn't match
            if (enfzone->name()!=zone)
                continue;
            
            if (id && key.locator()==id || keytag && key.keytag()==keytag ) {
                id_match = true;
                
                if (key.ds_at_parent()!=::ods::keystate::retracted) {
                    
                    std::string dsatparentname = dsatparent_Name(key.ds_at_parent());
                    (void)snprintf(buf, ODS_SE_MAXLINE, 
                                   "Key that matches id \"%s\" in zone "
                                   "\"%s\" is not retracted but %s\n",
                                   key.locator().c_str(), zone,
                                   dsatparentname.c_str());
                    ods_writen(sockfd, buf, strlen(buf));
                    break;
                }

                bKeyStateModified = true;
                
                ::ods::keystate::KeyData *kd =
                    keystateDoc->mutable_zones(z)->mutable_keys(k);
                kd->set_ds_at_parent(::ods::keystate::unsubmitted);
                enfzone->set_next_change(0); // reschedule immediately
            }

        }
    }

    if (!id_match) {
        if (id)
            (void)snprintf(buf, ODS_SE_MAXLINE, 
                           "No KSK key matches id \"%s\" in zone \"%s\"\n",
                           id, zone);
        else
            (void)snprintf(buf, ODS_SE_MAXLINE, 
                           "No KSK key matches keytag \"%u\" in zone \"%s\"\n",
                           keytag, zone);
        ods_writen(sockfd, buf, strlen(buf));
    }
    
    // Persist the keystate zones back to disk as they may have
    // been changed by the enforcer update
    if (bKeyStateModified) {
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
}
