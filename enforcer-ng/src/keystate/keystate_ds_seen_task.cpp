extern "C" {
#include "keystate/keystate_ds_seen_task.h"
#include "shared/file.h"
#include "shared/duration.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"


#include <fcntl.h>

static const char *module_str = "keystate_ds_seen_task";

void 
perform_keystate_ds_seen(int sockfd, engineconfig_type *config,
                         const char *zone, const char *id)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;

	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    ::ods::keystate::KeyStateDocument *keystateDoc =
    new ::ods::keystate::KeyStateDocument;
    {
        std::string datapath(datastore);
        datapath += ".keystate.pb";
        int fd = open(datapath.c_str(),O_RDONLY);
        if (keystateDoc->ParseFromFileDescriptor(fd)) {
            ods_log_debug("[%s] keys have been loaded",
                          module_str);
        } else {
            ods_log_error("[%s] keys could not be loaded from \"%s\"",
                          module_str,datapath.c_str());
        }
        close(fd);
    }
    
    (void)snprintf(buf, ODS_SE_MAXLINE,
                   "Database set to: %s\n"
                   "Keys:\n"
                   "Zone:                           "
                   "Key role:     "
                   "Id:                                      "
                   "ds-seen: "
                   "\n"
                   ,datastore
                   );
    ods_writen(sockfd, buf, strlen(buf));

    bool id_match = false;
    for (int z=0; z<keystateDoc->zones_size(); ++z) {

        const ::ods::keystate::EnforcerZone &enfzone  = keystateDoc->zones(z);
        
        for (int k=0; k<enfzone.keys_size(); ++k) {
            const ::ods::keystate::KeyData &key = enfzone.keys(k);

            // ZSKs are not referenced by DS records so skip them.
            if (key.role() == ::ods::keystate::ZSK)
                continue;
            // Skip KSKs with a zero length id, they are placeholder keys.
            if (key.locator().size()==0)
                continue;
            
            std::string keyrole = keyrole_Name(key.role());
            
            if (id && key.locator()==id || zone && enfzone.name()==zone)
            {
                ::ods::keystate::KeyData *mkey =
                    keystateDoc->mutable_zones(z)->mutable_keys(k);
                mkey->set_ds_seen(true);
                mkey->set_submit_to_parent(false);
                id_match = true;
            }

            const char *status = key.ds_seen() ? "yes" : "no";
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "%-31s %-13s %-40s %-8s\n",
                           enfzone.name().c_str(),
                           keyrole.c_str(),
                           key.locator().c_str(),
                           status
                           );
            ods_writen(sockfd, buf, strlen(buf));
        }
    }
    
    if (!id_match) {
        if (id) {
            (void)snprintf(buf, ODS_SE_MAXLINE, 
                    "WARNING - No key matches id \"%s\"\n", id);
            ods_writen(sockfd, buf, strlen(buf));
        }
        if (zone) {
            (void)snprintf(buf, ODS_SE_MAXLINE, 
                    "WARNING - No key matches zone \"%s\"\n", zone);
            ods_writen(sockfd, buf, strlen(buf));
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
}

static task_type * 
keystate_ds_seen_task_perform(task_type *task)
{
    perform_keystate_ds_seen(-1,(engineconfig_type *)task->context,NULL,NULL);
    
    task_cleanup(task);
    return NULL;
}

task_type *
keystate_ds_seen_task(engineconfig_type *config,const char *shortname)
{
    task_id what = task_register(shortname,
                                 "keystate_ds_seen_task_perform",
                                 keystate_ds_seen_task_perform);
	return task_create(what, time_now(), "all", (void*)config);
}
