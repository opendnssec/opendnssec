extern "C" {
#include "keystate/keystate_ds_submit_task.h"
#include "shared/file.h"
#include "shared/duration.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext.h"


#include <fcntl.h>

static const char *module_str = "keystate_ds_submit_task";

void 
perform_keystate_ds_submit(int sockfd, engineconfig_type *config)
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
                   "Keytype:      "
                   "Should Submit: "
                   "\n"
                   ,datastore
                   );
    ods_writen(sockfd, buf, strlen(buf));

    for (int z=0; z<keystateDoc->zones_size(); ++z) {

        const ::ods::keystate::EnforcerZone &zone  = keystateDoc->zones(z);
        
        for (int k=0; k<zone.keys_size(); ++k) {
            const ::ods::keystate::KeyData &key = zone.keys(k);
            
            std::string keyrole = keyrole_Name(key.role());
            const char *action = key.submit_to_parent() ? "yes" : "no";
            
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "%-31s %-13s %-14s\n",
                           zone.name().c_str(),
                           keyrole.c_str(),
                           action
                           );
            ods_writen(sockfd, buf, strlen(buf));
        }
    }
}

static task_type * 
keystate_ds_submit_task_perform(task_type *task)
{
    perform_keystate_ds_submit(-1,(engineconfig_type *)task->context);
    
    task_cleanup(task);
    return NULL;
}

task_type *
keystate_ds_submit_task(engineconfig_type *config,const char *shortname)
{
    task_id what = task_register(shortname,
                                 "keystate_ds_submit_task_perform",
                                 keystate_ds_submit_task_perform);
	return task_create(what, time_now(), "all", (void*)config);
}
