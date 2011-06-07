extern "C" {
#include "keystate/keystate_list_task.h"
#include "shared/file.h"
#include "shared/duration.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"


#include <fcntl.h>

static const char *module_str = "keystate_list_task";

void 
perform_keystate_list(int sockfd, engineconfig_type *config, int bverbose)
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
                   "DS:          "
                   "DNSKEY:      "
                   "RRSIG:       "
                   "Pub: "
                   "Act: "
                   "Id:"
                   "\n"
                   ,datastore
                   );
    ods_writen(sockfd, buf, strlen(buf));

    for (int z=0; z<keystateDoc->zones_size(); ++z) {

        const ::ods::keystate::EnforcerZone &zone  = keystateDoc->zones(z);
        
        for (int k=0; k<zone.keys_size(); ++k) {
            const ::ods::keystate::KeyData &key = zone.keys(k);
            std::string keyrole = keyrole_Name(key.role());
            std::string ds_rrstate = rrstate_Name(key.ds().state());
            std::string rrsig_rrstate = rrstate_Name(key.rrsig().state());
            std::string dnskey_rrstate = rrstate_Name(key.dnskey().state());
            (void)snprintf(buf, ODS_SE_MAXLINE,
                       "%-31s %-13s %-12s %-12s %-12s %d %4d    %s\n",
                       zone.name().c_str(),
                       keyrole.c_str(),
                       ds_rrstate.c_str(),
                       dnskey_rrstate.c_str(),
                       rrsig_rrstate.c_str(),
                       key.publish(),
                       key.active(),
                       key.locator().c_str()
                       );
            ods_writen(sockfd, buf, strlen(buf));
        }
    }
}

#if 0
static task_type * 
keystate_list_task_perform(task_type *task)
{
    perform_keystate_list(-1,(engineconfig_type *)task->context, 0);
    
    task_cleanup(task);
    return NULL;
}

task_type *
keystate_list_task(engineconfig_type *config,const char *shortname)
{
    task_id what = task_register(shortname,
                                 "keystate_list_task_perform",
                                 keystate_list_task_perform);
	return task_create(what, time_now(), "all", (void*)config);
}
#endif
