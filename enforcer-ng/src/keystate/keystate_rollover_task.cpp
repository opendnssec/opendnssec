extern "C" {
#include "keystate/keystate_rollover_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"
#include "libhsmdns.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"

#include <memory.h>
#include <fcntl.h>

static const char *module_str = "keystate_rollover_task";

void 
perform_keystate_rollover(int sockfd, engineconfig_type *config,
                          const char *zone, int nkeyrole)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;

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
            }
            close(fd);
        } else {
            ods_log_error("[%s] file \"%s\" could not be opened",
                          module_str,datapath.c_str());
        }
    }

    bool bFlagsChanged = false;
    for (int z=0; z<keystateDoc->zones_size(); ++z) {
        ::ods::keystate::EnforcerZone *enfzone  = keystateDoc->mutable_zones(z);
        if (enfzone->name() != std::string(zone))
            continue;

        if (nkeyrole == 0) {
            enfzone->set_roll_ksk_now(true);
            enfzone->set_roll_zsk_now(true);
            enfzone->set_roll_csk_now(true);
            enfzone->set_next_change(0); // reschedule immediately
            bFlagsChanged = true;
            (void)snprintf(buf, ODS_SE_MAXLINE, "rolling all keys for zone %s\n",
                           zone);
            ods_writen(sockfd, buf, strlen(buf));
        } else
        if (nkeyrole == (int)::ods::keystate::KSK) {
            enfzone->set_roll_ksk_now(true);
            enfzone->set_next_change(0); // reschedule immediately
            bFlagsChanged = true;
            (void)snprintf(buf, ODS_SE_MAXLINE, "rolling KSK for zone %s\n",
                           zone);
            ods_writen(sockfd, buf, strlen(buf));
        }
        if (nkeyrole == (int)::ods::keystate::ZSK) {
            enfzone->set_roll_zsk_now(true);
            enfzone->set_next_change(0); // reschedule immediately
            bFlagsChanged = true;
            (void)snprintf(buf, ODS_SE_MAXLINE, "rolling ZSK for zone %s\n",
                           zone);
            ods_writen(sockfd, buf, strlen(buf));
        }
        if (nkeyrole == (int)::ods::keystate::CSK) {
            enfzone->set_roll_csk_now(true);
            enfzone->set_next_change(0); // reschedule immediately
            bFlagsChanged = true;
            (void)snprintf(buf, ODS_SE_MAXLINE, "rolling CSK for zone %s\n",
                           zone);
            ods_writen(sockfd, buf, strlen(buf));
        }
        break;
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
}
