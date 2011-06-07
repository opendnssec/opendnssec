extern "C" {
#include "keystate/keystate_export_task.h"
#include "shared/file.h"
#include "shared/duration.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"
#include "xmlext-pb/xmlext-wr.h"


#include <fcntl.h>

static const char *module_str = "keystate_export_task";

void 
perform_keystate_export(int sockfd, engineconfig_type *config, const char *zone)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    std::auto_ptr< ::ods::keystate::KeyStateDocument >
        keystateDoc( new ::ods::keystate::KeyStateDocument );
    {
        std::string datapath(config->datastore);
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
    
    for (int z=0; z<keystateDoc->zones_size(); ++z) {
        const ::ods::keystate::EnforcerZone &efzone  = keystateDoc->zones(z);
        if (efzone.name() == zone) {
            ods::keystate::KeyStateExport *kexport = new ods::keystate::KeyStateExport;
            *kexport->mutable_zone() = efzone;
            write_pb_message_to_xml_fd(kexport,sockfd);
            delete kexport;
        }
    }
}
