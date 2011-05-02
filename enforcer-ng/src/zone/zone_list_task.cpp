
extern "C" {
#include "shared/duration.h"
#include "shared/file.h"
#include "zone/zone_list_task.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "zonelist.pb.h"

#include "xmlext-pb/xmlext.h"

#include <fcntl.h>

static const char *zone_list_task_str = "zone_list_task";

void 
perform_zone_list(int sockfd, engineconfig_type *config)
{
    char buf[ODS_SE_MAXLINE];
	const char *zonelistfile = config->zonelist_filename;
    const char *datastore = config->datastore;
    
	GOOGLE_PROTOBUF_VERIFY_VERSION;

    // Load the zonelist from the doc file
    ::ods::zonelist::ZoneListDocument *zonelistDoc =
    new ::ods::zonelist::ZoneListDocument;
    {
        std::string datapath(datastore);
        datapath += ".zonelist.pb";
        int fd = open(datapath.c_str(),O_RDONLY);
        if (zonelistDoc->ParseFromFileDescriptor(fd)) {
            ods_log_debug("[%s] zonelist has been loaded",
                          zone_list_task_str);
        } else {
            ods_log_error("[%s] zonelist could not be loaded from \"%s\"",
                          zone_list_task_str,datapath.c_str());
        }
        close(fd);
    }

    int nzones = zonelistDoc->zonelist().zones_size();
    if (nzones == 0) {
        (void)snprintf(buf, ODS_SE_MAXLINE,
                       "Zonelist filename set to: %s\n"
                       "Database set to: %s\n"
                       "I have no zones configured\n"
                       ,zonelistfile,datastore
                       );
        ods_writen(sockfd, buf, strlen(buf));
    } else {
        (void)snprintf(buf, ODS_SE_MAXLINE,
                       "Zonelist filename set to: %s\n"
                       "Database set to: %s\n"
                       "I have %i zones configured\n"
                       "Zones:\n"
                       "Zone:                           "
                       "Policy:      "
                       "Signer Configuration:"
                       "\n"
                       ,zonelistfile,datastore,nzones
                       );
        ods_writen(sockfd, buf, strlen(buf));
        
        for (int i=0; i<nzones; ++i) {
            const ::ods::zonelist::ZoneData &zl_zone = zonelistDoc->zonelist().zones(i);
            
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "%-31s %-13s %-34s\n",
                           zl_zone.name().c_str(),
                           zl_zone.policy().c_str(),
                           zl_zone.signerconfiguration().c_str()
                           );
            ods_writen(sockfd, buf, strlen(buf));
        }
    }
    
    ods_log_debug("[%s] zone list completed", zone_list_task_str);
}

static task_type * 
zone_list_task_perform(task_type *task)
{
    perform_zone_list(-1,(engineconfig_type *)task->context);
    
    task_cleanup(task);
    return NULL;
}

task_type *
zone_list_task(engineconfig_type *config)
{
    task_id what = task_register("zone list",
                                 "zone_list_task_perform", 
                                 zone_list_task_perform);
	return task_create(what, time_now(), "all",(void*)config);
}
