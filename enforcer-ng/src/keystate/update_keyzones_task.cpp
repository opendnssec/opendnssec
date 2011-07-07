extern "C" {
#include "keystate/update_keyzones_task.h"
#include "shared/file.h"
#include "shared/duration.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "zone/zonelist.pb.h"
#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"

#include <fcntl.h>

static const char *module_str = "update_keyzones_task";

static 
::ods::zonelist::ZoneListDocument *
load_zonelist_xml(int sockfd, const char *zonelistfile)
{
    char buf[ODS_SE_MAXLINE];
	// Create a zonefile and load it with zones from the xml zonelist.xml
	::ods::zonelist::ZoneListDocument *doc  = new ::ods::zonelist::ZoneListDocument;
	if (read_pb_message_from_xml_file(doc, zonelistfile)) {
		if (doc->has_zonelist()) {
			const ::ods::zonelist::ZoneList  &zonelist = doc->zonelist();
			if (zonelist.zones_size() > 0) {
				if (zonelist.IsInitialized()) {
                    
                    return doc;
                    
				} else {
                    (void)snprintf(buf, ODS_SE_MAXLINE, "error: a zone in the zonelist is missing mandatory information.\n");
                    ods_writen(sockfd, buf, strlen(buf));
                }
			} else {
                (void)snprintf(buf, ODS_SE_MAXLINE, "warning: no zones found in zonelist.\n");
                ods_writen(sockfd, buf, strlen(buf));
            }
		} else {
            (void)snprintf(buf, ODS_SE_MAXLINE, "warning: no zonelist found in zonelist.xml file.\n");
            ods_writen(sockfd, buf, strlen(buf));
        }
    } else {
        (void)snprintf(buf, ODS_SE_MAXLINE, "warning: unable to read the zonelist.xml file.\n");
        ods_writen(sockfd, buf, strlen(buf));
    }
    delete doc;
    return NULL;
}


void 
perform_update_keyzones(int sockfd, engineconfig_type *config)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;

	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    ::ods::zonelist::ZoneListDocument *
        zonelistDoc = load_zonelist_xml(sockfd, config->zonelist_filename);
    if (zonelistDoc == NULL) {
        ods_log_error("[%s] zonelist could not be loaded from \"%s\"",
                      module_str,config->zonelist_filename);
        return; // failure, exit.
    }
    
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
    
    // Add new zones found in the zonelist to the keystates
    // We don't want nested lookup loops of O(N^2) we create a map to get O(2N)
    std::map<const std::string,const ::ods::keystate::EnforcerZone*> kszonemap;
    for (int z=0; z<keystateDoc->zones_size(); ++z) {
        const ::ods::keystate::EnforcerZone &ks_zone = keystateDoc->zones(z);
        kszonemap[ ks_zone.name() ] = &ks_zone;
    }
    // Go through the list of zones from the zonelist to determine if we need
    // to insert new zones to the keystates.
    for (int i=0; i<zonelistDoc->zonelist().zones_size(); ++i) {
        const ::ods::zonelist::ZoneData &zl_zone = 
            zonelistDoc->zonelist().zones(i);
        // if we can't find the zone in the kszonemap, it is new and we need
        // to add it.
        if (kszonemap.find( zl_zone.name() ) == kszonemap.end()) {
            ::ods::keystate::EnforcerZone *ks_zone = keystateDoc->add_zones();
            
            // setup information the enforcer will need.
            ks_zone->set_name( zl_zone.name() );
            ks_zone->set_policy( zl_zone.policy() );
            ks_zone->set_signconf_path( zl_zone.signer_configuration() );
                        
            // enforcer needs to trigger signer configuration writing.
            ks_zone->set_signconf_needs_writing( false );
        }
    }
    
    // Persist the keystate zones back to disk as they may have
    // been changed by the key state update
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
    
    delete keystateDoc;
    delete zonelistDoc;
}

static task_type * 
update_keyzones_task_perform(task_type *task)
{
    perform_update_keyzones(-1,(engineconfig_type *)task->context);
    task_cleanup(task);
    return NULL;
}

task_type *
update_keyzones_task(engineconfig_type *config,const char *shortname)
{
    task_id what = task_register(shortname,
                                 "update_keyzones_task_perform",
                                 update_keyzones_task_perform);
	return task_create(what, time_now(), "all", (void*)config);
}
