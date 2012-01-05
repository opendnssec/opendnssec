#include "keystate/update_keyzones_task.h"
#include "shared/file.h"
#include "shared/duration.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "zone/zonelist.pb.h"
#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"

#include <fcntl.h>

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

static const char *module_str = "update_keyzones_task";

static bool
load_zonelist_xml(int sockfd, const char * zonelistfile,
				  std::auto_ptr< ::ods::zonelist::ZoneListDocument >&doc)
{
	// Create a zonefile and load it with zones from the xml zonelist.xml
	doc.reset(new ::ods::zonelist::ZoneListDocument);
	if (doc.get() == NULL) {
		ods_log_error_and_printf(sockfd,module_str,
								 "out of memory allocating ZoneListDocument");
		return false;
	}
	
	if (!read_pb_message_from_xml_file(doc.get(), zonelistfile)) {
		ods_log_error_and_printf(sockfd,module_str,
								 "unable to read the zonelist.xml file");
		return false;
	}
		
	if (!doc->has_zonelist()) {
		ods_log_error_and_printf(sockfd,module_str,
								 "no zonelist found in zonelist.xml file");
		return false;
	}
		
	const ::ods::zonelist::ZoneList  &zonelist = doc->zonelist();
	if (zonelist.zones_size() <= 0) {
		ods_log_error_and_printf(sockfd,module_str,
								 "no zones found in zonelist");
		return false;
	}
	
	if (!zonelist.IsInitialized()) {
		ods_log_error_and_printf(sockfd,module_str,
								 "a zone in the zonelist is missing mandatory "
								 "information");
		return false;
	}

	return true;
}


void 
perform_update_keyzones(int sockfd, engineconfig_type *config)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    std::auto_ptr< ::ods::zonelist::ZoneListDocument > zonelistDoc;
	if (!load_zonelist_xml(sockfd, config->zonelist_filename, zonelistDoc))
		return; // errors have already been reported.

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return;  // errors have already been reported.

	//TODO: SPEED: We should create an index on the EnforcerZone.name column
		
    // Go through the list of zones from the zonelist to determine if we need
    // to insert new zones to the keystates.
    for (int i=0; i<zonelistDoc->zonelist().zones_size(); ++i) {
        const ::ods::zonelist::ZoneData &zl_zone = 
            zonelistDoc->zonelist().zones(i);
		
		{	OrmTransactionRW transaction(conn);
			if (!transaction.started()) {
				ods_log_error_and_printf(sockfd, module_str,
					"error starting a database transaction for updating zones");
				return;
			}
			
			std::string qzone;
			if (!OrmQuoteStringValue(conn, zl_zone.name(), qzone)) {
				ods_log_error_and_printf(sockfd, module_str,
										 "quoting a string failed");
				return;
			}

			::ods::keystate::EnforcerZone ks_zone;
			{	OrmResultRef rows;
				
				if (!OrmMessageEnumWhere(conn, ks_zone.descriptor(), rows,
										 "name = %s",qzone.c_str()))
				{
					ods_log_error_and_printf(sockfd, module_str,
											 "zone lookup by name failed");
					return;
				}
			
				// if OrmFirst succeeds, a zone with the queried name is 
				// already present
				if (OrmFirst(rows))
					continue; // skip existing zones

				//TODO: FEATURE: update zone fields with information from zonelist.

				// query no longer needed, so lets drop it.
				rows.release();
				
				// setup information the enforcer will need.
				ks_zone.set_name( zl_zone.name() );
				ks_zone.set_policy( zl_zone.policy() );
				ks_zone.set_signconf_path( zl_zone.signer_configuration() );
							
				// enforcer needs to trigger signer configuration writing.
				ks_zone.set_signconf_needs_writing( false );
				
				pb::uint64 zoneid;
				if (!OrmMessageInsert(conn, ks_zone, zoneid)) {
					ods_log_error_and_printf(sockfd, module_str,
									"inserting zone into the database failed");
					return;
				}
				
				if (!transaction.commit()) {
					ods_log_error_and_printf(sockfd, module_str,
									"committing zone to the database failed");
					return;
				}
			}
		}
    }
}
