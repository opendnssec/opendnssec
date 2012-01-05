#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "keystate/zone_list_task.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"

#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <fcntl.h>

static const char *module_str = "zone_list_task";

void 
perform_zone_list(int sockfd, engineconfig_type *config)
{
	const char *zonelistfile = config->zonelist_filename;

	GOOGLE_PROTOBUF_VERIFY_VERSION;

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return; // error already reported.

	{	OrmTransaction transaction(conn);
		if (!transaction.started()) {
			const char *errmsg = "could not start database transaction";
			ods_log_error_and_printf(sockfd,module_str,errmsg);
			return;
		}
		
		::ods::keystate::EnforcerZone zone;
		
		{	OrmResultRef rows;
			if (!OrmMessageEnum(conn, zone.descriptor(),rows)) {
				const char *errmsg = "failure during zone enumeration";
				ods_log_error_and_printf(sockfd,module_str,errmsg);
				return;
			}
			
			if (!OrmFirst(rows)) {
				ods_printf(sockfd,
						   "Zonelist filename set to: %s\n"
						   "Database set to: %s\n"
						   "I have no zones configured\n",
						   zonelistfile,
						   config->datastore);
				return;
			}

			//TODO: SPEED: what if there are milions of zones ?
			
			ods_printf(sockfd,
                       "Zonelist filename set to: %s\n"
                       "Database set to: %s\n"
//                       "I have %i zones configured\n"
                       "Zones:\n"
                       "Zone:                           "
                       "Policy:       "
                       "Next change:               "
                       "Signer Configuration:"
                       "\n",
                       zonelistfile,
					   config->datastore //,nzones
                       );
			
			for (bool next=true; next; next=OrmNext(rows)) {

				if (!OrmGetMessage(rows, zone, true))
					return;
				
				char nctime[32];
				if (zone.next_change()>0) {
					if (!ods_ctime_r(nctime,sizeof(nctime),zone.next_change())) {
						strncpy(nctime,"invalid date/time",sizeof(nctime));
						nctime[sizeof(nctime)-1] = '\0';
					}
				} else {
					strncpy(nctime,"as soon as possible",sizeof(nctime));
					nctime[sizeof(nctime)-1] = '\0';
				}
				ods_printf(sockfd,
						   "%-31s %-13s %-26s %-34s\n",
						   zone.name().c_str(),
						   zone.policy().c_str(),
						   nctime,
						   zone.signconf_path().c_str()
						   );
			}
        }
    }

    ods_log_debug("[%s] zone list completed", module_str);
}
