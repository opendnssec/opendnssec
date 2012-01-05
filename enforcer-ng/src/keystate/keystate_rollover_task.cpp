#include "keystate/keystate_rollover_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"
#include "libhsmdns.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <memory>
#include <fcntl.h>

static const char *module_str = "keystate_rollover_task";

#define ODS_LOG_AND_RETURN(errmsg) do { \
ods_log_error_and_printf(sockfd,module_str,errmsg); return; } while (0)
#define ODS_LOG_AND_CONTINUE(errmsg) do { \
ods_log_error_and_printf(sockfd,module_str,errmsg); continue; } while (0)

void 
perform_keystate_rollover(int sockfd, engineconfig_type *config,
                          const char *zone, int nkeyrole)
{
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return; // error already reported.
	
	{	OrmTransactionRW transaction(conn);
		if (!transaction.started())
			ODS_LOG_AND_RETURN("transaction not started");
		
		{	OrmResultRef rows;
			::ods::keystate::EnforcerZone enfzone;
			
			std::string qzone;
			if (!OrmQuoteStringValue(conn, std::string(zone), qzone))
				ODS_LOG_AND_RETURN("quoting string value failed");
			
			if (!OrmMessageEnumWhere(conn,enfzone.descriptor(),
									 rows,"name = %s",qzone.c_str()))
				ODS_LOG_AND_RETURN("zone enumeration failed");
			
			if (!OrmFirst(rows)) {
				ods_printf(sockfd,"zone %s not found\n",zone);
				return;
			}

			OrmContextRef context;
			if (!OrmGetMessage(rows, enfzone, /*just zone*/false, context))
				ODS_LOG_AND_RETURN("retrieving zone from database failed");
				
			// we no longer need the query result, so release it.
			rows.release();
			
			switch (nkeyrole) {
				case 0:
					enfzone.set_roll_ksk_now(true);
					enfzone.set_roll_zsk_now(true);
					enfzone.set_roll_csk_now(true);
					enfzone.set_next_change(0); // reschedule immediately
					ods_printf(sockfd,"rolling all keys for zone %s\n",zone);
					break;
				case ::ods::keystate::KSK:
					enfzone.set_roll_ksk_now(true);
					enfzone.set_next_change(0); // reschedule immediately
					ods_printf(sockfd,"rolling KSK for zone %s\n",zone);
					break;
				case ::ods::keystate::ZSK:
					enfzone.set_roll_zsk_now(true);
					enfzone.set_next_change(0); // reschedule immediately
					ods_printf(sockfd,"rolling ZSK for zone %s\n",zone);
					break;
				case ::ods::keystate::CSK:
					enfzone.set_roll_csk_now(true);
					enfzone.set_next_change(0); // reschedule immediately
					ods_printf(sockfd,"rolling CSK for zone %s\n",zone);
					break;
				default:
					ods_log_assert(false && "nkeyrole out of range");
					ODS_LOG_AND_RETURN("nkeyrole out of range");
			}

			// Update the changes back into the database.
			if (!OrmMessageUpdate(context))
				ODS_LOG_AND_RETURN("updating zone in the database failed");

			// The zone has been changed and we need to commit it.
			if (!transaction.commit())
				ODS_LOG_AND_RETURN("commiting updated zone to the database failed");
		}
	}
}
