#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "keystate/zone_del_task.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"

#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <fcntl.h>

static const char *module_str = "zone_del_task";

void 
perform_zone_del(int sockfd, engineconfig_type *config, const char *zone)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return; // error already reported.

	std::string qzone;
	if (!OrmQuoteStringValue(conn, std::string(zone), qzone)) {
		const char *emsg = "quoting zone value failed";
		ods_log_error_and_printf(sockfd,module_str,emsg);
		return;
	}
	
	{	OrmTransactionRW transaction(conn);
		if (!transaction.started()) {
			const char *emsg = "could not start database transaction";
			ods_log_error_and_printf(sockfd,module_str,emsg);
			return;
		}
		
		if (!OrmMessageDeleteWhere(conn,
								   ::ods::keystate::EnforcerZone::descriptor(),
								   "name = %s",
								   qzone.c_str()))
		{
			const char *emsg = "unable to delete zone %s";
			ods_log_error_and_printf(sockfd,module_str,emsg,qzone.c_str());
			return;
		}
		
		if (!transaction.commit()) {
			const char *emsg = "committing delete of zone %s to database failed";
			ods_log_error_and_printf(sockfd,module_str,emsg,qzone.c_str());
			return;
		}
    }

    ods_log_debug("[%s] zone %s deleted successfully", module_str,qzone.c_str());
	ods_printf(sockfd, "zone %s deleted successfully\n",qzone.c_str());
}
