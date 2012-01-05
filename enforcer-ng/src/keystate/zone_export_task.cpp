#include "keystate/zone_export_task.h"
#include "shared/file.h"
#include "shared/duration.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"
#include "xmlext-pb/xmlext-wr.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <memory>

#include <fcntl.h>

static const char *module_str = "zone_export_task";

#define ODS_LOG_AND_RETURN(errmsg) do { \
	ods_log_error_and_printf(sockfd,module_str,errmsg); return; } while (0)
#define ODS_LOG_AND_CONTINUE(errmsg) do { \
	ods_log_error_and_printf(sockfd,module_str,errmsg); continue; } while (0)

void 
perform_zone_export(int sockfd, engineconfig_type *config, const char *zone)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return; // error already reported.
	
	{	OrmTransaction transaction(conn);
		if (!transaction.started())
			ODS_LOG_AND_RETURN("transaction not started");
		
		{	OrmResultRef rows;
			ods::keystate::KeyStateExport kexport;
			
			std::string qzone;
			if (!OrmQuoteStringValue(conn, std::string(zone), qzone))
				ODS_LOG_AND_RETURN("quoting string value failed");
			
			if (!OrmMessageEnumWhere(conn,kexport.zone().descriptor(),
									 rows,"name = %s",qzone.c_str()))
				ODS_LOG_AND_RETURN("message enumeration failed");

			for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
				
				if (!OrmGetMessage(rows, *kexport.mutable_zone(), true))
					ODS_LOG_AND_CONTINUE("reading zone from database failed");

				if (!write_pb_message_to_xml_fd(kexport.mutable_zone(),sockfd))
					ODS_LOG_AND_CONTINUE("writing message to xml file failed");
			}
		}
    }
}
