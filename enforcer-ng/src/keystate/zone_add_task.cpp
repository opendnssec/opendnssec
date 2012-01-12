#include "keystate/zone_add_task.h"
#include "shared/file.h"
#include "shared/duration.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"

#include <memory>
#include <fcntl.h>

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

static const char *module_str = "zone_add_task";

void 
perform_zone_add(int sockfd,
				 engineconfig_type *config,
				 const char *zone,
				 const char *policy,
				 const char *signerconf,
				 const char *ad_input_file,
				 const char *ad_output_file,
				 const char *ad_input_type,
				 const char *ad_input_config,
				 const char *ad_output_type,
				 const char *ad_output_config)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return;  // errors have already been reported.

	{	OrmTransactionRW transaction(conn);
		if (!transaction.started()) {
			ods_log_error_and_printf(sockfd, module_str,
				"starting a database transaction for adding a zone failed");
			return;
		}
		
		std::string qzone;
		if (!OrmQuoteStringValue(conn, std::string(zone), qzone)) {
			ods_log_error_and_printf(sockfd, module_str,
									 "quoting a string failed");
			return;
		}

		{	OrmResultRef rows;
			
			::ods::keystate::EnforcerZone ks_zone;
			if (!OrmMessageEnumWhere(conn, ks_zone.descriptor(), rows,
									 "name = %s",qzone.c_str()))
			{
				ods_log_error_and_printf(sockfd, module_str,
										 "zone lookup by name failed");
				return;
			}
		
			// if OrmFirst succeeds, a zone with the queried name is 
			// already present
			if (OrmFirst(rows)) {
				ods_log_error_and_printf(sockfd,
										 module_str,
										 "zone %s already exists",
										 zone);
				return;
			}

			// query no longer needed, so let's release it.
			rows.release();
			
			// setup information the enforcer will need.
			ks_zone.set_name( zone );
			ks_zone.set_policy( policy );
			ks_zone.set_signconf_path( signerconf );
			if (*ad_input_file) {
				ks_zone.mutable_adapters()->mutable_input()->set_file(ad_input_file);
			}
			if (*ad_output_file) {
				ks_zone.mutable_adapters()->mutable_output()->set_file(ad_output_file);
			}
			if (*ad_input_type) {
				::ods::keystate::Other *other =
				  ks_zone.mutable_adapters()->mutable_input()->mutable_other();
				other->set_type(ad_input_type);
				other->set_config(ad_input_config);
			}
			if (*ad_output_type) {
				::ods::keystate::Other *other =
				ks_zone.mutable_adapters()->mutable_output()->mutable_other();
				other->set_type(ad_output_type);
				other->set_config(ad_output_config);
			}
						
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
