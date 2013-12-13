/*
 * policy_purge_task.cpp
 *
 *  Created on: 2013-11-15
 *      Author: zhangjm
 */
#include <stdio.h>
#include <iostream>
#include <cassert>

#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "shared/log.h"

#include "enforcer/enforcerzone.h"
#include "policy/policy_purge_task.h"

#include "keystate/keystate_list_cmd.h"
#include "keystate/keystate_list_task.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "kasp.pb.h"

#include "xmlext-pb/xmlext-rd.h"
#include "xmlext-pb/xmlext-wr.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"
#include "daemon/engine.h"

#include <fcntl.h>
#include <memory>

static const char *module_str = "policy_purge_task";

int perform_policy_purge(int sockfd, engineconfig_type *config)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return 0; // error already reported.

	{	OrmTransactionRW transaction(conn);
		if (!transaction.started()) 
		{
			const char *emsg = "could not start database transaction";
			ods_log_error_and_printf(sockfd,module_str,emsg);
			return 0;
		}

		OrmResultRef rows;
		::ods::kasp::Policy policy;
		std::vector<std::string> purge_policy;
		bool ok = OrmMessageEnum(conn, policy.descriptor(), rows);
		if (!ok)
		{
			transaction.rollback();
			ods_log_error("[%s] enum policy failed", module_str);
			return 0;
		}

		for (bool next=OrmFirst(rows); next; next = OrmNext(rows))
		{
			OrmContextRef context;
			if (!OrmGetMessage(rows, policy, true, context))
			{
				rows.release();
				transaction.rollback();
				ods_log_error("[%s] retrieving policy from database failed");
				return 0;
			}
			purge_policy.push_back(policy.name());
		}
		rows.release();

		for (std::vector<std::string>::iterator it = purge_policy.begin();
				it != purge_policy.end(); ++it)
		{
			std::string del_policy;
			if (!OrmQuoteStringValue(conn, std::string(*it), del_policy))
			{
				transaction.rollback();
				const char *emsg = "quoting policy value failed";
				ods_log_error_and_printf(sockfd,module_str,emsg);
				return 0;
			}

			pb::uint64 count=0;
			if (!OrmMessageCountWhere(conn,::ods::keystate::EnforcerZone::descriptor(),count,"policy=%s",del_policy.c_str()))
			{
				transaction.rollback();
				const char *emsg = "Count EnforcerZone failed";
				ods_log_error_and_printf(sockfd,module_str,emsg);
				return 0;
			}else
			{
				if (count==0)
				{
					OrmMessageDeleteWhere(conn,
										  ::ods::kasp::Policy::descriptor(),
										  "name = %s",
										  del_policy.c_str());
					ods_printf(sockfd,"purge policy with name = %s succeed!\n",del_policy.c_str());
				}
			}
		}

		if (!transaction.commit()) 
		{
			const char *emsg = "committing purge policy to database failed";
			ods_log_error_and_printf(sockfd,module_str,emsg);
			return 0;
		}
	}
}
