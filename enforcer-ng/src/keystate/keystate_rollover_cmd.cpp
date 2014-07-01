/*
 * Copyright (c) 2011 Surfnet 
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2011 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "config.h"

#include <algorithm>
#include <string>

#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "enforcer/enforce_task.h"
#include "keystate/keystate.pb.h"
#include "daemon/clientpipe.h"

#include "keystate/keystate_rollover_cmd.h"

#include "shared/log.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"
#include "libhsmdns.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>
#include "daemon/clientpipe.h"
#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <memory>
#include <fcntl.h>

static const char *module_str = "keystate_rollover_cmd";

#define ODS_LOG_AND_RETURN(errmsg) do { \
ods_log_error_and_printf(sockfd,module_str,errmsg); return 1; } while (0)
#define ODS_LOG_AND_CONTINUE(errmsg) do { \
ods_log_error_and_printf(sockfd,module_str,errmsg); continue; } while (0)

int 
perform_keystate_rollover(int sockfd, engineconfig_type *config,
                          const char *zone, int nkeyrole)
{
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return 1;
	
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
				client_printf(sockfd,"zone %s not found\n",zone);
				return 1;
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
					client_printf(sockfd,"rolling all keys for zone %s\n",zone);
					ods_log_info("[%s] Manual rollover initiated for all keys on Zone: %s", module_str, zone);
					break;
				case ::ods::keystate::KSK:
					enfzone.set_roll_ksk_now(true);
					enfzone.set_next_change(0); // reschedule immediately
					client_printf(sockfd,"rolling KSK for zone %s\n",zone);
					ods_log_info("[%s] Manual rollover initiated for KSK on Zone: %s", module_str, zone);
					break;
				case ::ods::keystate::ZSK:
					enfzone.set_roll_zsk_now(true);
					enfzone.set_next_change(0); // reschedule immediately
					client_printf(sockfd,"rolling ZSK for zone %s\n",zone);
					ods_log_info("[%s] Manual rollover initiated for ZSK on Zone: %s", module_str, zone);
					break;
				case ::ods::keystate::CSK:
					enfzone.set_roll_csk_now(true);
					enfzone.set_next_change(0); // reschedule immediately
					client_printf(sockfd,"rolling CSK for zone %s\n",zone);
					ods_log_info("[%s] Manual rollover initiated for CSK on Zone: %s", module_str, zone);
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
	return 0;
}

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key rollover           Perform a manual key rollover.\n"
		"      --zone <zone>              (aka -z)  zone.\n"
		"      [--keytype <keytype>]      (aka -t)  KSK or ZSK (default all).\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_rollover_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	char buf[ODS_SE_MAXLINE];
	const int NARGV = 8;
	const char *argv[NARGV];
	int argc, error;

	ods_log_debug("[%s] %s command", module_str, key_rollover_funcblock()->cmdname);

	cmd = ods_check_command(cmd, n, key_rollover_funcblock()->cmdname);

	// Use buf as an intermediate buffer for the command.
	strncpy(buf, cmd, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';

	// separate the arguments
	argc = ods_str_explode(buf, NARGV, argv);
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
						module_str, key_rollover_funcblock()->cmdname);
		client_printf(sockfd,"too many arguments\n");
		return -1;
	}

	const char *zone = NULL;
	const char *keytype = NULL;
	(void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
	(void)ods_find_arg_and_param(&argc,argv,"keytype","t",&keytype);
	if (argc) {
		ods_log_warning("[%s] unknown arguments for %s command",
						module_str, key_rollover_funcblock()->cmdname);
		client_printf(sockfd,"unknown arguments\n");
		return -1;
	}
	if (!zone) {
		ods_log_warning("[%s] expected option --zone <zone> for %s command",
						module_str, key_rollover_funcblock()->cmdname);
		client_printf(sockfd,"expected --zone <zone> option\n");
		return -1;
	}

	int nkeytype = 0;
	if (keytype) {
		std::string kt(keytype);
		int (*fp)(int) = toupper;
		std::transform(kt.begin(),kt.end(),kt.begin(),fp);
		if (kt == "KSK") {
			nkeytype = (int)::ods::keystate::KSK;
		} else if (kt == "ZSK") {
			nkeytype = (int)::ods::keystate::ZSK;
		} else if (kt == "CSK") {
			nkeytype = (int)::ods::keystate::CSK;
		} else {
			ods_log_warning("[%s] given keytype \"%s\" invalid",
							module_str,keytype);
			client_printf(sockfd,"given keytype \"%s\" invalid\n",keytype);
			return 1;
		}
	}

	error = perform_keystate_rollover(sockfd,engine->config,zone,nkeytype);
	flush_enforce_task(engine, 0);
	return error;
}

static struct cmd_func_block funcblock = {
	"key rollover", &usage, NULL, &handles, &run
};

struct cmd_func_block*
key_rollover_funcblock(void)
{
	return &funcblock;
}
