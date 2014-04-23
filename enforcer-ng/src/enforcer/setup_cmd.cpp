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

#include <ctype.h>

#include "daemon/cmdhandler.h"
#include "enforcer/autostart_cmd.h"
#include "enforcer/update_repositorylist_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
#include "daemon/orm.h"
#include "policy/update_kasp_task.h"
#include "policy/kasp.pb.h"
#include "keystate/update_keyzones_task.h"
#include "keystate/keystate.pb.h"
#include "hsmkey/update_hsmkeys_task.h"    
#include "hsmkey/hsmkey_gen_task.h"    
#include "hsmkey/hsmkey.pb.h"
#include "protobuf-orm/pb-orm.h"
#include "daemon/clientpipe.h"

#include "enforcer/setup_cmd.h"


static const char *module_str = "setup_cmd";

/**
 * Print help for the 'setup' command
 *
 */
static void
usage(int sockfd)
{
	client_printf(sockfd,
		"setup                  Delete existing database contents and perform\n"
		"                       update kasp, zonelist and repositorylist.\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, setup_funcblock()->cmdname)?1:0;
}

static bool
create_database_tables(int sockfd, OrmConn conn)
{
	bool ok = true;
	if (!OrmCreateTable(conn, ods::hsmkey::HsmKey::descriptor() )) {
		ods_log_error_and_printf(sockfd, module_str,
								 "creating HsmKey tables failed");
		ok = false;
	}
	
	if (!OrmCreateTable(conn, ods::kasp::Policy::descriptor())) {
		ods_log_error_and_printf(sockfd,module_str,
								 "creating Policy tables failed");
		ok = false;
	}

	if (!OrmCreateTable(conn, ods::keystate::EnforcerZone::descriptor())) {
		ods_log_error_and_printf(sockfd,module_str,
								 "creating EnforcerZone tabled failed");
		ok = false;
	}
	return ok;
}

static bool
drop_database_tables(int sockfd, OrmConn conn, engineconfig_type* config)
{
	bool ok = true;
	if  (!OrmDropTable(conn,  ods::hsmkey::HsmKey::descriptor())) {
		ods_log_error_and_printf(sockfd, module_str,
								 "dropping HsmKey tables failed");
		ok = false;
	}
	if  (!OrmDropTable(conn,  ods::kasp::Policy::descriptor())) {
		ods_log_error_and_printf(sockfd, module_str,
								 "dropping Policy tables failed");
		ok = false;
	}
	if  (!OrmDropTable(conn,  ods::keystate::EnforcerZone::descriptor())) {
		ods_log_error_and_printf(sockfd, module_str,
								 "dropping EnforcerZone tables failed");
		ok = false;
	}
	
	if (!config->db_host && config->datastore) {
		// SQLite because 'db_host' is not assigned a value, but 'datastore' is.

		// Try to remove the SQLite database file too.
		if (unlink(config->datastore)==-1 && errno!=ENOENT) {
			ods_log_error_and_printf(sockfd, module_str,
									 "unlink of \"%s\" failed: %s (%d)",
									 config->datastore,strerror(errno),errno);
			ok = false;
		}
	}
	return ok;
}

/**
 * Handle the 'setup' command.
 *
 */
static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	char buf[ODS_SE_MAXLINE];
	(void)cmd; (void)n;
	
	assert(engine);
	
	ods_log_debug("[%s] %s command", module_str, setup_funcblock()->cmdname);

	if (!client_prompt_user(sockfd, 
			"*WARNING* This will erase all data in the database;"
			"are you sure? [y/N] ", buf))
		return 1;
	if (toupper(buf[0]) != 'Y') {
		client_printf(sockfd, "Okay, quitting...\n");
		return 1;
	}

	lock_basic_lock(&engine->signal_lock);
		/** we have got the lock, daemon thread is not going anywhere 
		 * we can safely stop all workers */
		engine->need_to_reload = 1;
		engine_stop_workers(engine);

		// Drop the database tables using a dedicated database connection.
		OrmConnRef conn;
		if (!ods_orm_connect(sockfd, engine->config, conn)
			|| !drop_database_tables(sockfd,conn,engine->config)
			|| !ods_orm_connect(sockfd, engine->config, conn)
			|| !create_database_tables(sockfd, conn))
		{
			engine->need_to_reload = 0;
			engine_start_workers(engine);
			lock_basic_unlock(&engine->signal_lock);
			lock_basic_alarm(&engine->signal_cond);
			return 1; // errors have already been reported.
		}

		/* we might have skipped this when starting w/o a db */
		autostart(engine); 

		/* TODO: Add this function once implemented
		 * perform_update_conf(engine->config); */
		int error = !perform_update_kasp(sockfd, engine->config);
		if (!error)
			error |= !perform_update_keyzones(sockfd, engine->config);
		if (!error) {
			perform_update_hsmkeys(sockfd, engine->config, 0 /* automatic */);
			(void)perform_hsmkey_gen(sockfd, engine->config, 0 /* automatic */,
							   engine->config->automatic_keygen_duration);
		}

		engine->need_to_reload = 0;
		engine_start_workers(engine);
		flush_all_tasks(sockfd, engine);
	lock_basic_unlock(&engine->signal_lock);
	lock_basic_alarm(&engine->signal_cond);

	return error;
}

static struct cmd_func_block funcblock = {
	"setup", &usage, NULL, &handles, &run
};

struct cmd_func_block*
setup_funcblock(void)
{
	return &funcblock;
}
