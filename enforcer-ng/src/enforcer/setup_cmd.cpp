/*
 * $Id$
 *
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

#include <ctime>
#include <iostream>
#include <cassert>

#include "enforcer/setup_cmd.h"
#include "enforcer/autostart_cmd.h"

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

static const char *module_str = "setup_cmd";

/**
 * Print help for the 'setup' command
 *
 */
void help_setup_cmd(int sockfd)
{
   ods_printf(sockfd,
			   "setup                  Delete existing database contents and perform\n"
			   "                       update kasp, zonelist and repositorylist.\n"
        );
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
int handled_setup_cmd(int sockfd, engine_type* engine, const char *cmd,
					  ssize_t n)
{
    const char *scmd = "setup";
    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

	// check that we are using a compatible protobuf version.
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	
    time_t tstart = time(NULL);
	
	{
		// Drop the database tables using a dedicated database connection.
		OrmConnRef conn;
		if (!ods_orm_connect(sockfd, engine->config, conn))
			return 1; // errors have already been reported.
		
		if (!drop_database_tables(sockfd,conn,engine->config))
			return 1; // errors have already been reported.
	}

	{ 
		// Create the database tables using a dedicated database connection.
		OrmConnRef conn;
		if (!ods_orm_connect(sockfd, engine->config, conn))
			return 1; // errors have already been reported.
		
		if (!create_database_tables(sockfd, conn))
			return 1; // errors have already been reported.
	}

	autostart(engine);
	// TODO: Add this function once implemented
	//perform_update_conf(engine->config);
	perform_update_kasp(sockfd, engine->config);
	perform_update_keyzones(sockfd, engine->config);
	perform_update_hsmkeys(sockfd, engine->config, 0 /* automatic */);
	perform_hsmkey_gen(sockfd, engine->config, 0 /* automatic */,
					   engine->config->automatic_keygen_duration);

    flush_all_tasks(sockfd, engine);

    ods_printf(sockfd, "%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    return 1;
}
