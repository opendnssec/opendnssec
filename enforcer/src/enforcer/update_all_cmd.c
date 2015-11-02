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

#include <pthread.h>

#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "utils/kc_helper.h"
#include "clientpipe.h"
#include "policy/policy_import.h"
#include "keystate/zonelist_import.h"

#include "enforcer/update_all_cmd.h"

static const char *module_str = "update_all_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"update all             Perform policy import, update zonelist, and update repositorylist.\n"
	);
}

static int
check_all(int sockfd, engine_type* engine)
{
	char *kasp = NULL;
	char *zonelist = NULL;
	char **replist = NULL;
	char **policy_names = NULL;
	int repcount, i;
	int policy_count = 0;
	int error = 1;

	if (check_conf(engine->config->cfg_filename, &kasp, 
			&zonelist, &replist, &repcount, 0))
		ods_log_error_and_printf(sockfd, module_str, 
			"Unable to validate '%s' consistency.", 
			engine->config->cfg_filename);
	else if (check_kasp(kasp, replist, repcount, 0, &policy_names, &policy_count))
		ods_log_error_and_printf(sockfd, module_str, 
			"Unable to validate '%s' consistency.", kasp);
	else if (check_zonelist(zonelist, 0, policy_names, policy_count))
		ods_log_error_and_printf(sockfd, module_str, 
			"Unable to validate '%s' consistency.", zonelist);
	else error = 0;

	free(kasp);
	free(zonelist);
	if (replist) {
		for (i = 0; i < repcount; i++) free(replist[i]);
	}
	if (policy_names) {
		for (i = 0; i < policy_count; i++) free(policy_names[i]);
	}
	return error;
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, update_all_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	int error;
	(void)cmd; (void)n;

	ods_log_debug("[%s] %s command", module_str, update_all_funcblock()->cmdname);

	/*
	 * Check conf.xml, KASP and zonelist. If there are no errors we stop all
	 * activity, update KASP and zonelist and then reload in order to load the
	 * new conf.xml
	 */
	if (!(error = check_all(sockfd, engine))) {
		/*
		 * Lock the engine and stop all workers
		 */
		pthread_mutex_lock(&engine->signal_lock);
		engine_stop_workers(engine);

		/*
		 * Update KASP and zonelist, first update without deleting and then
		 * update with deleting. This is for when a zone has changed policy and
		 * the policy did not exist before.
		 * NOTE: Errors are ignored!
		 */
		policy_import(sockfd, engine, dbconn, 0);
		zonelist_import(sockfd, engine, dbconn, 0, NULL);
		policy_import(sockfd, engine, dbconn, 1);
		zonelist_import(sockfd, engine, dbconn, 1, NULL);

		/*
		 * Mark the engine for reload, signal it and start it again
		 */
		engine->need_to_reload = 1;
		pthread_cond_signal(&engine->signal_cond);
		engine_start_workers(engine);
		pthread_mutex_unlock(&engine->signal_lock);
	}
	return error;
}

static struct cmd_func_block funcblock = {
	"update all", &usage, NULL, &handles, &run
};

struct cmd_func_block*
update_all_funcblock(void)
{
	return &funcblock;
}
