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

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
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
		"update all\n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd, "Perform policy import, update zonelist, and update repositorylist.\n\n");
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
			&zonelist, &replist, &repcount,
			(ods_log_verbosity() >= 3)))
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
		free(replist);
	}
	if (policy_names) {
		for (i = 0; i < policy_count; i++) free(policy_names[i]);
	}
	return error;
}

static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
	int error;
        db_connection_t* dbconn = getconnectioncontext(context);
        engine_type* engine = getglobalcontext(context);
	(void)cmd;

	ods_log_debug("[%s] %s command", module_str, update_all_funcblock.cmdname);

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

		policy_import(sockfd, engine, dbconn, 0);
		zonelist_import(sockfd, engine, dbconn, 0, NULL);

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

struct cmd_func_block update_all_funcblock = {
	"update all", &usage, &help, NULL, &run
};
