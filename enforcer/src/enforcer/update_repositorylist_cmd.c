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
#include "str.h"
#include "log.h"
#include "file.h"
#include "daemon/engine.h"
#include "clientpipe.h"
#include "daemon/cfg.h"
#include "parser/confparser.h"
#include "longgetopt.h"
#include "status.h"
#include "utils/kc_helper.h"
#include "daemon/engine.h"
#include "libhsm.h"

#include "enforcer/update_repositorylist_cmd.h"

static const char *module_str = "update_repositorylist_cmd";

/* 0 succes, 1 error */
static int
validate_configfile(const char* cfgfile)
{
	char *kasp = NULL, *zonelist = NULL, **replist = NULL;
	int repcount, i;
	int cc_status = check_conf(cfgfile, &kasp, &zonelist, &replist, 
		&repcount, 0);
	free(kasp);
	free(zonelist);
	if (replist) for (i = 0; i < repcount; i++) free(replist[i]);
	free(replist);
	return cc_status;
}

/** 
 * Update the repositorylist
 * \param sockfd. Client to print to.
 * \param engine. Main daemon state
 * \return 1 on success, 0 on failure.
 */
static int
perform_update_repositorylist(int sockfd, engine_type* engine)
{
	const char* cfgfile = ODS_SE_CFGFILE;
	int status = 1;
	hsm_repository_t* new_reps;

	if (validate_configfile(cfgfile)) {
		ods_log_error_and_printf(sockfd, module_str,
			"Unable to validate '%s' consistency.", cfgfile);
		return 0;
	}
	
	/* key gen tasks must be stopped, hsm connections must be closed
	 * easiest way is to stop all workers,  */
	pthread_mutex_lock(&engine->signal_lock);
		/** we have got the lock, daemon thread is not going anywhere 
		 * we can safely stop all workers */
		engine_stop_workers(engine);
		new_reps = parse_conf_repositories(cfgfile);
		if (!new_reps) {
			/* revert */
			status = 0;
			client_printf(sockfd, "Could not load new repositories. Will continue with old.\n");
		} else {
			/* succes */
            hsm_repository_free(engine->config->repositories);
			engine->config->repositories = new_reps;
			engine->need_to_reload = 1;
			client_printf(sockfd, "new repositories parsed successful.\n");
			client_printf(sockfd, "Notifying enforcer of new respositories.\n");
			/* kick daemon thread so it will reload the hsms */
			pthread_cond_signal(&engine->signal_cond);
		}
		engine_start_workers(engine);
	pthread_mutex_unlock(&engine->signal_lock);
	return status;
}

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"update repositorylist\n");
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"Import respositories from conf.xml into the enforcer.\n\n");
}

static int
run(cmdhandler_ctx_type* context, int argc, char* argv[])
{
     int sockfd = context->sockfd;
        engine_type* engine = getglobalcontext(context);

	if (!perform_update_repositorylist(sockfd, engine)) {
		ods_log_error_and_printf(sockfd, module_str,
			"unable to update repositorylist.");
		return 1;
	}
	return 0;
}

struct cmd_func_block update_repositorylist_funcblock = {
	"update repositorylist", &usage, &help, NULL, NULL, &run, NULL
};
