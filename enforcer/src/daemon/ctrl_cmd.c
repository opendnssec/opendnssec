/*
 * Copyright (c) 2014 NLNet Labs
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
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

#include "file.h"
#include "log.h"
#include "str.h"
#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "clientpipe.h"

#include "daemon/ctrl_cmd.h"

/* static const char *module_str = "ctrl_cmd"; */

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"running                Returns acknowledgment that the engine is running.\n"
		"reload                 Reload the engine.\n"
		"stop                   Stop the engine and terminate the process.\n"
		/*"start                  Start the engine.\n"*/
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	if (ods_check_command(cmd, n, "stop")) return 1;
	if (ods_check_command(cmd, n, "reload")) return 1;
	if (ods_check_command(cmd, n, "running")) return 1;
	if (ods_check_command(cmd, n, "start")) return 1;
	return 0;
}


static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	(void) dbconn;
	if (ods_check_command(cmd, n, "start")) {
		ods_log_debug("[cmdhandler] start command");
		client_printf(sockfd, "Engine already running.\n");
		/* if you asked us to start, we are already started */
		return 1; /* error */
	} else if (ods_check_command(cmd, n, "running")) {
		ods_log_debug("[cmdhandler] running command");
		client_printf(sockfd, "Engine running.\n");
		return 0;
	} else if (ods_check_command(cmd, n, "reload")) {
		ods_log_debug("[cmdhandler] reload command");
		ods_log_assert(engine);
		engine->need_to_reload = 1;
		pthread_mutex_lock(&engine->signal_lock);
			pthread_cond_signal(&engine->signal_cond);
		pthread_mutex_unlock(&engine->signal_lock);
		client_printf(sockfd, "Reloading engine.\n");
		return 0;
	} else if (ods_check_command(cmd, n, "stop")) {
		ods_log_debug("[cmdhandler] stop command");
		ods_log_assert(engine);
		engine->need_to_exit = 1;
		pthread_mutex_lock(&engine->signal_lock);
			pthread_cond_signal(&engine->signal_cond);
		pthread_mutex_unlock(&engine->signal_lock);
		client_printf(sockfd, "%s\n", ODS_SE_STOP_RESPONSE);
		return 0;
	} else {
		return -1;
	}
}

static struct cmd_func_block funcblock = {
	"ctrl", &usage, NULL, &handles, &run
};

struct cmd_func_block*
ctrl_funcblock(void)
{
	return &funcblock;
}
