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

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "enforcer/enforce_task.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"

#include "enforcer/enforce_cmd.h"

static const char *module_str = "enforce_cmd";

#define MAX_ARGS 16

/**
 * Print help for the 'enforce' command
 *
 */
static void
usage(int sockfd)
{
	client_printf(sockfd,
		"enforce\n"
		"	--zone <zone>	aka -z\n");
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"Force enforce task to run for a zone."
		" Without arguments run enforce task for every zone.\n"
		"\nOptions:\n"
		"zone		Schedule enforce task for this zone for *now*\n"
		"\n"
	);
}

/**
 * Handle the 'enforce' command.
 *
 */
static int
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
	time_t t_next;
	task_type *task;
	char *buf;
	int argc;
	char const *argv[MAX_ARGS];
	char const *zone_name = NULL;
	int pos;
        db_connection_t* dbconn = getconnectioncontext(context);
        engine_type* engine = getglobalcontext(context);

	ods_log_debug("[%s] %s command", module_str, enforce_funcblock.cmdname);

	cmd = ods_check_command(cmd, enforce_funcblock.cmdname);
	if (!cmd) return -1;

	if (!(buf = strdup(cmd))) {
		client_printf_err(sockfd, "memory error\n");
		return -1;
	}
	argc = ods_str_explode(buf, MAX_ARGS, argv);

	pos = ods_find_arg_and_param(&argc, argv, "zone", "z", &zone_name);
	if (argc > 0) {
		client_printf_err(sockfd, "Too many arguments.\n");
		free(buf);
		return -1;
	}

	if (pos != -1) {
		enforce_task_flush_zone(engine, zone_name);
	} else {
		enforce_task_flush_all(engine, dbconn);
	}
	free(buf);
	return 0;
}

struct cmd_func_block enforce_funcblock = {
	"enforce", &usage, &help, NULL, &run
};
