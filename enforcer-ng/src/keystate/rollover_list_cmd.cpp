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

#include "daemon/engine.h"
#include "daemon/cmdhandler.h"
#include "keystate/rollover_list_task.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/clientpipe.h"

#include "keystate/rollover_list_cmd.h"

static const char *module_str = "rollover_list_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd, 
		"rollover list          List upcoming rollovers.\n"
		"     [--zone <zone>]              (aka -z)  zone.\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, rollover_list_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
	char buf[ODS_SE_MAXLINE];
	const int NARGV = 8;
	const char *argv[NARGV];
	int argc;
	const char *zone = NULL;
	
	ods_log_debug("[%s] %s command", module_str, rollover_list_funcblock()->cmdname);
	cmd = ods_check_command(cmd, n, rollover_list_funcblock()->cmdname);
	
	// Use buf as an intermediate buffer for the command.
	strncpy(buf, cmd,sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	
	// separate the arguments
	argc = ods_str_explode(buf, NARGV, argv);
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
						module_str, rollover_list_funcblock()->cmdname);
		client_printf(sockfd,"too many arguments\n");
		return -1;
	}
	
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
	if (argc) {
		ods_log_warning("[%s] unknown arguments for %s command",
						module_str, rollover_list_funcblock()->cmdname);
		client_printf(sockfd,"unknown arguments\n");
		return -1;
	}
	return perform_rollover_list(sockfd, engine->config, zone);
}

static struct cmd_func_block funcblock = {
	"rollover list", &usage, NULL, &handles, &run
};

struct cmd_func_block*
rollover_list_funcblock(void)
{
	return &funcblock;
}
