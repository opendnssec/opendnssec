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

#include "shared/file.h"
#include "shared/str.h"
#include "daemon/cmdhandler.h"
#include "daemon/engine.h"

#include "daemon/verbosity_cmd.h"

static const char *module_str = "verbosity_cmd";

static void
usage(int sockfd)
{
	ods_printf(sockfd,
		"verbosity <nr>         Set verbosity.\n"
	);
}

static void
help(int sockfd)
{
	ods_printf(sockfd, ""

	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, verbosity_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
	(void)n;
	ods_log_debug("[%s] verbosity command", module_str);
	if (cmd[9] == '\0') {
		char buf[ODS_SE_MAXLINE];
		(void)snprintf(buf, ODS_SE_MAXLINE, "Error: verbosity command missing "
											"an argument (verbosity level).\n");
		ods_writen(sockfd, buf, strlen(buf));
		return -1;
	} else if (cmd[9] != ' ') {
		return 1; /* no match */
	} else {
		int val = atoi(&cmd[10]);
		char buf[ODS_SE_MAXLINE];
		ods_log_assert(engine);
		ods_log_assert(engine->config);
		ods_log_init(engine->config->log_filename,
					 engine->config->use_syslog, val);
		(void)snprintf(buf, ODS_SE_MAXLINE, "Verbosity level set to %i.\n", val);
		ods_writen(sockfd, buf, strlen(buf));
		return 0;
	}
}


static struct cmd_func_block funcblock = {
	"verbosity", &usage, &help, &handles, &run
};

struct cmd_func_block*
verbosity_funcblock(void)
{
	return &funcblock;
}
