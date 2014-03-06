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

#include "daemon/help_cmd.h"

static const char *module_str = "help_cmd";

static void
usage(int sockfd)
{
	ods_printf(sockfd,
		"help                   Show overview of available commands.\n"
		"     [command]         Show help for command.\n"
	);
}

static void
help(int sockfd)
{
	ods_printf(sockfd,
		"Without arguments print an overview of available commands" 
		" for the daemon and a short description of usage. "
		"With [command] set, print usage information of command"
		" and extended help if available.\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, help_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
	struct cmd_func_block* fb;
	char buf[ODS_SE_MAXLINE];
	(void) engine;

	ods_log_debug("[%s] help command", module_str);
	
	if (n < 4) return -1;
	if (strncmp(cmd, help_funcblock()->cmdname, 4) != 0) return -1;
	if (n < 6) {
		/* Anouncement */
		(void) snprintf(buf, ODS_SE_MAXLINE, "\nCommands:\n");
		ods_writen(sockfd, buf, strlen(buf));

		cmdhandler_get_usage(sockfd);

		/* Generic commands */
		(void) snprintf(buf, ODS_SE_MAXLINE,
				   "queue                  Show the current task queue.\n"
		#ifdef ENFORCER_TIMESHIFT
				   "time leap              Simulate progression of time by leaping to the time of\n"
				   "                       the earliest scheduled task.\n"
		#endif
				   "flush                  Execute all scheduled tasks immediately.\n"
			);
		ods_writen(sockfd, buf, strlen(buf));
		(void) snprintf(buf, ODS_SE_MAXLINE,
			"running                Returns acknowledgment that the engine is running.\n"
			"reload                 Reload the engine.\n"
			"stop                   Stop the engine and terminate the process.\n"
			"verbosity <nr>         Set verbosity.\n"
			);
		ods_writen(sockfd, buf, strlen(buf));
	} else {
		cmd += 5;
		n -= 5;
		if ((fb = get_funcblock(cmd, n))) {
			ods_printf(sockfd, "Usage:\n");
			fb->usage(sockfd);
			ods_printf(sockfd, "\nHelp:\n");
			if (fb->help) {
				fb->help(sockfd);
			} else {
				ods_printf(sockfd, "No help available for %s\n", cmd);
				return 1;
			}
		} else {
			ods_printf(sockfd, "Command %s unknown\n", cmd);
			return 2;
		}
	}
	return 0;
}

static struct cmd_func_block funcblock = {
	"help", &usage, &help, &handles, &run
};

struct cmd_func_block*
help_funcblock(void)
{
	return &funcblock;
}
