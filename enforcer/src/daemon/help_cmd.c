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

#include "file.h"
#include "log.h"
#include "str.h"
#include "cmdhandler.h"
#include "daemon/engine.h"
#include "clientpipe.h"

#include "daemon/help_cmd.h"

static const char *module_str = "help_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"help\n"
		"	[command]\n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"Without arguments print an overview of available commands for the daemon\n"
		"and a short description of usage. With [command] set, print usage information\n"
		"of command and extended help if available.\n\n"
	);
}

static int
handles(const char *cmd)
{
	return ods_check_command(cmd, help_funcblock.cmdname)? 1 : 0;
}

static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
	struct cmd_func_block* fb;

	ods_log_debug("[%s] help command", module_str);
	
	if (strlen(cmd) < 6) {
		/* Anouncement */
		client_printf(sockfd, "\nCommands:\n");
		cmdhandler_get_usage(sockfd, context->cmdhandler);
	} else {
		if ((fb = get_funcblock(&cmd[5], context->cmdhandler))) {
			client_printf(sockfd, "Usage:\n");
			fb->usage(sockfd);
			client_printf(sockfd, "\nHelp:\n");
			if (fb->help) {
				fb->help(sockfd);
			} else {
				client_printf(sockfd, "No help available for '%s'\n",
					cmd+5);
				return 1;
			}
		} else {
			client_printf(sockfd, "Help: command '%s' unknown. Type "
				"'help' without arguments to get a list of supported "
				"commands.\n", cmd+5);
			return 2;
		}
	}
	return 0;
}

struct cmd_func_block help_funcblock = {
	"help", &usage, &help, &handles, &run
};
