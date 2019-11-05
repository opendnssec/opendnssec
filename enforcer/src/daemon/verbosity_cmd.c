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

#include <limits.h>

#include "file.h"
#include "log.h"
#include "str.h"
#include "cmdhandler.h"
#include "daemon/engine.h"
#include "clientpipe.h"

#include "daemon/verbosity_cmd.h"

#define MAX_ARGS 2

static const char *module_str = "verbosity_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"verbosity <nr>\n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd, "Set verbosity.\n\n"
	);
}

static int
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
	const int NARGV = MAX_ARGS;
	const char *argv[MAX_ARGS];
	char buf[ODS_SE_MAXLINE];
	int argc;
	long val;
	char *endptr, *errorstr;

	strncpy(buf, cmd, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	argc = ods_str_explode(buf, NARGV, argv);

	ods_log_debug("[%s] verbosity command", module_str);
	if (argc == 1) {
		client_printf(sockfd, "Current verbosity is set to %d.\n", 
			ods_log_verbosity());
		client_printf(sockfd,
			"Available modes:\n"
			"  0 - Critical\n"
			"  1 - Error\n"
			"  2 - Warning\n"
			"  3 - Notice\n"
			"  4 - Info\n"
			"  5 - Debug\n"
		);
		return 0;
	} else if (argc == 2) {
		errno = 0;
		val = strtol(argv[1], &endptr, 10);
		if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
			|| (errno != 0 && val == 0)) {
			errorstr = strerror(errno);
			client_printf(sockfd, "Error parsing verbosity value: %s.\n", errorstr);
			return -1;
		}
		if (endptr == argv[1]) {
			client_printf(sockfd, "Error parsing verbosity value: No digits were found.\n");
			return -1;
		}
		if ((int)val < 0) { /* also catches wrapped longs */
			client_printf(sockfd, "Error parsing verbosity value: must be >= 0.\n");
			return -1;
		}
		ods_log_setverbosity(val);
		client_printf(sockfd, "Verbosity level set to %li.\n", val);
		return 0;
	} else {
		client_printf(sockfd, "Too many arguments.\n");
		return -1;
	}
}


struct cmd_func_block verbosity_funcblock = {
	"verbosity", &usage, &help, NULL, &run
};
