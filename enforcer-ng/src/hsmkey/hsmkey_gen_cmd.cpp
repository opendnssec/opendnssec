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

#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "daemon/clientpipe.h"

#include "hsmkey/hsmkey_gen_cmd.h"


static const char *module_str = "keystate_generate";

/**
 * Print help for the 'hsmkey_gen' command
 *
 */
static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key generate           Pre-generate keys.\n"
		"      --duration <duration>      (aka -d)  duration to generate keys for.\n"
	);
}

static int
get_period(int sockfd,
		   engineconfig_type *config,
		   const char *scmd,
		   const char *cmd,
		   time_t &period)
{
	char buf[ODS_SE_MAXLINE];
    const int NARGV = 8;
    const char *argv[NARGV];
    int argc;
	
	// Use buf as an intermediate buffer for the command.
    strncpy(buf, cmd, sizeof(buf));
    buf[sizeof(buf)-1] = '\0';

    // separate the arguments
    argc = ods_str_explode(&buf[0], NARGV, &argv[0]);
    if (argc > NARGV) {
		ods_log_error_and_printf(sockfd, module_str,
								 "too many arguments for %s command",
								 scmd);
        return -1;
    }
    
    const char *str = NULL;
    (void)ods_find_arg_and_param(&argc, argv, "duration","d", &str);
	
	// fail on unhandled arguments;
    if (argc) {
		ods_log_error_and_printf(sockfd, module_str,
								 "unknown arguments for %s command",
								 scmd);
        return -1;
    }

	// Use the automatic keygen period when no period is specified 
	// on the commandline. This defaults to a year.
	period = config->automatic_keygen_duration;
	
	// Analyze the argument and fail on error.
	if (str) {
		duration_type *duration = duration_create_from_string(str);
		if (!duration) {
			ods_log_error_and_printf(sockfd, module_str,
									 "invalid duration argument %s",
									 str);									
			return 1;
		}
		period = duration2time(duration);
		duration_cleanup(duration);
		if (!period) {
			ods_log_error_and_printf(sockfd, module_str,
									 "invalid period in duration argument %s",
									 str);
			return 1;
		}
	}
		
	return 0;
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_gen_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	int error;
	ods_log_debug("[%s] %s command", module_str, key_gen_funcblock()->cmdname);
	
	cmd = ods_check_command(cmd, n, key_gen_funcblock()->cmdname);
	
	time_t period;
	error = get_period(sockfd,engine->config, 
		key_gen_funcblock()->cmdname, cmd, period);
	if (error != 0)
		return error;
	return perform_hsmkey_gen(sockfd,engine->config,1,period);
}

static struct cmd_func_block funcblock = {
	"key generate", &usage, NULL, &handles, &run
};

struct cmd_func_block*
key_gen_funcblock(void)
{
	return &funcblock;
}
