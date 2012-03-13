/*
 * $Id$
 *
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

#include <ctime>
#include <iostream>
#include <cassert>

#include "hsmkey/hsmkey_gen_cmd.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "hsmkey_gen_cmd";

/**
 * Print help for the 'hsmkey_gen' command
 *
 */
void help_hsmkey_gen_cmd(int sockfd)
{
    ods_printf(sockfd,
        "hsm key gen     pre-generate a collection of hsm keys\n"
        "                before they are actually needed by the enforcer.\n"
		"  --duration <duration>\n"
		"                (aka -d) generate enough keys for the currently\n"
		"                present zones to last for the duration specified.\n"
		"                examples:\n"
		"                  -d P2Y         2 years\n"
		"                  -d P3YT1H6M    3 years, 1 hour and 6 minutes\n"
        );
}

static bool
get_period(int sockfd,
		   engineconfig_type *config,
		   const char *scmd,
		   const char *cmd,
		   time_t &period)
{
	char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);    
    int argc;
	
	// Use buf as an intermediate buffer for the command.
    strncpy(buf,cmd,sizeof(buf));
    buf[sizeof(buf)-1] = '\0';

    // separate the arguments
    argc = ods_str_explode(&buf[0], NARGV, &argv[0]);
    if (argc > NARGV) {
		ods_log_error_and_printf(sockfd, module_str,
								 "too many arguments for %s command",
								 scmd);
        return false; // errors, but handled
    }
    
    const char *str = NULL;
    (void)ods_find_arg_and_param(&argc,argv,"duration","d",&str);
	
	// fail on unhandled arguments;
    if (argc) {
		ods_log_error_and_printf(sockfd, module_str,
								 "unknown arguments for %s command",
								 scmd);
        return false; // errors, but handled
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
			return false; // errors, but handled
		}
		period = duration2time(duration);
		duration_cleanup(duration);
		if (!period) {
			ods_log_error_and_printf(sockfd, module_str,
									 "invalid period in duration argument %s",
									 str);
			return false; // errors, but handled
		}
	}
		
	return true;
}



int handled_hsmkey_gen_cmd(int sockfd, engine_type* engine, const char *cmd,
						   ssize_t n)
{
    const char *scmd = "hsm key gen";
    
    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

	time_t period;
	if (!get_period(sockfd,engine->config, scmd, cmd, period))
		return 1; // errors, but handled

    time_t tstart = time(NULL);

    perform_hsmkey_gen(sockfd,engine->config,1,period);
    
	ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    return 1;
}
