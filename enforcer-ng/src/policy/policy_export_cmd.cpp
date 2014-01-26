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

#include "policy/policy_export_cmd.h"
#include "policy/policy_export_task.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "policy_export_cmd";

void help_policy_export_cmd(int sockfd)
{
    ods_printf(sockfd,
			   "policy export   export policies in the kasp.xml format\n"
			   "                --policy <policy_name> | --all (aka -p | -a)  \n");
}

int handled_policy_export_cmd(int sockfd, engine_type* engine, const char *cmd,
                                ssize_t n)
{

		char buf[ODS_SE_MAXLINE];
	    const char *argv[8];
	    const int NARGV = sizeof(argv)/sizeof(char*);
	    int argc;
	    const char *scmd = "policy export";

	    cmd = ods_check_command(cmd,n,scmd);
	    if (!cmd)
	        return 0; // not handled

	    ods_log_debug("[%s] %s command", module_str, scmd);
	
		//time_t tstart = time(NULL);

	    // Use buf as an intermediate buffer for the command.
	    strncpy(buf,cmd,sizeof(buf));
	    buf[sizeof(buf)-1] = '\0';

	    // separate the arguments
	    argc = ods_str_explode(buf,NARGV,argv);
	    if (argc > NARGV) {
	        ods_log_warning("[%s] too many arguments for %s command",
	                        module_str,scmd);
	        ods_printf(sockfd,"too many arguments\n");
	        return 1; // errors, but handled
	    }

	    const char *policy = NULL;
	    int export_all=0;
	    ods_find_arg_and_param(&argc,argv,"policy","p",&policy);
	    if (ods_find_arg(&argc, argv, "all", "a") >= 0) export_all = 1;
	
	    if (!policy && export_all == 0) {
	        ods_log_warning("[%s] expected option --policy <zone> | --all  for %s command",
	                        module_str,scmd);
	        ods_printf(sockfd,"expected --policy <policy> | --all  option\n");
	        return 1; // errors, but handled
	    }

	    if (argc) {
	        ods_log_warning("[%s] unknown arguments for %s command",
	                        module_str,scmd);
	        ods_printf(sockfd,"unknown arguments\n");
	        return 1; // errors, but handled
	    }

	    perform_policy_export_to_fd(sockfd,engine->config,policy);
	
		//ods_printf(sockfd, "%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
	    return 1;

}

