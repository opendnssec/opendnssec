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

#include "keystate/zone_add_cmd.h"
#include "keystate/zone_add_task.h"
#include "enforcer/enforce_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "shared/log.h"
#include "daemon/engine.h"

static const char *module_str = "zone_add_cmd";

void
help_zone_add_cmd(int sockfd)
{
    ods_printf(sockfd,
			   "zone add        add a new zone to the enforcer\n"
			   "  --zone <zone>	(aka -z) name of the zone\n"
			   "  --policy <policy>\n"
			   "                (aka -p) name of the policy\n"
			   "  --signconf <path>\n"
			   "                (aka -s) signer configuration file\n"
			   "  --infile <path>\n"
			   "                (aka -if) file input adapter file\n"
			   "  --outfile <path>\n"
			   "                (aka -of) file  output adapter file\n"
			   "  --intype <type>\n"
			   "                (aka -it) input adapter type\n"
			   "  --outtype <type>\n"
			   "                (aka -ot) output adapter type\n"
			   "  --inconf <path>\n"
			   "                (aka -ic) input adapter config file\n"
			   "  --outconf <path>\n"
			   "                (aka -oc) output adapter config file\n"

        );
}

bool get_arguments(int sockfd, const char *cmd,
				   std::string &out_zone,
				   std::string &out_policy,
				   std::string &out_signconf,
				   std::string &out_infile,
				   std::string &out_outfile,
				   std::string &out_intype,
				   std::string &out_outtype,
				   std::string &out_inconf,
				   std::string &out_outconf)
{
	char buf[ODS_SE_MAXLINE];
    const char *argv[16];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
    
    // Use buf as an intermediate buffer for the command.
    strncpy(buf,cmd,sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    
    // separate the arguments
    argc = ods_str_explode(buf,NARGV,argv);
    if (argc > NARGV) {
        ods_log_error_and_printf(sockfd,module_str,"too many arguments");
        return false;
    }
    
    const char *zone = NULL;
    const char *policy = NULL;
	const char *signconf = NULL;
	const char *infile = NULL;
	const char *outfile = NULL;
	const char *intype = NULL;
	const char *outtype = NULL;
	const char *inconf = NULL;
	const char *outconf = NULL;
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
    (void)ods_find_arg_and_param(&argc,argv,"policy","p",&policy);
    (void)ods_find_arg_and_param(&argc,argv,"signconf","s",&signconf);
    (void)ods_find_arg_and_param(&argc,argv,"infile","if",&infile);
    (void)ods_find_arg_and_param(&argc,argv,"outfile","of",&outfile);
    (void)ods_find_arg_and_param(&argc,argv,"intype","it",&intype);
    (void)ods_find_arg_and_param(&argc,argv,"outtype","ot",&outtype);
    (void)ods_find_arg_and_param(&argc,argv,"inconf","ic",&inconf);
    (void)ods_find_arg_and_param(&argc,argv,"outconf","oc",&outconf);

    if (argc) {
		ods_log_error_and_printf(sockfd,module_str,"unknown arguments");
        return false;
    }
    if (!zone) {
		ods_log_error_and_printf(sockfd,module_str,
								 "expected option --zone <zone>");
        return false;
    }
	out_zone = zone;
    if (!policy) {
		ods_log_error_and_printf(sockfd,module_str,
								 "expected option --policy <policy>");
        return false;
    }
	out_policy = policy;
    if (!signconf) {
		ods_log_error_and_printf(sockfd,module_str,
								 "expected option --signconf <path>");
        return false;
    }
	out_signconf = signconf;
	if (!infile && !intype) {
		ods_log_error_and_printf(sockfd,module_str,
								 "expected option --infile or --intype");
        return false;
	}
	if (infile)
		out_infile = infile;
	if (intype)
		out_intype = intype;
	if (!outfile && !outtype) {
		ods_log_error_and_printf(sockfd,module_str,
								 "expected option --outfile or --outtype");
        return false;
	}
	if (outfile)
		out_outfile = outfile;
	if (outtype)
		out_outtype = outtype;
	if (intype && !inconf) {
		ods_log_error_and_printf(sockfd,module_str,
								 "expected option --inconf");
        return false;
	}
	if (inconf)
		out_inconf = inconf;
	if (outtype && !outconf) {
		ods_log_error_and_printf(sockfd,module_str,
								 "expected option --outconf");
        return false;
	}
	if (outconf)
		out_outconf = outconf;
	return true;
}

int
handled_zone_add_cmd(int sockfd, engine_type* engine, const char *cmd,
					 ssize_t n)
{
    const char *scmd = "zone add";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

	std::string zone,policy,signconf,infile,outfile,intype,outtype,inconf,outconf;
	if (!get_arguments(sockfd,cmd,zone,policy,signconf,infile,outfile,
					   intype,outtype,inconf,outconf)
		)
		return 1;
	
    time_t tstart = time(NULL);
	
    perform_zone_add(sockfd,engine->config,
					 zone.c_str(),
					 policy.c_str(),
					 signconf.c_str(),
					 infile.c_str(),
					 outfile.c_str(),
					 intype.c_str(),
					 outtype.c_str(),
					 inconf.c_str(),
					 outconf.c_str()
					 );
	
    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);

    flush_enforce_task(engine);
    return 1;
}
