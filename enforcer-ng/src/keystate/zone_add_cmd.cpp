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
#include <cstring>
#include <iostream>
#include <cassert>

#include "keystate/zone_add_cmd.h"
#include "keystate/zone_add_task.h"
#include "enforcer/enforce_task.h"
#include "hsmkey/hsmkey_gen_task.h"
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
			   "                --zone <zone>         (aka -z)    name of the zone\n"
			   "                [--policy <policy>]   (aka -p)    name of the policy\n"
			   "                [--signerconf <path>] (aka -s)    signer configuration file\n"
			   "                [--input <path>]      (aka -i)    input adapter zone file or config file\n"
			   "                [--output <path>]     (aka -o)    output adapter zone file or config file\n"
			   "                [--in-type <type>]    (aka -j)    input adapter type ('File' or 'DNS')\n"
			   "                [--out-type <type>]   (aka -q)    output adapter type ('File' or 'DNS')\n"
               "                [--xml]               (aka -u)    update the zonelist.xml file\n"
        );
}

static inline void
get_full_path(const std::string &input_file,
                    const std::string &relative_dir,
                    std::string &full_file_path)
{
    if (input_file[0] == '/')
        full_file_path = input_file;
    else {
        full_file_path = relative_dir +
                        std::string("/") +
                        input_file;
    }
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
				   std::string &out_outconf,
                   int &need_write_xml)
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
		help_zone_add_cmd(sockfd);	
        return false;
    }
    
    const char *zone = NULL;
    const char *policy = NULL;
	const char *signconf = NULL;
	const char *input = NULL;
	const char *output = NULL;
	const char *intype = NULL;
	const char *outtype = NULL;
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
    (void)ods_find_arg_and_param(&argc,argv,"policy","p",&policy);
    (void)ods_find_arg_and_param(&argc,argv,"signerconf","s",&signconf);
    (void)ods_find_arg_and_param(&argc,argv,"input","i",&input);
    (void)ods_find_arg_and_param(&argc,argv,"output","o",&output);
    (void)ods_find_arg_and_param(&argc,argv,"in-type","j",&intype);
    (void)ods_find_arg_and_param(&argc,argv,"out-type","q",&outtype);
    if (ods_find_arg(&argc, argv, "xml", "u") >= 0) need_write_xml = 1;

    if (argc) {
		ods_log_error_and_printf(sockfd,module_str,"unknown arguments");
		help_zone_add_cmd(sockfd);	
        return false;
    }
    if (!zone) {
		ods_log_error_and_printf(sockfd,module_str,
								 "expected option --zone <zone>");
		help_zone_add_cmd(sockfd);						
								
        return false;
    }
	out_zone = zone;
	
    if (!policy) {
		out_policy = "default";
    } else {
		out_policy = policy;
	}
	
    if (!signconf) {
        bool is_dot_ending = false;
        if (zone[strlen(zone) - 1] == '.') is_dot_ending = true;
        out_signconf = out_zone + 
                        (is_dot_ending ? std::string("xml") 
                                        : std::string(".xml"));
    }
    else {
	    out_signconf = signconf;
	}
    get_full_path(out_signconf, OPENDNSSEC_STATE_DIR + std::string("/signconf"), out_signconf);

	//TODO: I think this can be simplified to remove the out_in/outconf variables.
    if (!intype || (0 == strcasecmp(intype, "file"))) {
        if (input)
            out_infile = input; 
        else
            out_infile = out_zone;
        get_full_path(out_infile, OPENDNSSEC_STATE_DIR + std::string("/unsigned"),
                out_infile);
    } else if (0 == strcasecmp(intype, "dns")) {
		out_intype = "DNS";
        if (input)
		    out_inconf = input;
        else
            out_inconf = "addns.xml";
        get_full_path(out_inconf, std::string(OPENDNSSEC_CONFIG_DIR), out_inconf);
    } else {
		ods_log_error_and_printf(sockfd, module_str,
								 "invalid parameter for --in-type");
		help_zone_add_cmd(sockfd);	
        return false;
    }

    if (!outtype || (0 == strcasecmp(outtype, "file"))) {
        if (output)
            out_outfile = output; 
        else
            out_outfile = out_zone;
        get_full_path(out_outfile, OPENDNSSEC_STATE_DIR + std::string("/signed"),
                out_outfile);
    } else if (0 == strcasecmp(outtype, "dns")) {
        if (output)
		    out_outconf = output;
        else
            out_outconf = "addns.xml";
		out_outtype = outtype;
        get_full_path(out_outconf, std::string(OPENDNSSEC_CONFIG_DIR), out_outconf);
    } else {
		ods_log_error_and_printf(sockfd, module_str,
								 "invalid parameter for --out-type");
		help_zone_add_cmd(sockfd);	
        return false;
    }

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
    int need_write_xml = 0;
	if (!get_arguments(sockfd,cmd,zone,policy,signconf,infile,outfile,
					   intype,outtype,inconf,outconf, need_write_xml)
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
					 inconf.c_str(),
					 outtype.c_str(),
					 outconf.c_str(),
					 need_write_xml);
					
	perform_hsmkey_gen(sockfd, engine->config, 0 /* automatic */,
					   engine->config->automatic_keygen_duration);					
	
    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);

    flush_enforce_task(engine);
    return 1;
}
