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

#include <ctime>
#include <iostream>
#include <cassert>

#include "keystate/zone_del_cmd.h"
#include "keystate/zone_del_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "zone_del_cmd";

void help_zone_del_cmd(int sockfd)
{
    ods_printf(sockfd,
			   "zone delete            Delete zones from the enforcer database.\n"
			   "      --zone <zone> | --all      (aka -z | -a)  zone, or delete all zones.\n"
               "      [--xml]                    (aka -u)       update zonelist.xml.\n"
			   );
	
}

bool get_arguments(int sockfd, const char *cmd,
				   std::string &out_zone,
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
        return false;
    }
    
    const char *zone = NULL;
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
    int del_all = 0;
    if (ods_find_arg(&argc, argv, "all", "a") != -1) del_all = 1;
    if (ods_find_arg(&argc, argv, "xml", "u") >= 0) need_write_xml = 1;
	
    if (argc) {
		ods_log_error_and_printf(sockfd,module_str,"unknown arguments");
        return false;
    }
	if (zone && del_all) {
	    ods_log_error_and_printf(sockfd,module_str,
							 "expected either --zone <zone> or --all, found both ");
        return false;		
	}
    if (!zone) {
        if (!del_all) {
		    ods_log_error_and_printf(sockfd,module_str,
								 "expected option --zone <zone> or --all ");
            return false;
        }
    }
    else
	    out_zone = zone;

	return true;
}

int handled_zone_del_cmd(int sockfd, engine_type* engine, const char *cmd, 
						  ssize_t n)
{
    const char *scmd =  "zone delete";
    
    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled
    
    ods_log_debug("[%s] %s command", module_str, scmd);

	std::string zone;
    int need_write_xml = 0;
	if (!get_arguments(sockfd,cmd,zone, need_write_xml)) {
		help_zone_del_cmd(sockfd);
		return 1;
	}

    time_t tstart = time(NULL);

    perform_zone_del(sockfd,engine->config, zone.c_str(), need_write_xml, false);

    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    return 1;
}
