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

#include "keystate/keystate_list_cmd.h"
#include "keystate/keystate_list_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "keystate_list_cmd";

void help_keystate_list_cmd(int sockfd)
{
    ods_printf(sockfd,
               "key list               List the keys in the enforcer database.\n"
               "      [--verbose]                (aka -v)  also show additional key parameters.\n"
               "      [--debug]                  (aka -d)  print information about the keystate.\n"
        );
}

int handled_keystate_list_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
    const char *scmd = "key list";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled
    
    ods_log_debug("[%s] %s command", module_str, scmd);
    
    // Use buf as an intermediate buffer for the command.
    strncpy(buf,cmd,sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    
    // separate the arguments
    argc = ods_str_explode(buf,NARGV,argv);
    if (argc > NARGV) {
        ods_log_warning("[%s] too many arguments for %s command",
                        module_str,scmd);
        ods_printf(sockfd,"too many arguments\n");
		help_keystate_list_cmd(sockfd);
        return 1; // errors, but handled
    }
    
    bool bVerbose = ods_find_arg(&argc,argv,"verbose","v") != -1;
    bool bDebug = ods_find_arg(&argc,argv,"debug","d") != -1;
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str,scmd);
        ods_printf(sockfd,"unknown arguments\n");
		help_keystate_list_cmd(sockfd);
        return 1; // errors, but handled
    }
    
    time_t tstart = time(NULL);

    perform_keystate_list(sockfd, engine->config, bVerbose, bDebug);
	
	ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    
    return 1;
}
