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

#include "keystate/keystate_ds_retract_cmd.h"
#include "keystate/keystate_ds_retract_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "keystate_ds_retract_cmd";

void
help_keystate_ds_retract_cmd(int sockfd)
{
    ods_printf(sockfd,
        "key ds-retract  list KSK keys that should be retracted from the parent.\n"
        "  --zone <zone> (aka -z) force retract of KSK key for zone <zone>.\n"
        "  --cka_id <cka_id>\n"
        "                (aka -k) force retract of KSK key with cka_id <cka_id>.\n"
        "  --auto        (aka -a) perform retract for all keys that have "
                        "the retract flag set.\n"
        );
}

int
handled_keystate_ds_retract_cmd(int sockfd, engine_type* engine,
								const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
    task_type *task;
    ods_status status;
    const char *scmd = "key ds-retract";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled
    
    ods_log_debug("[%s] %s command", module_str, scmd);
    
    // Use buf as an intermediate buffer for the command.
    strncpy(buf,cmd,sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    
    // separate the arguments
    argc = ods_str_explode(&buf[0], NARGV, &argv[0]);
    if (argc > NARGV) {
        ods_log_warning("[%s] too many arguments for %s command",
                        module_str,scmd);
        ods_printf(sockfd,"too many arguments\n");
        return 1; // errors, but handled
    }
    
    const char *zone = NULL;
    const char *cka_id = NULL;
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
    (void)ods_find_arg_and_param(&argc,argv,"cka_id","k",&cka_id);
    bool bAutomatic = ods_find_arg(&argc,argv,"auto","a") != -1;
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str,scmd);
        ods_printf(sockfd,"unknown arguments\n");
        return 1; // errors, but handled
    }
    
    /* perform task immediately */
    time_t tstart = time(NULL);
    perform_keystate_ds_retract(sockfd,engine->config,zone,cka_id,bAutomatic?1:0);
    if (!zone && !cka_id) {
        ods_printf(sockfd,"%s completed in %ld seconds.\n",
				   scmd,time(NULL)-tstart);
    }

    return 1;
}
