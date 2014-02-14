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

#include "keystate/keystate_ds_seen_cmd.h"
#include "keystate/keystate_ds_seen_task.h"
#include "enforcer/enforce_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "keystate_ds_seen_cmd";

void help_keystate_ds_seen_cmd(int sockfd)
{
    ods_printf(sockfd,
               "key ds-seen            Issue a ds-seen to the enforcer for a KSK.\n"
			   "                       (This command with no parameters lists eligible keys.)\n"
               "      --zone <zone>              (aka -z)  zone.\n"
               "      --cka_id <CKA_ID>          (aka -k)  cka_id <CKA_ID> of the key.\n"
               "      --keytag <keytag>          (aka -x)  keytag <keytag> of the key.\n"
        );
}

int handled_keystate_ds_seen_cmd(int sockfd, engine_type* engine,
                                 const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
    const char *scmd = "key ds-seen";
    
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
        return 1; // errors, but handled
    }
    
    const char *zone = NULL;
    const char *cka_id = NULL;
    const char *keytag = NULL;
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
    (void)ods_find_arg_and_param(&argc,argv,"cka_id","k",&cka_id);
    (void)ods_find_arg_and_param(&argc,argv,"keytag","x",&keytag);
    
    // Check for unknown parameters on the command line
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str,scmd);
        ods_printf(sockfd,"unknown arguments\n");
		help_keystate_ds_seen_cmd(sockfd);
        return 1; // errors, but handled
    }
    
    // Check for too many parameters on the command line
    if (argc > NARGV) {
        ods_log_warning("[%s] too many arguments for %s command",
                        module_str,scmd);
		ods_printf(sockfd,"too many arguments\n");
		help_keystate_ds_seen_cmd(sockfd);		
        return 1; // errors, but handled
    }
    
    // Either no option or combi of zone & cka_id or zone & keytag needs to be 
    // present. But not both cka_id and keytag
    uint16_t nkeytag = 0;
    if (zone || cka_id || keytag) {
        if (!zone) {
            ods_log_warning("[%s] expected option --zone <zone> for %s command",
                            module_str,scmd);
			ods_printf(sockfd,"expected --zone <zone> option\n");
			help_keystate_ds_seen_cmd(sockfd);
            return 1; // errors, but handled
        }
        if (!cka_id && !keytag) {
            ods_log_warning("[%s] expected option --cka_id <cka_id> or "
                            "--keytag <keytag> for %s command",
                            module_str,scmd);
            ods_printf(sockfd,"expected --cka_id <cka_id> or "
                           "--keytag <keytag> option\n");
			help_keystate_ds_seen_cmd(sockfd);
            return 1; // errors, but handled
        } else {
            if (cka_id && keytag) {
                ods_log_warning("[%s] both --cka_id <cka_id> and --keytag <keytag> given, "
                                "please only specify one for %s command",
                                module_str,scmd);
                ods_printf(sockfd,
                               "both --cka_id <cka_id> and --keytag <keytag> given, "
                               "please only specify one\n");
				help_keystate_ds_seen_cmd(sockfd);
                return 1; // errors, but handled
            }
        }
        if (keytag) {
            int kt = atoi(keytag);
            if (kt<=0 || kt>=65536) {
                ods_log_warning("[%s] value \"%s\" for --keytag is invalid",
                                module_str,keytag);
                ods_printf(sockfd,
                               "value \"%s\" for --keytag is invalid\n",
                               keytag);
                return 1; // errors, but handled
            }
            nkeytag = (uint16_t )kt;
        }
    }

    time_t tstart = time(NULL);
	
    perform_keystate_ds_seen(sockfd,engine->config,zone,cka_id,nkeytag);

    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);

    flush_enforce_task(engine);
    return 1;
}
