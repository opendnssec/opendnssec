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
#include "keystate/keystate_list_task.h"
#include "shared/file.h"
#include "shared/str.h"

#include "keystate/keystate_list_cmd.h"


static const char *module_str = "keystate_list_cmd";

static void
usage(int sockfd)
{
	ods_printf(sockfd,
		"key list               List the keys in the enforcer database.\n"
		"      [--verbose]                (aka -v)  also show additional key parameters.\n"
		"      [--debug]                  (aka -d)  print information about the keystate.\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_list_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const int NARGV = 8;
    const char *argv[NARGV];
    int argc;

    ods_log_debug("[%s] %s command", module_str, key_list_funcblock()->cmdname);
    
    // Use buf as an intermediate buffer for the command.
    strncpy(buf, cmd, sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    
    // separate the arguments
    argc = ods_str_explode(buf, NARGV, argv);
    if (argc > NARGV) {
        ods_log_warning("[%s] too many arguments for %s command",
                        module_str,key_list_funcblock()->cmdname);
        ods_printf(sockfd,"too many arguments\n");
        return -1;
    }
    
    bool bVerbose = ods_find_arg(&argc,argv,"verbose","v") != -1;
    bool bDebug = ods_find_arg(&argc,argv,"debug","d") != -1;
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str,key_list_funcblock()->cmdname);
        ods_printf(sockfd,"unknown arguments\n");
        return -1;
    }
    return perform_keystate_list(sockfd, engine->config, bVerbose, bDebug);
}

static struct cmd_func_block funcblock = {
	"key list", &usage, NULL, &handles, &run
};

struct cmd_func_block*
key_list_funcblock(void)
{
	return &funcblock;
}
