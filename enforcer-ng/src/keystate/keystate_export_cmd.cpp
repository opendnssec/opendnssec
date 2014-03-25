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
#include "keystate/keystate_export_task.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/clientpipe.h"

#include "keystate/keystate_export_cmd.h"

static const char *module_str = "keystate_export_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key export             Export DNSKEY(s) for a given zone.\n"
		"      --zone <zone>              (aka -z)  zone.\n"
		"      [--ds]                     (aka -d)  export DS in BIND format.\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_export_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const int NARGV = 8;
    const char *argv[NARGV];
    int argc;
    
    ods_log_debug("[%s] %s command", module_str, key_export_funcblock()->cmdname);
    
    // Use buf as an intermediate buffer for the command.
    strncpy(buf, cmd, sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    
    // separate the arguments
    argc = ods_str_explode(buf, NARGV, argv);
    if (argc > NARGV) {
        ods_log_warning("[%s] too many arguments for %s command",
                        module_str, key_export_funcblock()->cmdname);
        client_printf(sockfd,"too many arguments\n");
        return -1;
    }
    
    const char *zone = NULL;
	bool bds = 0;
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
	if (ods_find_arg(&argc,argv,"ds","d") >= 0) bds = 1;
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str, key_export_funcblock()->cmdname);
        client_printf(sockfd,"unknown arguments\n");
        return -1;
    }
    if (!zone) {
        ods_log_warning("[%s] expected option --zone <zone> for %s command",
                        module_str, key_export_funcblock()->cmdname);
        client_printf(sockfd,"expected --zone <zone> option\n");
        return -1;
    }
    /* perform task immediately */
    return perform_keystate_export(sockfd,engine->config,zone,bds?1:0);
}

static struct cmd_func_block funcblock = {
	"key export", &usage, NULL, &handles, &run
};

struct cmd_func_block*
key_export_funcblock(void)
{
	return &funcblock;
}
