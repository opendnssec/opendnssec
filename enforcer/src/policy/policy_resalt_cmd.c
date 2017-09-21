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

#include "getopt.h"

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "policy/policy_resalt_task.h"
#include "duration.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "daemon/engine.h"
#include "clientpipe.h"

#include "policy/policy_resalt_cmd.h"

static void
usage(int sockfd)
{
    client_printf(sockfd,
        "policy resalt\n"
        "	[--policy <POLICY>]			aka -p\n"
        "	[--all]					aka -a\n"
    );
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Generate random new NSEC3 salts. The use without arguments is"
        " depricated since it never effectively did anything other than"
        " rescheduling the resalt tasks.\n"
        "\nOptions:\n"
        "policy		Immediatly resalt this policy.\n"
        "all		Immedeatly resalt all policies.\n\n"
    );
}

static int
parse_args(int sockfd, char *cmd, char **policy, int *all)
{
    #define NARGV 12
    char * argv[NARGV];

    static struct option lopts[] = {
        {"policy", required_argument, 0, 'p'},
        {"all", no_argument, 0, 'a'},
        {0, 0, 0, 0}
    };

    *all = 0;
    *policy = NULL;

    int argc = ods_str_explode(cmd, NARGV, (const char **)argv);
    if (argc == -1) {
        ods_log_error("[resalt] too many arguments for %s command",
            resalt_funcblock.cmdname);
        client_printf_err(sockfd, "too many arguments\n");
        return 1;
    }

    optind = 0;
    while (1) {
        int lidx = 0;
        switch (getopt_long(argc, argv, "p:a", lopts, &lidx)) {
            case -1: return 0; /* Done */
            case 'p':
                *policy = optarg;
                break;
            case 'a':
                *all = 1;
                break;
            default:
                client_printf_err(sockfd, "unknown arguments\n");
                ods_log_error("[resalt] unknown arguments for %s command",
                    resalt_funcblock.cmdname);
                return 1;
        }
    }
}

static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
    db_connection_t* dbconn = getconnectioncontext(context);;
    engine_type* engine = getglobalcontext(context);
    char *policy;
    int all;
    if (parse_args(sockfd, cmd, &policy, &all)) {
        client_printf_err(sockfd, "Error parsing arguments.\n");
        return 1;
    }
    if (all && policy) {
        client_printf_err(sockfd, "--all and --policy are mutually exclusive.\n");
        return 1;
    }
    if (!all && !policy) { /* Old behavior, deprecated */
        return resalt_task_schedule(engine, dbconn);
    }
    return resalt_task_flush(engine, dbconn, policy);
}

struct cmd_func_block resalt_funcblock = {
	"policy resalt", &usage, &help, NULL, &run
};
