/*
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
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
#include <getopt.h>

#include "daemon/engine.h"
#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "longgetopt.h"
#include "hsmkey/hsm_key_factory.h"
#include "db/policy.h"
#include "duration.h"

#include "hsmkey/key_generate_cmd.h"

static const char *module_str = "key_generate_cmd";

static void
usage(int sockfd)
{
    client_printf(sockfd,
        "key generate\n"
        "	--duration <duration>			aka -d\n"
        "	--policy <policy>			aka -p \n"
        "	--all					aka -a\n"
    );
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Pre-generate keys for all or a given policy, the duration to pre-generate for\n"
        "can be specified or otherwise its taken from the conf.xml.\n"
	"\nOptions:\n"
	"duration	duration to generate keys for\n"
	"policy|all	generate keys for a specified policy or for all of them \n\n");
}

static int
run(cmdhandler_ctx_type* context, int argc, char* argv[])
{
    int sockfd = context->sockfd;
    struct longgetopt optctx;
    int long_index =0, opt = 0;
    const char* policy_name = NULL;
    const char* duration_text = NULL;
    time_t duration_time = 0;
    duration_type* duration = NULL;
    int all = 0;
    policy_t* policy;
    db_connection_t* dbconn = getconnectioncontext(context);
    engine_type* engine = getglobalcontext(context);

    static struct option long_options[] = {
        {"policy", required_argument, 0, 'p'},
        {"all", no_argument, 0, 'a'},
        {"duration", required_argument, 0, 'd'},
        {0, 0, 0, 0}
    };

    ods_log_debug("[%s] key generate command", module_str);

    for(opt = longgetopt(argc, argv, "p:ad:", long_options, &long_index, &optctx); opt != -1;
        opt = longgetopt(argc, argv, NULL,    long_options, &long_index, &optctx)) {
        switch (opt) {
            case 'd':
                duration_text = optctx.optarg;
                break;
            case 'p':
                policy_name = optctx.optarg;
                break;
            case 'a':
                all = 1;
                break;
            default:
                client_printf_err(sockfd, "unknown arguments\n");
                ods_log_error("[%s] unknown arguments for key generate command", module_str);
                return -1;
        }
    }
    if (duration_text) {
        if (!(duration = duration_create_from_string(duration_text))
            || !(duration_time = duration2time(duration)))
        {
            client_printf_err(sockfd, "Error parsing the specified duration!\n");
            duration_cleanup(duration);
            return 1;
        }
        duration_cleanup(duration);
    }

    if (all) {
        hsm_key_factory_schedule_generate_all(engine, duration_time);
    }
    else if (policy_name) {
        if (!(policy = policy_new_get_by_name(dbconn, policy_name))) {
            client_printf_err(sockfd, "Unable to find policy %s!\n", policy_name);
            return 1;
        }
        hsm_key_factory_schedule_generate_policy(engine, policy, duration_time);
        policy_free(policy);
    }
    else {
        client_printf_err(sockfd, "Either --all or --policy needs to be given!\n");
        return 1;
    }

    client_printf(sockfd, "Key generation task scheduled.\n");
    return 0;
}

struct cmd_func_block key_generate_funcblock = {
    "key generate", &usage, &help, NULL, NULL, &run, NULL
};
