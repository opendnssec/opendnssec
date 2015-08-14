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

#include "daemon/engine.h"
#include "daemon/cmdhandler.h"
#include "shared/log.h"
#include "shared/str.h"
#include "clientpipe.h"
#include "hsmkey/hsm_key_factory.h"
#include "db/policy.h"
#include "shared/duration.h"

#include "hsmkey/key_generate_cmd.h"

static const char *module_str = "key_generate_cmd";

static void
usage(int sockfd)
{
    client_printf(sockfd,
        "key generate           Pre-generate keys.\n"
        "      --duration <duration>      (aka -d)  duration to generate keys for.\n"
        "      --policy <policy>          (aka -p)  policy to generate keys for.\n"
        "      --all                      (aka -a)  generate keys for all policies.\n"
    );
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Pre-generate keys for all or a given policy, the duration to pre-generate for\n"
        "can be specified or otherwise its taken from the conf.xml.\n"
    );
}

static int
handles(const char *cmd, ssize_t n)
{
    return ods_check_command(cmd, n, key_generate_funcblock()->cmdname) ? 1 : 0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
    db_connection_t *dbconn)
{
    char* buf;
    const char* argv[6];
    int argc;
    const char* policy_name = NULL;
    const char* duration_text = NULL;
    time_t duration_time = 0;
    duration_type* duration = NULL;
    int all = 0;
    policy_t* policy;

    ods_log_debug("[%s] %s command", module_str, key_generate_funcblock()->cmdname);
    cmd = ods_check_command(cmd, n, key_generate_funcblock()->cmdname);

    if (!(buf = strdup(cmd))) {
        client_printf_err(sockfd, "memory error\n");
        return -1;
    }

    argc = ods_str_explode(buf, 6, argv);
    if (argc > 6) {
        client_printf_err(sockfd, "too many arguments\n");
        free(buf);
        return -1;
    }

    ods_find_arg_and_param(&argc, argv, "duration", "d", &duration_text);
    ods_find_arg_and_param(&argc, argv, "policy", "p", &policy_name);
    all = ods_find_arg(&argc, argv, "all", "a") > -1 ? 1 : 0;

    if (argc) {
        client_printf_err(sockfd, "unknown arguments\n");
        free(buf);
        return -1;
    }

    if (duration_text) {
        if (!(duration = duration_create_from_string(duration_text))
            || !(duration_time = duration2time(duration)))
        {
            client_printf_err(sockfd, "Error parsing the specified duration!\n");
            duration_cleanup(duration);
            free(buf);
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
            free(buf);
            return 1;
        }
        hsm_key_factory_schedule_generate_policy(engine, policy, duration_time);
        policy_free(policy);
    }
    else {
        client_printf_err(sockfd, "Either --all or --policy needs to be given!\n");
        free(buf);
        return 1;
    }

    client_printf(sockfd, "Key generation task scheduled.\n");
    free(buf);
    return 0;
}

static struct cmd_func_block funcblock = {
    "key generate", &usage, &help, &handles, &run
};

struct cmd_func_block*
key_generate_funcblock(void)
{
    return &funcblock;
}
