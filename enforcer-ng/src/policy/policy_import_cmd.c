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
#include "daemon/clientpipe.h"
#include "policy/policy_import.h"

#include "policy/policy_import_cmd.h"

static const char *module_str = "policy_import_cmd";

static void database_error_help(int sockfd) {
    client_printf_err(sockfd,
        "\nThe information in the database may have been changed during KASP update"
        "and caused an update error, try rerunning policy import. If the problem persists"
        "please check logs and database setup and after correcting the problem rerun policy import.\n"
    );
}

static void
usage(int sockfd)
{
    client_printf(sockfd,
        "policy import          Import policies from kasp.xml into the enforcer.\n"
    );
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Import policies from kasp.xml into the enforcer\n"
    );
}

static int
handles(const char *cmd, ssize_t n)
{
    return ods_check_command(cmd, n, policy_import_funcblock()->cmdname) ? 1 : 0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
    db_connection_t *dbconn)
{
    (void)cmd; (void)n;

    if (!engine) {
        return 1;
    }
    if (!engine->config) {
        return 1;
    }
    if (!engine->config->policy_filename) {
        return 1;
    }
    if (!dbconn) {
        return 1;
    }

    ods_log_debug("[%s] %s command", module_str, policy_import_funcblock()->cmdname);

    switch (policy_import(sockfd, engine, dbconn)) {
    case POLICY_IMPORT_OK:
        /*
        error = perform_hsmkey_gen(sockfd, engine->config, 0 / * automatic * /,
            engine->config->automatic_keygen_duration);

        schedule_flush(engine->taskq);
        */
        return 0;
        break;

    case POLICY_IMPORT_ERR_ARGS:
    case POLICY_IMPORT_ERR_XML:
    case POLICY_IMPORT_ERR_MEMORY:
        break;

    case POLICY_IMPORT_ERR_DATABASE:
        database_error_help(sockfd);
        break;

    default:
        break;
    }

    return 1;
}

static struct cmd_func_block funcblock = {
    "policy import", &usage, &help, &handles, &run
};

struct cmd_func_block*
policy_import_funcblock(void)
{
    return &funcblock;
}
