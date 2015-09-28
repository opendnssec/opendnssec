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

#include "config.h"
#include <limits.h>

#include "daemon/engine.h"
#include "daemon/cmdhandler.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "enforcer/enforce_task.h"
#include "keystate/zonelist_import.h"
#include "keystate/zonelist_export.h"

#include "keystate/zonelist_import_cmd.h"

static const char *module_str = "zonelist_import_cmd";

static void
usage(int sockfd)
{
    client_printf(sockfd,
        "zonelist import        Import zones from zonelist.xml into enforcer.\n"
        "      [--remove-missing-zones]   (aka -r)  Remove any zones from database not in zonelist file.\n"
    /* We require the user to give an absolute path. The daemon
     * and the client might not have the same working directory. */
        "      [--file <absolute path>]   (aka -f)  File to import, instead of zonelist file configured in conf.xml.\n"
    );
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Import zones from zonelist.xml into enforcer\n"
    );
}

static int
handles(const char *cmd, ssize_t n)
{
    return ods_check_command(cmd, n, zonelist_import_funcblock()->cmdname) ? 1 : 0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
    db_connection_t *dbconn)
{
    char path[PATH_MAX], buf[ODS_SE_MAXLINE];
    int ret, argc, remove_missing_zones;
    #define NARGV 8
    const char *argv[NARGV];
    const char* zonelist_path = NULL;

    ods_log_debug("[%s] %s command", module_str, zonelist_import_funcblock()->cmdname);

    if (!engine || !engine->config ||
        !engine->config->zonelist_filename || !dbconn)
    {
        return 1;
    }

    cmd = ods_check_command(cmd, n, zonelist_import_funcblock()->cmdname);
    if (!cmd) return -1;
    /* Use buf as an intermediate buffer for the command.*/
    strncpy(buf, cmd, sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    /* separate the arguments*/
    argc = ods_str_explode(buf, NARGV, argv);
    if (argc > NARGV) {
        ods_log_warning("[%s] too many arguments for %s command",
                        module_str, zonelist_import_funcblock()->cmdname);
        client_printf(sockfd,"too many arguments\n");
        return -1;
    }
    remove_missing_zones = (ods_find_arg(&argc, argv, "remove-missing-zones", "r") >= 0);
    (void)ods_find_arg_and_param(&argc, argv, "file", "f", &zonelist_path);
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str, zonelist_import_funcblock()->cmdname);
        client_printf(sockfd,"unknown arguments\n");
        return -1;
    }

    ret = zonelist_import(sockfd, engine, dbconn, remove_missing_zones, zonelist_path);
    if (ret == ZONELIST_IMPORT_NO_CHANGE) {
        return 0;
    } else if (ret != ZONELIST_IMPORT_OK) {
        return 1;
    }

    if (snprintf(path, sizeof(path), "%s/%s", engine->config->working_dir, OPENDNSSEC_ENFORCER_ZONELIST) >= (int)sizeof(path)
        || zonelist_export(sockfd, dbconn, path, 0) != ZONELIST_EXPORT_OK)
    {
        ods_log_error("[%s] internal zonelist export failed", module_str);
        client_printf_err(sockfd, "Unable to export the internal zonelist %s, updates will not reach the Signer!\n", path);
        return 1;
    }
    else {
        ods_log_info("[%s] internal zonelist exported successfully", module_str);
    }

    flush_enforce_task(engine, 1);

    return 0;
}

static struct cmd_func_block funcblock = {
    "zonelist import", &usage, &help, &handles, &run
};

struct cmd_func_block*
zonelist_import_funcblock(void)
{
    return &funcblock;
}
