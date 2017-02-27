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
#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "keystate/zonelist_export.h"

#include "keystate/zonelist_export_cmd.h"

static const char *module_str = "zonelist_export_cmd";

static void
usage(int sockfd)
{
    client_printf(sockfd, "zonelist export\n");
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Export list of zones from the database to the zonelist.xml file.\n\n"
    );
}

static int
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
    db_connection_t* dbconn = getconnectioncontext(context);
    engine_type* engine = getglobalcontext(context);
    (void)cmd;

    if (!engine || !engine->config || !engine->config->zonelist_filename
        || !dbconn)
    {
        return 1;
    }
    ods_log_debug("[%s] %s command", module_str, zonelist_export_funcblock.cmdname);

    if (zonelist_export(sockfd, dbconn, engine->config->zonelist_filename, 1)
        != ZONELIST_EXPORT_OK)
    {
        ods_log_error("[%s] zonelist exported to %s failed", module_str,
            engine->config->zonelist_filename);
        client_printf_err(sockfd, "Exported zonelist to %s failed!\n",
            engine->config->zonelist_filename);
        return 1;
    }

    ods_log_info("[%s] zonelist exported to %s successfully", module_str,
        engine->config->zonelist_filename);
    client_printf(sockfd, "Exported zonelist to %s successfully\n",
        engine->config->zonelist_filename);
    return 0;
}

struct cmd_func_block zonelist_export_funcblock = {
    "zonelist export", &usage, &help, NULL, &run
};
