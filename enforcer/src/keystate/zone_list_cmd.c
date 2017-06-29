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

/**
 * FILE
 * list: zone, policy, next change, signconfpath
 */

#include "config.h"

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "duration.h"
#include "clientpipe.h"
#include "db/dbw.h"

#include "keystate/zone_list_cmd.h"

static const char *module_str = "zone_list_cmd";

static void
usage(int sockfd)
{
    client_printf(sockfd, "zone list\n");
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "List all zones currently in the database.\n\n"
    );
}

static const char *
time_to_human(time_t t, char *buf, size_t buflen)
{
    if (t >= time_now()) {
        if (ods_ctime_r(buf, buflen, t))
            return buf;
        return "<error>";
    }
    if (t >= 0)
        return "as soon as possible";
    return "no changes scheduled";

}

static int
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
    const char* fmt = "%-31s %-13s %-26s %-34s\n";
    char buf[32];
    db_connection_t* dbconn = getconnectioncontext(context);
    engine_type* engine = getglobalcontext(context);
    (void)cmd;

    ods_log_debug("[%s] %s command", module_str, zone_list_funcblock.cmdname);

    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) return 1;
    if (!db->zones->n) {
        client_printf(sockfd, "No zones in database.\n");
        dbw_free(db);
        return 0;
    }
    client_printf(sockfd, "Database set to: %s\n", engine->config->datastore);
    client_printf(sockfd, "Zones:\n");
    client_printf(sockfd, fmt, "Zone:", "Policy:", "Next change:",
        "Signer Configuration:");

    for (size_t p = 0; p < db->policies->n; p++) {
        struct dbw_policy *policy = (struct dbw_policy *)db->policies->set[p];
        for (size_t i = 0; i < policy->zone_count; i++) {
            struct dbw_zone *z = policy->zone[i];
            client_printf(sockfd, fmt, z->name, z->policy->name,
                time_to_human(z->next_change, buf, sizeof(buf)), z->signconf_path);
        }
    }
    dbw_free(db);
    return 0;
}

struct cmd_func_block zone_list_funcblock = {
    "zone list", &usage, &help, NULL, &run
};
