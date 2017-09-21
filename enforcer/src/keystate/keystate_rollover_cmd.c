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
#include <getopt.h>

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "str.h"
#include "enforcer/enforce_task.h"
#include "clientpipe.h"
#include "db/dbw.h"
#include "log.h"
#include "file.h"

#include "keystate/keystate_rollover_cmd.h"

static const char *module_str = "keystate_rollover_cmd";

static void
usage(int sockfd)
{
    client_printf(sockfd,
        "key rollover\n"
        "	--zone <zone> | --policy <policy>	aka -z | -p \n"
        "	[--keytype <keytype>]			aka -t\n"
    );
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Start a key rollover of the desired type *now*. The process is the same\n"
        "as for the scheduled automated rollovers however it does not wait for\n"
        "the keys lifetime to expire before rolling. The next rollover is due\n"
        "after the newest key aged passed its lifetime.\n"
        "\nOptions:\n"
        "zone		limit the output to the given the zone\n"
        "policy		limit the output to the given the policy\n"
        "keytype		limit the output to the given type, can be KSK, ZSK or CSK (default is all)\n\n"
    );
}

static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
    #define NARGV 6
    const char *argv[NARGV];
    int argc = 0, error;
    int long_index = 0, opt = 0;
    const char *s_zone = NULL, *keytype = NULL, *s_policy = NULL;
    db_connection_t* dbconn = getconnectioncontext(context);
    engine_type* engine = getglobalcontext(context);

    static struct option long_options[] = {
        {"zone", required_argument, 0, 'z'},
        {"policy", required_argument, 0, 'p'},
        {"keytype", required_argument, 0, 't'},
        {0, 0, 0, 0}
    };

    ods_log_debug("[%s] %s command", module_str, key_rollover_funcblock.cmdname);

    /* separate the arguments */
    argc = ods_str_explode(cmd, NARGV, argv);
    if (argc == -1) {
        client_printf_err(sockfd, "too many arguments\n");
        ods_log_error("[%s] too many arguments for %s command",
            module_str, key_rollover_funcblock.cmdname);
        return -1;
    }

    optind = 0;
    while ((opt = getopt_long(argc,
        (char* const*)argv, "p:z:t:", long_options, &long_index)) != -1) 
    {
        switch (opt) {
            case 'z':
                s_zone = optarg;
                break;
            case 'p':
                s_policy = optarg;
                break;
            case 't':
                keytype = optarg;
                break;
            default:
                client_printf_err(sockfd, "unknown arguments\n");
                ods_log_error("[%s] unknown arguments for %s command",
                                module_str, key_rollover_funcblock.cmdname);
                return -1;
        }
    }

    if ((!s_zone && !s_policy) || (s_zone && s_policy)) {
        ods_log_warning("[%s] expected either --zone <zone> or --policy <policy> for %s command",
                module_str, key_rollover_funcblock.cmdname);
        client_printf(sockfd,"expected either --zone <zone> or --policy <policy> option\n");
        return -1;
    }

    int keytype_int = 0;
    if (keytype && (keytype_int = dbw_txt2enum(dbw_key_role_txt, keytype)) == -1) {
        ods_log_error("[%s] unknown keytype, should be one of KSK, ZSK, or CSK", module_str);
        client_printf_err(sockfd, "unknown keytype, should be one of KSK, ZSK, or CSK\n");
        return -1;
    }

    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) return -1;
    for (size_t p = 0; p < db->policies->n; p++) {
        struct dbw_policy *policy = (struct dbw_policy *)db->policies->set[p];
        if (s_policy && strcasecmp(policy->name, s_policy)) continue;
        for (size_t z = 0; z < policy->zone_count; z++) {
            struct dbw_zone *zone = policy->zone[z];
            if (s_zone && strcasecmp(zone->name, s_zone)) continue;
            /* Key of this zone needs to roll */
            zone->roll_zsk_now = (keytype_int == DBW_ZSK) || !keytype_int;
            zone->roll_ksk_now = (keytype_int == DBW_KSK) || !keytype_int;
            zone->roll_csk_now = (keytype_int == DBW_CSK) || !keytype_int;
            zone->scratch = 1; /* Flush this zone later */
            zone->dirty = DBW_UPDATE;
            client_printf(sockfd, "rolling %s for zone %s\n",
                keytype_int?dbw_enum2txt(dbw_key_role_txt, keytype_int):"all keys",
                zone->name);
            ods_log_info("[%s] Manual rollover initiated for %s on Zone: %s",
                module_str,
                keytype_int?dbw_enum2txt(dbw_key_role_txt, keytype_int):"all keys",
                zone->name);
        }
    }
    error = dbw_commit(db);
    if (!error) {
        for (size_t z = 0; z < db->zones->n; z++) {
            struct dbw_zone *zone = (struct dbw_zone *)db->zones->set[z];
            if (!zone->scratch) continue;
            enforce_task_flush_zone(engine, zone->name);
        }
    }
    dbw_free(db);
    return error;
}

struct cmd_func_block key_rollover_funcblock = {
    "key rollover", &usage, &help, NULL, &run
};
