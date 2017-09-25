/*
 * Copyright (c) 2017 Stichting NLnet Labs
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
#include "config.h"

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "duration.h"
#include "enforcer/enforcer.h"
#include "keystate/keystate_list_cmd.h"

#include "enforcer/lookahead_cmd.h"

static const char *module_str = "lookahead_cmd";

#define MAX_ARGS 4

static void
usage(int sockfd)
{
    client_printf(sockfd,
        "look-ahead\n"
        "	--zone <zonename>	aka -z\n"
        "	--steps <n>		aka -s\n");
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Shows the n next state changes for a zone.\n"
        "\nOptions:\n"
        "zone		Zone to show the state for.\n"
        "steps		Number of steps to take in to the future.\n"
        "\n"
    );
}

static void
printdebugheader(int sockfd) {
    client_printf(sockfd,
            "Key role:     "
            "DS:          DNSKEY:      RRSIGDNSKEY: RRSIG:       "
            "Time:                 Pub: Act: Id:\n");
}

static void
printdebugkey_fmt(int sockfd, char const *fmt, struct dbw_key *key, char const  *tchange)
{
    (void)tchange;
    client_printf(sockfd, fmt,
        dbw_enum2txt(dbw_key_role_txt, key->role),
        dbw_enum2txt(dbw_keystate_state_txt, dbw_get_keystate(key, DBW_DS)->state), /*  TODO */
        dbw_enum2txt(dbw_keystate_state_txt, dbw_get_keystate(key, DBW_DNSKEY)->state),
        dbw_enum2txt(dbw_keystate_state_txt, dbw_get_keystate(key, DBW_RRSIGDNSKEY)->state),
        dbw_enum2txt(dbw_keystate_state_txt, dbw_get_keystate(key, DBW_RRSIG)->state),
        tchange,
        key->publish,
        key->active_ksk | key->active_zsk,
        key->hsmkey->locator);
}

static void
printdebugkey(int sockfd, struct dbw_key *key, char *tchange)
{
    printdebugkey_fmt(sockfd, "%-13s %-12s %-12s %-12s %-12s %-21s %d %4d    %s\n", key, tchange);
}

static void
perform_keystate_list(int sockfd, struct dbw_zone *zone,
    void (printheader)(int sockfd),
    void (printkey)(int sockfd, struct dbw_key *key, char* tchange), time_t now)
{
    if (printheader) (*printheader)(sockfd);
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *key = zone->key[k];
        if (key->dirty == DBW_DELETE) continue;
        char* tchange = map_keytime(key, now); /* allocs */
            (*printkey)(sockfd, key, tchange);
        free(tchange);
    }
}

/**
 * Handle the 'look-ahead' command.
 *
 */
static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
    int argc = 0;
    char const *argv[MAX_ARGS];
    int long_index = 0, opt = 0;
    char const *zonename = NULL;
    int steps = 10;
    db_connection_t* dbconn = getconnectioncontext(context);
    engine_type* engine = getglobalcontext(context);

    static struct option long_options[] = {
        {"zone", required_argument, 0, 'z'},
        {"steps", required_argument, 0, 's'},
        {0, 0, 0, 0}
    };

    ods_log_debug("[%s] %s command", module_str, lookahead_funcblock.cmdname);
    if (!cmd) return -1;
    argc = ods_str_explode(cmd, MAX_ARGS, argv);
    if (argc == -1) {
        client_printf_err(sockfd, "too many arguments\n");
        return -1;
    }

    optind = 0;
    while ((opt = getopt_long(argc, (char* const*)argv, "z:s:", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'z':
                zonename = optarg;
                break;
            case 's':
                steps = atoi(optarg);
                break;
            default:
                client_printf_err(sockfd, "unknown arguments\n");
                ods_log_error("[%s] unknown arguments for %s command",
                    module_str, lookahead_funcblock.cmdname);
                return -1;
        }
    }
    if (!zonename) {
        client_printf_err(sockfd, "--zone required\n");
        return -1;
    }

    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) return 1;
    struct dbw_zone *zone = dbw_get_zone(db, zonename);
    if (!zone) {
        client_printf_err(sockfd, "Could not find zone %s in database\n", zonename);
        dbw_free(db);
        return 1;
    }
    /* TODO actually delete keys from structure, these may confuse the enforcer. */
    /* TODO Tab completion */

    time_t now = time_now();
    client_printf(sockfd, "Current state:\n");
    perform_keystate_list(sockfd, zone, printdebugheader, printdebugkey, now);
    for (int i = 0; i < steps; i++) {
        time_t t_next = -1;
        int zone_updated = 0;
        if (!zone->policy->passthrough) {
            t_next = update_mockup(engine, db, zone, now, &zone_updated);
            zone->next_change = t_next;
        }
        char tbuf[26];
        if (!ods_ctime_r(now, tbuf)) memset(tbuf, 0 , sizeof(tbuf));
        client_printf(sockfd, "\nat %s zone %s will look like:\n", tbuf, zone->name);
        if (zone_updated) {
            perform_keystate_list(sockfd, zone, printdebugheader, printdebugkey, now);
            client_printf(sockfd, "\n");
        } else {
            client_printf(sockfd, " - No changes to zone.\n");
        }
        for (size_t k = 0; k < zone->key_count; k++) {
            struct dbw_key *key = zone->key[k];
            if (key->ds_at_parent == DBW_DS_AT_PARENT_SUBMIT) {
                key->ds_at_parent = DBW_DS_AT_PARENT_SUBMITTED;
                client_printf(sockfd, " - Submitting DS to parent zone.\n");
                t_next = now;
            } else if (key->ds_at_parent == DBW_DS_AT_PARENT_RETRACT) {
                key->ds_at_parent = DBW_DS_AT_PARENT_RETRACTED;
                client_printf(sockfd, " - Removing DS from parent zone.\n");
                t_next = now;
            } else if (key->ds_at_parent == DBW_DS_AT_PARENT_SUBMITTED) {
                key->ds_at_parent = DBW_DS_AT_PARENT_SEEN;
                client_printf(sockfd, " - Marking DS as seen.\n");
                t_next = now;
            } else if (key->ds_at_parent == DBW_DS_AT_PARENT_RETRACTED) {
                key->ds_at_parent = DBW_DS_AT_PARENT_UNSUBMITTED;
                client_printf(sockfd, " - Marking DS as gone.\n");
                t_next = now;
            }
        }
        if (zone->signconf_needs_writing) {
            zone->signconf_needs_writing = 0;
            client_printf(sockfd, " - Writing signconf.\n");
        }
        if (t_next == -1) break; /* nothing to be done ever */
        now = t_next;
    }
    dbw_free(db);
    return 0;
}

struct cmd_func_block lookahead_funcblock = {
    "look-ahead", &usage, &help, NULL, &run
};
