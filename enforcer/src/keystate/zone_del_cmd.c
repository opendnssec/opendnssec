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

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "db/dbw.h"
#include "hsmkey/hsm_key_factory.h"
#include "keystate/zonelist_update.h"
#include "keystate/zonelist_export.h"

#include "keystate/zone_del_cmd.h"

#include <limits.h>
#include <getopt.h>

static const char *module_str = "zone_del_cmd";

static void
usage(int sockfd)
{
    client_printf(sockfd,
        "zone delete\n"
        "   --zone <zone> | --all           aka -z | -a \n"
        "   [--xml]                 aka -u \n"
    );
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Delete one zone or all of them from the enforcer database.\n"
        "\nOptions:\n"
        "zone|all   name of the zone or all zones\n"
        "xml        update zonelist.xml and remove the contents for the deleted zone\n\n"
    );
}

static int
delete_zone(struct dbw_zone *zone)
{
    /*
     * Get key data for the zone and for each key data get the key state
     * and try to delete all key state then the key data
     */
    for (size_t ki = 0; ki < zone->key_count; ki++) {
        struct dbw_key *key = zone->key[ki];
        for (size_t si = 0; si < key->keystate_count; si++) {
            struct dbw_keystate *keystate = key->keystate[si];
            keystate->dirty = DBW_DELETE;
        }
        struct dbw_hsmkey *hsmkey = key->hsmkey;
        hsm_key_factory_release_key(hsmkey, key);
        key->dirty = DBW_DELETE;
    }
    zone->dirty = DBW_DELETE;
    return 0; /* success */
}

static int
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
    #define NARGV 6
    char* buf;
    const char* argv[NARGV];
    int argc = 0;
    const char *zonename = NULL;
    int all = 0;
    int write_xml = 0;
    int long_index = 0, opt = 0;
    int ret = 0;
    char path[PATH_MAX];
    db_connection_t* dbconn = getconnectioncontext(context);;
    engine_type* engine = getglobalcontext(context);

    static struct option long_options[] = {
        {"zone", required_argument, 0, 'z'},
        {"all", no_argument, 0, 'a'},
        {"xml", no_argument, 0, 'u'},
        {0, 0, 0, 0}
    };

    ods_log_debug("[%s] %s command", module_str, zone_del_funcblock.cmdname);

    if (!(buf = strdup(cmd))) {
        client_printf_err(sockfd, "memory error\n");
        return -1;
    }

    argc = ods_str_explode(buf, NARGV, argv);
    if (argc == -1) {
        client_printf_err(sockfd, "too many arguments\n");
        ods_log_error("[%s] too many arguments for %s command",
                      module_str, zone_del_funcblock.cmdname);
        free(buf);
        return -1;
    }

    optind = 0;
    while ((opt = getopt_long(argc, (char* const*)argv, "z:au", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'z':
                zonename = optarg;
                break;
            case 'a':
                all = 1;
                break;
            case 'u':
                write_xml = 1;
                break;
           default:
               client_printf_err(sockfd, "unknown arguments\n");
               ods_log_error("[%s] unknown arguments for %s command",
                                module_str, zone_del_funcblock.cmdname);
               free(buf);
               return -1;
        }
    }
    if (all == (zonename != NULL)) { /*xnor*/
       client_printf_err(sockfd, "Either --zone or --all required.\n");
       free(buf);
       return -1;
    }

    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) {
        client_printf(sockfd, "Error reading database.\n");
        return 1;
    }
    int zones_deleted = 0;
    for (size_t z = 0; z < db->zones->n; z++) {
        struct dbw_zone *zone = (struct dbw_zone *)db->zones->set[z];
        if (!all && strcmp(zonename, zone->name)) continue;
        if (delete_zone(zone)) {
            client_printf(sockfd, "Error deleting zone %s.\n", zone->name);
            dbw_free(db);
            ret = 1;
            continue;
        }
        int len = strlen(zone->signconf_path) + strlen(".ZONE_DELETED") + 1;
        char *signconf_del = malloc(len);
        strcpy(signconf_del, zone->signconf_path);
        strncat(signconf_del, ".ZONE_DELETED", len);
        rename(zone->signconf_path, signconf_del);
        free(signconf_del);
        zones_deleted++;

        /* Delete all 'zone' related tasks */
        schedule_purge_owner(engine->taskq, TASK_CLASS_ENFORCER, zone->name);
        ods_log_info("[%s] zone %s deleted", module_str, zone->name);
        client_printf(sockfd, "Deleted zone %s successfully\n", zone->name);
    }
    //todo handle error
    if (dbw_commit(db)) {
        client_printf(sockfd, "Error committing changes to database.\n");
        dbw_free(db);
        free(buf);
        return 1;
    }
    dbw_free(db);
    free(buf);

    if (!zones_deleted && zonename) {
        client_printf_err(sockfd, "Unable to delete zone, zone %s not found", zonename);
        return 1;
    }

    if (write_xml) {
        if (zonelist_export(sockfd, dbconn, engine->config->zonelist_filename, 1) != ZONELIST_EXPORT_OK) {
            ods_log_error("[%s] zonelist exported to %s failed", module_str, engine->config->zonelist_filename);
            client_printf_err(sockfd, "Exported zonelist to %s failed!\n", engine->config->zonelist_filename);
            ret = 1;
        } else {
            ods_log_info("[%s] zonelist exported to %s successfully", module_str, engine->config->zonelist_filename);
            client_printf(sockfd, "Exported zonelist to %s successfully\n", engine->config->zonelist_filename);
        }
    }

    if (snprintf(path, sizeof(path), "%s/%s", engine->config->working_dir, OPENDNSSEC_ENFORCER_ZONELIST) >= (int)sizeof(path)
        || zonelist_export(sockfd, dbconn, path, 0) != ZONELIST_EXPORT_OK)
    {
        ods_log_error("[%s] internal zonelist update failed", module_str);
        client_printf_err(sockfd, "Unable to update the internal zonelist %s, updates will not reach the Signer!\n", path);
        ret = 1;
    } else {
        ods_log_info("[%s] internal zonelist updated successfully", module_str);
    }

    return ret;
}

struct cmd_func_block zone_del_funcblock = {
    "zone delete", &usage, &help, NULL, &run
};
