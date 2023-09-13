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
#include "longgetopt.h"
#include "db/zone_db.h"
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

static int delete_key_data(zone_db_t* zone, db_connection_t *dbconn, int sockfd) {
    int successful;
    key_data_list_t* key_data_list;
    key_data_t* key_data;
    key_state_list_t* key_state_list;
    key_state_t* key_state;

    /*
     * Get key data for the zone and for each key data get the key state
     * and try to delete all key state then the key data
     */
    if (!(key_data_list = key_data_list_new_get_by_zone_id(dbconn, zone_db_id(zone)))) {
        client_printf_err(sockfd, "Unable to get key data for zone %s from database!\n", zone_db_name(zone));
        return 0;
    }
    successful = 1;
    for (key_data = key_data_list_get_next(key_data_list); key_data; key_data_free(key_data), key_data = key_data_list_get_next(key_data_list)) {
        if (!(key_state_list = key_state_list_new_get_by_key_data_id(dbconn, key_data_id(key_data)))) {
            client_printf_err(sockfd, "Unable to get key states for key data %s of zone %s from database!\n", key_data_role_text(key_data), zone_db_name(zone));
            successful = 0;
            continue;
        }

        for (key_state = key_state_list_get_next(key_state_list); key_state; key_state_free(key_state), key_state = key_state_list_get_next(key_state_list)) {
            if (key_state_delete(key_state)) {
                client_printf_err(sockfd, "Unable to delete key state %s for key data %s of zone %s from database!\n", key_state_type_text(key_state), key_data_role_text(key_data), zone_db_name(zone));
                successful = 0;
                continue;
            }
        }
        key_state_list_free(key_state_list);

        if (key_data_delete(key_data)) {
            client_printf_err(sockfd, "Unable to delete key data %s of zone %s from database!\n", key_data_role_text(key_data), zone_db_name(zone));
            successful = 0;
            continue;
        }

        if (hsm_key_factory_release_key_id(key_data_hsm_key_id(key_data), dbconn)) {
            client_printf_err(sockfd, "Unable to release HSM key for key data %s of zone %s from database!\n", key_data_role_text(key_data), zone_db_name(zone));
            successful = 0;
            continue;
        }
    }
    key_data_list_free(key_data_list);

    return successful;
}

static int
run(cmdhandler_ctx_type* context, int argc, char* argv[])
{
    int sockfd = context->sockfd;
    struct longgetopt optctx;
    const char *zone_name2 = NULL;
    int all = 0;
    int write_xml = 0;
    int long_index = 0, opt = 0;
    zone_list_db_t* zone_list;
    zone_db_t* zone;
    int ret = 0;
    char path[PATH_MAX];
    char *signconf_del = NULL;
    db_connection_t* dbconn = getconnectioncontext(context);;
    engine_type* engine = getglobalcontext(context);

    static struct option long_options[] = {
        {"zone", required_argument, 0, 'z'},
        {"all", no_argument, 0, 'a'},
        {"xml", no_argument, 0, 'u'},
        {0, 0, 0, 0}
    };

    for(opt = longgetopt(argc, argv, "z:au", long_options, &long_index, &optctx); opt != -1;
        opt = longgetopt(argc, argv, NULL,   long_options, &long_index, &optctx)) {
        switch (opt) {
            case 'z':
                zone_name2 = optctx.optarg;
                break;
            case 'a':
                all = 1;
                break;
            case 'u':
                write_xml = 1;
                break;
           default:
               client_printf_err(sockfd, "unknown arguments\n");
               ods_log_error("[%s] unknown arguments for zone delete command", module_str);
               return -1;
        }
    }

    if (zone_name2 && !all) {
        if (!(zone = zone_db_new_get_by_name(dbconn, zone_name2))) {
            client_printf_err(sockfd, "Unable to delete zone, zone %s not found!\n", zone_name2);
            return 1;
        }

        if (!delete_key_data(zone, dbconn, sockfd)) {
            zone_db_free(zone);
            return 1;
        }
        if (zone_db_delete(zone)) {
            client_printf_err(sockfd, "Unable to delete zone %s from database!\n", zone_name2);
            zone_db_free(zone);
            return 1;
        }
        signconf_del = (char*) calloc(strlen(zone_db_signconf_path(zone)) +
            strlen(".ZONE_DELETED") + 1, sizeof(char));
        if (!signconf_del) {
            ods_log_error("[%s] malloc failed", module_str);
            zone_db_free(zone);
            return 1;
        }
        strncpy(signconf_del, zone_db_signconf_path(zone), strlen(zone_db_signconf_path(zone)));
        strncat(signconf_del, ".ZONE_DELETED", strlen(".ZONE_DELETED"));
        rename(zone_db_signconf_path(zone), signconf_del);
        free(signconf_del);
        signconf_del = NULL;

        /* Delete all 'zone' related tasks */
        schedule_purge_owner(engine->taskq, TASK_CLASS_ENFORCER, zone_name2);

        ods_log_info("[%s] zone %s deleted", module_str, zone_name2);
        client_printf(sockfd, "Deleted zone %s successfully\n", zone_name2);
    } else if (!zone_name2 && all) {
        if (!(zone_list = zone_list_db_new_get(dbconn))) {
            client_printf_err(sockfd, "Unable to get list of zones from database!\n");
            return 1;
        }
        for (zone = zone_list_db_get_next(zone_list); zone; zone_db_free(zone), zone = zone_list_db_get_next(zone_list)) {
            if (!delete_key_data(zone, dbconn, sockfd)) {
                continue;
            }
            if (zone_db_delete(zone)) {
                client_printf_err(sockfd, "Unable to delete zone %s from database!\n", zone_db_name(zone));
                continue;
            }

            signconf_del = (char*) calloc(strlen(zone_db_signconf_path(zone)) +
                strlen(".ZONE_DELETED") + 1, sizeof(char));
            if (!signconf_del) {
                ods_log_error("[%s] malloc failed", module_str);
                zone_db_free(zone);
                zone_list_db_free(zone_list);
                return 1;
            }
            strncpy(signconf_del, zone_db_signconf_path(zone), strlen(zone_db_signconf_path(zone)));
            strncat(signconf_del, ".ZONE_DELETED", strlen(".ZONE_DELETED"));
            rename(zone_db_signconf_path(zone), signconf_del);
            free(signconf_del);
            signconf_del = NULL;

            /* Delete all 'zone' related tasks */
            schedule_purge_owner(engine->taskq, TASK_CLASS_ENFORCER, zone_db_name(zone));

            ods_log_info("[%s] zone %s deleted", module_str, zone_db_name(zone));
            client_printf(sockfd, "Deleted zone %s successfully\n", zone_db_name(zone));
        }
        zone_list_db_free(zone_list);
        zone = NULL;
        client_printf(sockfd, "All zones deleted successfully\n");
    } else {
        client_printf_err(sockfd, "expected either --zone <zone> or --all\n");
        return -1;
    }

    if (write_xml) {
        if (zone) {
            if (zonelist_update_delete(sockfd, engine->config->zonelist_filename, zone, 1) != ZONELIST_UPDATE_OK) {
                ods_log_error("[%s] zonelist %s updated failed", module_str, engine->config->zonelist_filename);
                client_printf_err(sockfd, "Zonelist %s update failed!\n", engine->config->zonelist_filename);
                ret = 1;
            } else {
                ods_log_info("[%s] zonelist %s updated successfully", module_str, engine->config->zonelist_filename);
                client_printf(sockfd, "Zonelist %s updated successfully\n", engine->config->zonelist_filename);
            }
        } else {
            if (zonelist_export(sockfd, dbconn, engine->config->zonelist_filename, 1) != ZONELIST_EXPORT_OK) {
                ods_log_error("[%s] zonelist exported to %s failed", module_str, engine->config->zonelist_filename);
                client_printf_err(sockfd, "Exported zonelist to %s failed!\n", engine->config->zonelist_filename);
                ret = 1;
            } else {
                ods_log_info("[%s] zonelist exported to %s successfully", module_str, engine->config->zonelist_filename);
                client_printf(sockfd, "Exported zonelist to %s successfully\n", engine->config->zonelist_filename);
            }
        }
    }

    if (zone) {
        if (snprintf(path, sizeof(path), "%s/%s", engine->config->working_dir, OPENDNSSEC_ENFORCER_ZONELIST) >= (int)sizeof(path)
            || zonelist_update_delete(sockfd, path, zone, 0) != ZONELIST_UPDATE_OK)
        {
            ods_log_error("[%s] internal zonelist update failed", module_str);
            client_printf_err(sockfd, "Unable to update the internal zonelist %s, updates will not reach the Signer!\n", path);
            ret = 1;
        } else {
            ods_log_info("[%s] internal zonelist updated successfully", module_str);
        }
    } else {
        if (snprintf(path, sizeof(path), "%s/%s", engine->config->working_dir, OPENDNSSEC_ENFORCER_ZONELIST) >= (int)sizeof(path)
            || zonelist_export(sockfd, dbconn, path, 0) != ZONELIST_EXPORT_OK)
        {
            ods_log_error("[%s] internal zonelist update failed", module_str);
            client_printf_err(sockfd, "Unable to update the internal zonelist %s, updates will not reach the Signer!\n", path);
            ret = 1;
        } else {
            ods_log_info("[%s] internal zonelist updated successfully", module_str);
        }
    }

    zone_db_free(zone);
    return ret;
}

struct cmd_func_block zone_del_funcblock = {
    "zone delete", &usage, &help, NULL, NULL, &run, NULL
};
