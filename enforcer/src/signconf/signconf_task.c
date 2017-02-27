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

#include "signconf/signconf_xml.h"
#include "duration.h"
#include "log.h"
#include "file.h"
#include "db/dbw.h"

#include "signconf/signconf_task.h"

static const char *module_str = "signconf_cmd";

static time_t
perform(task_type* task, char const *zonename, void *userdata, void *context)
{
    (void)userdata;
    int ret;
    char cmd[SYSTEM_MAXLEN];
    db_connection_t* dbconn = (db_connection_t*) context;

    ods_log_info("[%s] performing signconf for zone %s", module_str,
        zonename);

    /* exports all that have "needswriting set */
    ret = signconf_export_zone(zonename, dbconn);
    if (ret == SIGNCONF_EXPORT_NO_CHANGE) {
        ods_log_info("[%s] signconf done, no change", module_str);
        return schedule_SUCCESS;
    }
    if (ret != SIGNCONF_EXPORT_OK) {
        ods_log_error("[%s] signconf failed", module_str);
        /* YBS reschedule backoff? */
        return schedule_SUCCESS;
    }
    
    ods_log_info("[%s] signconf done for zone %s, notifying signer",
        module_str, zonename);
        
    /* TODO: do this better, connect directly or use execve() */
    if (snprintf(cmd, sizeof(cmd), "%s %s", SIGNER_CLI_UPDATE, zonename) >= (int)sizeof(cmd)
        || system(cmd))
    {
        ods_log_error("[%s] unable to notify signer of signconf changes for zone %s!",
            module_str, zonename);
    }
    return schedule_SUCCESS;
}

void
signconf_task_flush_zone(engine_type *engine, db_connection_t *dbconn,
    const char* zonename)
{
    task_type* task = task_create(strdup(zonename), TASK_CLASS_ENFORCER,
        TASK_TYPE_SIGNCONF, perform, NULL, NULL, time_now());
    (void) schedule_task(engine->taskq, task, 1, 0);
}

void
signconf_task_flush_policy(engine_type *engine, db_connection_t *dbconn,
    char const *policyname)
{
    struct dbw_list *policies = dbw_policies_all_filtered(dbconn, policyname, NULL, 0);
    if (!policies) {
        ods_log_error("[%s] Can't fetch zones for policy %s from database",
            module_str, policyname);
        return;
    }
    for (size_t p = 0; p < policies->n; p++) {
        struct dbw_policy *policy = (struct dbw_policy *)policies->set[p];
        for (size_t z = 0; z < policy->zone_count; z++) {
            struct dbw_zone *zone = policy->zone[z];
            signconf_task_flush_zone(engine, dbconn, zone->name);
        }
    }
    dbw_list_free(policies);
}

void
signconf_task_flush_all(engine_type *engine, db_connection_t *dbconn)
{
    zone_list_db_t *zonelist;
    zone_db_t const *zone;

    zonelist = zone_list_db_new(dbconn);
    if (!zonelist) {
        ods_log_error("[%s] Can't fetch zones from database", module_str);
        return;
    }
    if (zone_list_db_get(zonelist)) { /* fetch all */
        ods_log_error("[%s] Can't fetch zones from database", module_str);
        zone_list_db_free(zonelist);
        return;
    }
    while ((zone = zone_list_db_next(zonelist))) {
        signconf_task_flush_zone(engine, dbconn, zone_db_name(zone));
    }
    zone_list_db_free(zonelist);
}
