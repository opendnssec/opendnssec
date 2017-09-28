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

#include <pthread.h>

#include "enforcer/enforcer.h"
#include "clientpipe.h"
#include "daemon/engine.h"
#include "signconf/signconf_task.h"
#include "keystate/keystate_ds_submit_task.h"
#include "keystate/keystate_ds_retract_task.h"
#include "duration.h"
#include "file.h"
#include "log.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "db/dbw.h"

#include "enforcer/enforce_task.h"

static const char *module_str = "enforce_task";

static void
schedule_ds_tasks(engine_type *engine, struct dbw_zone *zone)
{
    int bSubmitToParent = 0;
    int bRetractFromParent = 0;
    for (size_t i = 0; i < zone->key_count; i++) {
        struct dbw_key *key= zone->key[i];
        if (key->ds_at_parent == KEY_DATA_DS_AT_PARENT_SUBMIT) {
            ods_log_warning("[%s] please submit DS with keytag %d for zone %s",
                module_str, key->keytag&0xFFFF, zone->name);
            bSubmitToParent = 1;
        } else if (key->ds_at_parent == KEY_DATA_DS_AT_PARENT_RETRACT) {
            ods_log_warning("[%s] please retract DS with keytag %d for zone %s",
                module_str, key->keytag&0xFFFF, zone->name);
            bRetractFromParent = 1;
        }
    }
    /* Do not schedule DS tasks when no command is specified */
    if (!engine->config->delegation_signer_submit_command) bSubmitToParent = 0;
    if (!engine->config->delegation_signer_retract_command) bRetractFromParent = 0;
    /* Launch ds-submit task when one of the updated key states has the
     * DS_SUBMIT flag set. */
    if (bSubmitToParent) {
        task_type *submit = keystate_ds_submit_task(engine, zone->name);
        schedule_task(engine->taskq, submit, 1, 0);
    }
    /* Launch ds-retract task when one of the updated key states has the
     * DS_RETRACT flag set. */
    if (bRetractFromParent) {
        task_type *retract = keystate_ds_retract_task(engine, zone->name);
        schedule_task(engine->taskq, retract, 1, 0);
    }
}

static time_t
perform_enforce(int sockfd, engine_type *engine, char const *zonename,
    db_connection_t *dbconn)
{
    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) {
        ods_log_error("[%s] Error reading database", module_str);
        return -1;
    }
    struct dbw_zone *zone = dbw_get_zone(db, zonename);
    if (!zone) {
        ods_log_error("[%s] Could not find zone %s in database", module_str, zonename);
        dbw_free(db);
        return -1;
    }
    time_t t_next;
    int zone_updated = 0;
    if (zone->policy->passthrough) {
        ods_log_info("Passing through zone %s.\n", zone->name);
        t_next = schedule_SUCCESS;
    } else {
        t_next = update(engine, db, zone, time_now(), &zone_updated);
    }
    /* Commit zone to database before we schedule signconf */
    if (zone_updated) {
        zone->next_change = t_next;
        if (dbw_commit(db)) {
            ods_log_error("[%s] Unable to commit changes to zone %s to "
                "database, deferring.", module_str, zonename);
            dbw_free(db);
            return schedule_DEFER;
        }
    }
    if (zone->signconf_needs_writing || zone->policy->passthrough) {
        /* We always write signconf on passthrough, but we won't schedule the
         * zone so the signconf will not be written over and over. Unless
         * scheduled by user or first start which is desirable. */
        signconf_task_flush_zone(engine, dbconn, zonename);
    } else {
        ods_log_info("[%s] No changes to signconf file required for zone %s",
            module_str, zonename);
    }
    schedule_ds_tasks(engine, zone);
    dbw_free(db);
    return t_next;
}

time_t
enforce_task_perform(task_type* task, char const *owner, void *userdata, void *context)
{
    db_connection_t* dbconn = (db_connection_t*) context;
    return perform_enforce(-1, (engine_type *)userdata, owner, dbconn);
}

task_type *
enforce_task(engine_type *engine, char const *owner)
{
    return task_create(strdup(owner), TASK_CLASS_ENFORCER, TASK_TYPE_ENFORCE,
        enforce_task_perform, engine, NULL, time_now());
}

void
enforce_task_flush_zone(engine_type *engine, char const *zonename)
{
    (void)schedule_task(engine->taskq, enforce_task(engine, zonename), 1, 0);
}

void
enforce_task_flush_policy(engine_type *engine, struct dbw_policy *policy)
{
    for (size_t z = 0; z < policy->zone_count; z++) {
        struct dbw_zone *zone = policy->zone[z];
        (void)schedule_task(engine->taskq, enforce_task(engine, zone->name), 1, 0);
    }
}

void
enforce_task_flush_all(engine_type *engine, db_connection_t *dbconn)
{
    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) ods_fatal_exit("[%s] failed to list zones from DB", module_str);
    for (size_t z = 0; z < db->zones->n; z++) {
        struct dbw_zone *zone = (struct dbw_zone *)db->zones->set[z];
        (void)schedule_task(engine->taskq, enforce_task(engine, zone->name), 1, 0);
    }
    dbw_free(db);
}
