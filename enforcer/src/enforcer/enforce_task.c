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
#include "db/zone_db.h"
#include "db/db_clause.h"

#include "enforcer/enforce_task.h"

static const char *module_str = "enforce_task";

static time_t
perform_enforce(int sockfd, engine_type *engine, char const *zonename,
	db_connection_t *dbconn)
{
	zone_db_t *zone;
	policy_t *policy;
	time_t t_next;
	int zone_updated = 0;
	int bSignerConfNeedsWriting = 0;
	int bSubmitToParent = 0;
	int bRetractFromParent = 0;
	key_data_list_t *keylist;
	key_data_t const *key;

	
	zone = zone_db_new_get_by_name(dbconn, zonename);
	if (!zone) {
		ods_log_error("[%s] Could not find zone %s in database",
			module_str, zonename);
		return -1;
	}

	if (!(policy = zone_db_get_policy(zone))) {
		ods_log_error("Next update for zone %s NOT scheduled "
			"because policy is missing !\n", zone_db_name(zone));
		zone_db_free(zone);
		return -1;
	}

	if (policy_passthrough(policy)) {
		ods_log_info("Passing through zone %s.\n", zone_db_name(zone));
		bSignerConfNeedsWriting = 1;
		t_next = schedule_SUCCESS;
	} else {
		t_next = update(engine, dbconn, zone, policy, time_now(), &zone_updated);
		bSignerConfNeedsWriting = zone_db_signconf_needs_writing(zone);
	}
	
	policy_free(policy);

	/* Commit zone to database before we schedule signconf */
	if (zone_updated) {
		(void)zone_db_set_next_change(zone, t_next);
		(void)zone_db_update(zone);
	}

	if (bSignerConfNeedsWriting) {
		signconf_task_flush_zone(engine, dbconn, zonename);
	} else {
		ods_log_info("[%s] No changes to signconf file required for zone %s", module_str, zonename);
	}

	keylist = zone_db_get_keys(zone);
	while ((key = key_data_list_next(keylist))) {
		if (key_data_ds_at_parent(key) == KEY_DATA_DS_AT_PARENT_SUBMIT) {
			ods_log_warning("[%s] please submit DS "
				"with keytag %d for zone %s",
				module_str, key_data_keytag(key)&0xFFFF, zone_db_name(zone));
			bSubmitToParent = 1;
		} else if (key_data_ds_at_parent(key) == KEY_DATA_DS_AT_PARENT_RETRACT) {
			ods_log_warning("[%s] please retract DS "
				"with keytag %d for zone %s",
				module_str, key_data_keytag(key)&0xFFFF, zone_db_name(zone));
			bRetractFromParent = 1;
		}
	}
	key_data_list_free(keylist);

	/* Launch ds-submit task when one of the updated key states has the
	 * DS_SUBMIT flag set. */
	if (bSubmitToParent) {
		task_type *submit = keystate_ds_submit_task(engine, zonename);
		schedule_task(engine->taskq, submit, 1, 0);
	}
	/* Launch ds-retract task when one of the updated key states has the
	 * DS_RETRACT flag set. */
	if (bRetractFromParent) {
		task_type *retract = keystate_ds_retract_task(engine, zonename);
		schedule_task(engine->taskq, retract, 1, 0);
	}

	zone_db_free(zone);
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
enforce_task_flush_policy(engine_type *engine, db_connection_t *dbconn,
	policy_t const *policy)
{
	zone_db_t const *zone;
	zone_list_db_t *zonelist;

	ods_log_assert(policy);
	
	zonelist = zone_list_db_new_get_by_policy_id(dbconn, policy_id(policy));
	if (!zonelist) {
		ods_log_error("[%s] Can't fetch zones for policy %s from database",
			module_str, policy_name(policy));
		return;
	}
	while ((zone = zone_list_db_next(zonelist))) {
		(void)schedule_task(engine->taskq, enforce_task(engine, zone->name), 1, 0);
	}
	zone_list_db_free(zonelist);
}

void
enforce_task_flush_all(engine_type *engine, db_connection_t *dbconn)
{
	zone_list_db_t *zonelist;
	const zone_db_t *zone;
	
	zonelist = zone_list_db_new_get(dbconn);
	if (!zonelist) {
		db_connection_free(dbconn);
		ods_fatal_exit("[%s] failed to list zones from DB", module_str);
	}
	while ((zone = zone_list_db_next(zonelist))) {
		(void)schedule_task(engine->taskq, enforce_task(engine, zone->name), 1, 0);
	}
	zone_list_db_free(zonelist);
}
