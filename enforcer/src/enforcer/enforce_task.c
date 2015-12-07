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
#include "db/zone.h"
#include "db/db_clause.h"

#include "enforcer/enforce_task.h"

static const char *module_str = "enforce_task";

static void
enf_schedule_task(int sockfd, engine_type* engine, task_type *task, const char *what)
{
	/* schedule task */
	if (!task) {
		ods_log_crit("[%s] failed to create %s task", module_str, what);
	} else {
		ods_status status = schedule_task(engine->taskq, task);
		if (status != ODS_STATUS_OK) {
			ods_log_crit("[%s] failed to create %s task", module_str, what);
			client_printf(sockfd, "Unable to schedule %s task.\n", what);
		} else {
			client_printf(sockfd, "Scheduled %s task.\n", what);
		}
	}
}

static void
reschedule_enforce(task_type *task, time_t t_when, const char *z_when)
{
	ods_log_assert(task->who);
	free(task->who);
	task->who = strdup(z_when);
	task->when = t_when;
	task->backoff = 0;
}

static time_t
perform_enforce(int sockfd, engine_type *engine, int bForceUpdate,
	task_type* task, db_connection_t *dbconn)
{
	zone_list_t *zonelist = NULL;
	zone_t *zone, *firstzone = NULL;
	policy_t *policy;
	key_data_list_t *keylist;
	const key_data_t *key;
	time_t t_next, t_now = time_now(), t_reschedule = -1;
	/* Flags that indicate tasks to be scheduled after zones have been
	 * enforced. */
	int bSignerConfNeedsWriting = 0;
	int bSubmitToParent = 0;
	int bRetractFromParent = 0;
	int zone_updated;

	if (!(zonelist = zone_list_new(dbconn))
		/*|| zone_list_associated_fetch(zonelist)*/
		|| zone_list_get(zonelist))
	{
		zone_list_free(zonelist);
		zonelist = NULL;
	}
	if (!zonelist) {
		/* TODO: log error */
		ods_log_error("[%s] zonelist NULL", module_str);
		/* TODO: backoff? */
		return t_reschedule;
	}

	for (zone = zone_list_get_next(zonelist); zone;
		zone_free(zone), zone = zone_list_get_next(zonelist))
	{
		if (engine->need_to_reload || engine->need_to_exit) break;

		if (!bForceUpdate && (zone_next_change(zone) == -1)) {
			continue;
		} else if (zone_next_change(zone) > t_now && !bForceUpdate) {
			/* This zone needs no update, however it might be the first
			 * for future updates */
			if (zone_next_change(zone) < t_reschedule || !firstzone)
			{
				t_reschedule = zone_next_change(zone);
				if (firstzone) {
					zone_free(firstzone);
				}
				firstzone = zone;
				zone = NULL; /* keeps firstzone from being freed. */
			}
			continue;
		}
		if (!(policy = zone_get_policy(zone))) {
			client_printf(sockfd,
				"Next update for zone %s NOT scheduled "
				"because policy is missing !\n", zone_name(zone));
			if (zone_next_change(zone) != -1
				&& (zone_set_next_change(zone, -1)
					|| zone_update(zone)))
			{
				/* TODO: Log error */
			}
			continue;
		}

		if (policy_passthrough(policy)) {
			ods_log_info("Passing through zone %s.\n", zone_name(zone));
			zone_set_signconf_needs_writing(zone, 1);
			zone_update(zone);
			bSignerConfNeedsWriting = 1;
			policy_free(policy);
			continue;
		}

		zone_updated = 0;
		t_next = update(engine, dbconn, zone, policy, t_now, &zone_updated);
		policy_free(policy);
		bSignerConfNeedsWriting |= zone_signconf_needs_writing(zone);

		keylist = zone_get_keys(zone);
		while ((key = key_data_list_next(keylist))) {
			if (key_data_ds_at_parent(key) == KEY_DATA_DS_AT_PARENT_SUBMIT) {
				ods_log_warning("[%s] please submit DS "
					"with keytag %d for zone %s",
					module_str, key_data_keytag(key)&0xFFFF, zone_name(zone));
				bSubmitToParent = 1;
			} else if (key_data_ds_at_parent(key) == KEY_DATA_DS_AT_PARENT_RETRACT) {
				ods_log_warning("[%s] please retract DS "
					"with keytag %d for zone %s",
					module_str, key_data_keytag(key)&0xFFFF, zone_name(zone));
				bRetractFromParent = 1;
			}
		}
		key_data_list_free(keylist);

		if (t_next == -1) {
			client_printf(sockfd,
				"Next update for zone %s NOT scheduled "
				"by enforcer !\n", zone_name(zone));
			ods_log_debug("Next update for zone %s NOT scheduled "
				"by enforcer !\n", zone_name(zone));
		} else {
			/* Invalid schedule time then skip the zone.*/
			char tbuf[32] = "date/time invalid\n"; /* at least 26 bytes */
			ctime_r(&t_next, tbuf); /* note that ctime_r inserts \n */
			client_printf(sockfd,
				"Next update for zone %s scheduled at %s",
				zone_name(zone), tbuf);
			ods_log_debug("Next update for zone %s scheduled at %s",
				zone_name(zone), tbuf);
		}
		if (zone_next_change(zone) != t_next) {
			zone_set_next_change(zone, t_next);
			zone_updated = 1;
		}

		/*
		 * Commit the changes to the zone if there where any.
		 */
		if (zone_updated) {
			if (zone_update(zone)) {
				ods_log_debug("[%s] error zone_update(%s)", module_str, zone_name(zone));
			}
		}

		/*
		 * Find out when to schedule the next change.
		 */
		if (zone_next_change(zone) != -1
			&& (zone_next_change(zone) < t_reschedule
				|| !firstzone))
		{
			t_reschedule = zone_next_change(zone);
			if (firstzone) {
				zone_free(firstzone);
			}
			firstzone = zone;
			zone = NULL;
		}
	}
	zone_list_free(zonelist);

	/*
	 * Schedule the next change if needed.
	 */
	if (firstzone) {
		reschedule_enforce(task, t_reschedule, zone_name(firstzone));
		zone_free(firstzone);
	}

	/* Launch signer configuration writer task when one of the
	 * zones indicated that it needs to be written.
	 * TODO: unschedule it first!
	 */
	if (bSignerConfNeedsWriting) {
		task_type *signconf =
			signconf_task(dbconn, "signconf", "signer configurations");
		enf_schedule_task(sockfd,engine,signconf,"signconf");
	} else {
		ods_log_info("[%s] No changes to any signconf file required", module_str);
	}

	/* Launch ds-submit task when one of the updated key states has the
	 * DS_SUBMIT flag set. */
	if (bSubmitToParent) {
		task_type *submit =
			keystate_ds_submit_task(engine);
		enf_schedule_task(sockfd, engine, submit, "ds-submit");
	}


	/* Launch ds-retract task when one of the updated key states has the
	 * DS_RETRACT flag set. */
	if (bRetractFromParent) {
		task_type *retract =
			keystate_ds_retract_task(engine);
		enf_schedule_task(sockfd, engine, retract, "ds-retract");
	}


	return t_reschedule;
}

time_t perform_enforce_lock(int sockfd, engine_type *engine,
	int bForceUpdate, task_type* task, db_connection_t *dbconn)
{
	time_t returntime;
	if (pthread_mutex_trylock(&engine->enforce_lock)) {
		client_printf(sockfd, "An other enforce task is already running."
			" No action taken.\n");
		return 0;
	}
	returntime = perform_enforce(sockfd, engine, bForceUpdate, task,
		dbconn);
	pthread_mutex_unlock(&engine->enforce_lock);
	return returntime;
}

struct enf_task_ctx {
	engine_type *engine;
	int enforce_all;
};

static struct enf_task_ctx enforcer_context;

static task_type*
enforce_task_clean_ctx(task_type *task)
{
	task->context = NULL;
	return NULL;
}

static task_type *
enforce_task_perform(task_type *task)
{
	engine_type *engine = ((struct enf_task_ctx *)task->context)->engine;
	int enforce_all = ((struct enf_task_ctx *)task->context)->enforce_all;
	int return_time = perform_enforce_lock(-1, engine, enforce_all,
		task, task->dbconn);
	enforcer_context.enforce_all = 0;
	if (return_time != -1) return task;
	task_cleanup(task);
	return NULL;
}

task_type *
enforce_task(engine_type *engine, bool all)
{
	task_id what_id;
	const char *what = "enforce";
	const char *who = "next zone";
	struct enf_task_ctx *ctx = &enforcer_context;
	if (!ctx) {
		ods_log_error("Malloc failure, enforce task not scheduled");
		return NULL;
	}
	ctx->engine = engine;
	ctx->enforce_all = all;
	what_id = task_register(what, module_str, enforce_task_perform);
	return task_create(what_id, time_now(), who, what, ctx,
		enforce_task_clean_ctx);
}

int
flush_enforce_task(engine_type *engine, bool enforce_all)
{
	int status;
	task_id what_id;

	printf("flushing\n"); /* TODO output to stdout */
	/* flush (force to run) the enforcer task when it is waiting in the
	 task list. */
	if (!task_id_from_long_name(module_str, &what_id)) {
		/* no such task */
		return 1;
	}

	enforcer_context.enforce_all = enforce_all;

	if (!schedule_flush_type(engine->taskq, what_id)) {
		status = schedule_task(engine->taskq, enforce_task(engine, enforce_all));
		if (status != ODS_STATUS_OK) {
			ods_fatal_exit("[%s] failed to create enforce task", module_str);
			return 0;
		}
	}
	return 1;
}
