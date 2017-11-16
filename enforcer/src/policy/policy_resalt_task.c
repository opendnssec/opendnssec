/*
 * Copyright (c) 2011 Surfnet 
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2011 OpenDNSSEC AB (svb)
 * Copyright (c) 2014 NLnet Labs
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

/* On MacOSX arc4random is only available when we 
   undef _ANSI_SOURCE and define _DARWIN_C_SOURCE. */
#ifdef __APPLE__
	#undef _ANSI_SOURCE
	#define _DARWIN_C_SOURCE 1
#endif
/* Make arc4random visible on FreeBSD */
#ifndef __BSD_VISIBLE
	#define __BSD_VISIBLE 1
#endif

#include "duration.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "scheduler/task.h"
#include "daemon/engine.h"
#include "db/dbw.h"

#include <stdlib.h>

#include "policy/policy_resalt_task.h"
#include "signconf/signconf_task.h"

static const char *module_str = "policy_resalt_task";
static const time_t TIME_INF = ((time_t)-1);

/**
 * Generate salt of len bytes, make sure prng is seeded.
 * arc4random needs no seed.
 * \param buf, buffer at least len bytes wide
 * \param len, len of bytes of entropy to store in buf
 */
static void
generate_salt(char *buf, int len)
{
#ifdef HAVE_ARC4RANDOM
	arc4random_buf(buf, len);
#else
	int i;
	/* Not really sure how many bits we get, but pseudo randomness
	 * is cheap. */
	for (i = 0; i < len; i++)
		buf[i] = rand() & 0xFF;
#endif
}

/**
 * convert buf to hexstring
 * \param buf, input
 * \param len, lenght of buf
 * \param[out] out, resulting hex string must be at least 2*len+1 lenght
 */
static void
to_hex(const char *buf, int len, char *out)
{
	const char *h = "0123456789abcdef";
	int i;

	for (i = 0; i < len; i++) {
		out[2*i] = h[(buf[i]>>4) & 0x0F];
		out[2*i+1] = h[buf[i] & 0x0F];
	}
	out[2*len] = 0;
}

/**
 * Generate new salt for specified policy. Schedules signconf task
 * when done.
 */
static time_t
perform_policy_resalt(task_type* task, char const *policyname, void *userdata,
    void *context)
{
    db_connection_t *dbconn = (db_connection_t *) context;
    time_t resalt_time, now = time_now();
    char salt[255], salthex[511];
    engine_type *engine = (engine_type *)userdata;

    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) {
        ods_log_error("[%s] Unable to get list of policies from database",
            module_str);
        return schedule_DEFER;
    }
    struct dbw_policy *policy = dbw_get_policy(db, policyname);
    if (!policy) {
        dbw_free(db);
        return -1;
    }

    if (policy->denial_salt_length <= 0 || policy->denial_salt_length > 255) {
        ods_log_error("[%s] policy %s has an invalid salt length. "
            "Must be in range [0..255]", module_str, policy->name);
        dbw_free(db);
        return schedule_SUCCESS; /* no point in rescheduling */
    }

#ifndef HAVE_ARC4RANDOM
    srand(now);
#endif
    generate_salt(salt, policy->denial_salt_length);
    to_hex(salt, policy->denial_salt_length, salthex);
    policy->denial_salt = strdup(salthex);
    policy->denial_salt_last_change = now;
    dbw_mark_dirty((struct dbrow *)policy);

    if (policy->denial_resalt <= 0)
        resalt_time = -1;
    else
        resalt_time = now + policy->denial_resalt;
    int r = dbw_commit(db);
    dbw_free(db);
    if (r) {
        ods_log_error("[%s] unable to update DB", module_str);
    } else {
        signconf_task_flush_policy(engine, dbconn, policy->name);
        ods_log_debug("[%s] policy %s resalted successfully", module_str, policyname);
    }
    return resalt_time;
}

static task_type *
policy_resalt_task(char const *owner, engine_type *engine, time_t t)
{
    return task_create(strdup(owner), TASK_CLASS_ENFORCER, TASK_TYPE_RESALT,
        perform_policy_resalt, engine, NULL, t);
}

int
resalt_task_flush(engine_type *engine, db_connection_t *dbconn,
    const char *policyname)
{
    int status = ODS_STATUS_OK;

    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) {
        ods_log_error("[%s] Unable to get list of policies from database",
            module_str);
        return ODS_STATUS_DB_ERR;
    }
    for (size_t p = 0; p < db->policies->n; p++) {
        struct dbw_policy *policy = (struct dbw_policy *)db->policies->set[p];
        if (policyname && strcmp(policy->name, policyname)) continue;
        if  (policy->denial_type == POLICY_DENIAL_TYPE_NSEC3 && !policy->passthrough) {
            task_type *task = policy_resalt_task(policyname, engine, time_now());
            status = schedule_task(engine->taskq, task, 1, 0);
        }
    }
    dbw_free(db);
    return status;
}

int
resalt_task_schedule(engine_type *engine, db_connection_t *dbconn)
{
    task_type *task;
    int status = ODS_STATUS_OK;

    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) {
        ods_log_error("[%s] Unable to get list of policies from database",
            module_str);
        return ODS_STATUS_DB_ERR;
    }
    for (size_t p = 0; p < db->policies->n; p++) {
        struct dbw_policy *policy = (struct dbw_policy *)db->policies->set[p];
        if  (policy->denial_type != POLICY_DENIAL_TYPE_NSEC3 || policy->passthrough)
            continue;
        time_t resalt_time = policy->denial_salt_last_change + policy->denial_resalt;
        task = policy_resalt_task(policy->name, engine, resalt_time);
        status |= schedule_task(engine->taskq, task, 1, 0);
    }
    dbw_free(db);
    return status;
}
