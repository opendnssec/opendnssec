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
#include "db/policy.h"

#include <stdlib.h>

#include "policy/policy_resalt_task.h"
#include "signconf/signconf_task.h"

static const char *module_str = "policy_resalt_task";

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
performresalt(task_type* task, char const *policyname, void *userdata,
	void *context, int do_now)
{
	policy_t *policy;
        db_connection_t *dbconn = (db_connection_t *) context;
	time_t resalt_time, now = time_now();
	char salt[255], salthex[511];
	int saltlength;
	engine_type *engine = (engine_type *)userdata;
	
	policy = policy_new_get_by_name(dbconn, policyname);
	if (!policy) {
		ods_log_error("[%s] could not fetch policy %s from database,"
			" rescheduling", module_str, policyname);
		/* TODO: figure out if it was a database error. if it is truly
		 * not in database we should just return schedule_SUCCESS */
		return schedule_DEFER;
	}

	if  (policy_denial_type(policy) != POLICY_DENIAL_TYPE_NSEC3
		|| policy_passthrough(policy))
	{
		policy_free(policy);
		return schedule_SUCCESS;
	}
	resalt_time = policy_denial_salt_last_change(policy) +
		policy_denial_resalt(policy);

	if (now >= resalt_time || do_now) {
		saltlength = policy_denial_salt_length(policy);
		if (saltlength < 0 || saltlength > 255) {
			ods_log_error("[%s] policy %s has an invalid salt length. "
				"Must be in range [0..255]", module_str, policy_name(policy));
			policy_free(policy);
			return schedule_SUCCESS; /* no point in rescheduling */
		}

#ifndef HAVE_ARC4RANDOM
		srand(now);
#endif

		/* Yes, we need to resalt this policy */
		generate_salt(salt, saltlength);
		to_hex(salt, saltlength, salthex);

		if(policy_set_denial_salt(policy, salthex) ||
			policy_set_denial_salt_last_change(policy, now) ||
			policy_update(policy))
		{
			ods_log_error("[%s] db error", module_str);
			policy_free(policy);
			return schedule_DEFER;
		}
		resalt_time = now + policy_denial_resalt(policy);
		ods_log_debug("[%s] policy %s resalted successfully", module_str, policy_name(policy));
		signconf_task_flush_policy(engine, dbconn, policy);
        }
	if (policy_denial_resalt(policy) <= 0) resalt_time = -1;
	policy_free(policy);
	return resalt_time;
}

static time_t 
perform_policy_resalt(task_type* task, char const *policyname, void *userdata, void *context)
{
    return performresalt(task, policyname, userdata, context, 0);
}

static time_t 
perform_policy_forceresalt(task_type* task, char const *policyname, void *userdata, void *context)
{
    return performresalt(task, policyname, userdata, context, 1);
}

/*
 * Schedule resalt tasks for all policies. 
 */
int
flush_resalt_task_all(engine_type *engine, db_connection_t *dbconn)
{

	policy_list_t *policylist;
	const policy_t *policy;
	task_type *task;
	int status = ODS_STATUS_OK;

	policylist = policy_list_new(dbconn);
	if (policy_list_get(policylist)) {
		ods_log_error("[%s] Unable to get list of policies from database",
			module_str);
		policy_list_free(policylist);
		return ODS_STATUS_ERR;
	}

	while ((policy = policy_list_next(policylist))) {
            task = task_create(strdup(policy_name(policy)), TASK_CLASS_ENFORCER, TASK_TYPE_RESALT, perform_policy_resalt, engine, NULL, time_now());
            status |= schedule_task(engine->taskq, task, 1, 0);
	}
	policy_list_free(policylist);
	return status;
}

int
flush_resalt_task_now(engine_type *engine, db_connection_t *dbconn)
{

	policy_list_t *policylist;
	const policy_t *policy;
	task_type *task;
	int status = ODS_STATUS_OK;

	policylist = policy_list_new(dbconn);
	if (policy_list_get(policylist)) {
		ods_log_error("[%s] Unable to get list of policies from database",
			module_str);
		policy_list_free(policylist);
		return ODS_STATUS_ERR;
	}

	while ((policy = policy_list_next(policylist))) {
            task = task_create(strdup(policy_name(policy)), TASK_CLASS_ENFORCER, TASK_TYPE_RESALT, perform_policy_forceresalt, engine, NULL, time_now());
            status |= schedule_task(engine->taskq, task, 1, 0);
	}
	policy_list_free(policylist);
	return status;
}
