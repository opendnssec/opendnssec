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

#include "shared/duration.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "scheduler/task.h"
#include "daemon/engine.h"
#include "db/policy.h"

#include <stdlib.h>

#include "policy/policy_resalt_task.h"

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

time_t 
perform_policy_resalt(int sockfd, engine_type* engine,
	db_connection_t *dbconn)
{
	policy_list_t *pol_list;
	policy_t *policy;
	time_t schedule_time = TIME_INF, now = time_now(), resalt_time;
	char salt[255], salthex[511];
	int saltlength;
	db_clause_list_t* clause_list;
	(void) engine; (void) sockfd;

#ifndef HAVE_ARC4RANDOM
	srand(now);
#endif

	if (!(clause_list = db_clause_list_new())
	    || !policy_denial_type_clause(clause_list, POLICY_DENIAL_TYPE_NSEC3)
	    || !(pol_list = policy_list_new_get_by_clauses(dbconn, clause_list)))
	{
	    db_clause_list_free(clause_list);
		ods_log_error("[%s] retrying in 60 seconds", module_str);
		return now + 60;
	}
    db_clause_list_free(clause_list);
	
	while ((policy = policy_list_get_next(pol_list))) {
		resalt_time = policy_denial_salt_last_change(policy) +
			policy_denial_resalt(policy);
		if (now > resalt_time) {
			saltlength = policy_denial_salt_length(policy);
			if (saltlength <= 0 || saltlength > 255) {
				ods_log_error("[%s] policy %s has an invalid salt length. "
					"Must be in range [0..255]", module_str, policy_name(policy));
				policy_free(policy);
				continue; /* no need to schedule for this policy */
			}
			/* Yes, we need to resalt this policy */
			generate_salt(salt, saltlength);
			to_hex(salt, saltlength, salthex);

			if(policy_set_denial_salt(policy, salthex) ||
			   policy_set_denial_salt_last_change(policy, now) ||
			   policy_update(policy))
			{
				ods_log_error("[%s] db error", module_str);
				policy_free(policy);
				break;
			}
			resalt_time = now + policy_denial_resalt(policy);
			ods_log_debug("[%s] policy %s resalted successfully", module_str, policy_name(policy));
		}
		if (resalt_time < schedule_time || schedule_time == TIME_INF)
			schedule_time = resalt_time;
		policy_free(policy);
	}
	policy_list_free(pol_list);
	ods_log_debug("[%s] policies have been updated", module_str);
	return schedule_time;
}

static task_type * 
policy_resalt_task_perform(task_type *task)
{
	task->backoff = 0;
	task->when = perform_policy_resalt(-1,(engine_type *)task->context,
		task->dbconn);
	if (task->when == TIME_INF) {
		/* This means there is no need to schedule resalt again.
		 * We do it anyway as it takes less administration. */
		task->when = time_now() + 30*60;
	}
	return task;
}

task_type *
policy_resalt_task(engine_type* engine)
{
	task_id what_id = task_register("resalt",
		"policy_resalt_task_perform", policy_resalt_task_perform);
	return task_create(what_id, time_now(), "policies", engine);
}
