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

#ifndef _HSM_KEY_FACTORY_H_
#define _HSM_KEY_FACTORY_H_

#include "db/hsm_key.h"
#include "db/policy_key.h"
#include "daemon/engine.h"

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Schedule a task to generate keys for a specific policy key.
 * \param[in] engine an engine_type.
 * \prama[in] policy_key_orig a policy_key_t pointer to the policy key we will
 * generate keys for.
 * \param[in] duration a time_t specifying the duration to generate keys from,
 * if its zero then the duration from conf.xml is taken.
 * \return non-zero on error.
 */
int hsm_key_factory_schedule_generate(engine_type* engine,
    const policy_key_t* policy_key_orig, time_t duration);

/**
 * Schedule a task to generate keys for a specific policy.
 * \param[in] engine an engine_type.
 * \prama[in] policy_orig a policy_t pointer to the policy we will generate keys
 * for.
 * \param[in] duration a time_t specifying the duration to generate keys from,
 * if its zero then the duration from conf.xml is taken.
 * \return non-zero on error.
 */
int hsm_key_factory_schedule_generate_policy(engine_type* engine,
    const policy_t* policy_orig, time_t duration);

/**
 * Schedule a task to generate keys for all policies and policy keys we
 * currently have.
 * \param[in] engine an engine_type.
 * \param[in] duration a time_t specifying the duration to generate keys from,
 * if its zero then the duration from conf.xml is taken.
 * \return non-zero on error.
 */
int hsm_key_factory_schedule_generate_all(engine_type* engine, time_t duration);

/**
 * Allocate a private or shared HSM key for the policy key provided. This will
 * also schedule a task for generating more keys if needed.
 * \param[in] engine an engine_type.
 * \param[in] connection a database connection.
 * \param[in] policy_key a policy key.
 * \param[in] hsm_key_state indicate if its a private or shared key that should
 * be fetched (HSM_KEY_STATE_PRIVATE | HSM_KEY_STATE_SHARED).
 * \return an allocated HSM key or NULL on error or if there are no unused keys
 * available for allocation right now.
 */
hsm_key_t* hsm_key_factory_get_key(engine_type* engine,
    const db_connection_t* connection, const policy_key_t* policy_key,
    hsm_key_state_t hsm_key_state);

/**
 * Release a key, if its not used anyore it will be marked DELETE.
 * \param[in] hsm_key_id a db_value_t pointer with the hsm_key database id.
 * \return non-zero on error.
 */
int hsm_key_factory_release_key_id(const db_value_t* hsm_key_id,
    const db_connection_t* connection);

#ifdef __cplusplus
}
#endif

#endif /* _HSM_KEY_FACTORY_H_ */
