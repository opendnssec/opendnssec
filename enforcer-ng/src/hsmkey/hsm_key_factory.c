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

#include "mm.h"
#include "db/hsm_key.h"
#include "db/policy.h"
#include "db/policy_key.h"
#include "db/key_data.h"
#include "shared/log.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "shared/duration.h"
#include "libhsm.h"

#include <math.h>

#include "hsmkey/hsm_key_factory.h"


struct __hsm_key_factory_task {
    engine_type* engine;
    policy_key_t* policy_key;
    policy_t* policy;
    time_t duration;
};

static pthread_once_t __hsm_key_factory_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t* __hsm_key_factory_lock = NULL;

static void hsm_key_factory_init(void) {
    pthread_mutexattr_t attr;

    if (!__hsm_key_factory_lock) {
        if (!(__hsm_key_factory_lock = calloc(1, sizeof(pthread_mutex_t)))
            || pthread_mutexattr_init(&attr)
            || pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)
            || pthread_mutex_init(__hsm_key_factory_lock, &attr))
        {
            ods_log_error("[hsm_key_factory_init] mutex error");
            if (__hsm_key_factory_lock) {
                pthread_mutex_destroy(__hsm_key_factory_lock);
                __hsm_key_factory_lock = NULL;
            }
        }
    }
}

void hsm_key_factory_generate(engine_type* engine, const db_connection_t* connection, const policy_key_t* policy_key, time_t duration) {
    db_clause_list_t* clause_list;
    hsm_key_t* hsm_key = NULL;
    size_t num_keys;
    zone_t* zone = NULL;
    size_t num_zones;
    size_t generate_keys;
    libhsm_key_t *key = NULL;
    hsm_ctx_t *hsm_ctx;
    char* key_id;
    struct engineconfig_repository* hsm;
    char* hsm_err;

    if (!engine) {
        return;
    }
    if (!policy_key) {
        return;
    }

    if (!__hsm_key_factory_lock) {
        pthread_once(&__hsm_key_factory_once, hsm_key_factory_init);
        if (!__hsm_key_factory_lock) {
            ods_log_error("[hsm_key_factory_generate] mutex init error");
            return;
        }
    }
    if (pthread_mutex_lock(__hsm_key_factory_lock)) {
        ods_log_error("[hsm_key_factory_generate] mutex lock error");
        return;
    }

    ods_log_debug("[hsm_key_factory_generate] repository %s role %s", policy_key_repository(policy_key), policy_key_role_text(policy_key));

    /*
     * Get a count of unused keys that match our policy key to determine how
     * many keys we need to make if any
     */
    if (!(clause_list = db_clause_list_new())
        || !(hsm_key = hsm_key_new(connection))
        || !hsm_key_policy_id_clause(clause_list, policy_key_policy_id(policy_key))
        || !hsm_key_state_clause(clause_list, HSM_KEY_STATE_UNUSED)
        || !hsm_key_bits_clause(clause_list, policy_key_bits(policy_key))
        || !hsm_key_algorithm_clause(clause_list, policy_key_algorithm(policy_key))
        || !hsm_key_role_clause(clause_list, policy_key_role(policy_key))
        || !hsm_key_is_revoked_clause(clause_list, 0)
        || !hsm_key_key_type_clause(clause_list, HSM_KEY_KEY_TYPE_RSA)
        || !hsm_key_repository_clause(clause_list, policy_key_repository(policy_key))
        || hsm_key_count(hsm_key, clause_list, &num_keys))
    {
        ods_log_error("[hsm_key_factory_generate] unable to count unused keys, database or memory allocation error");
        hsm_key_free(hsm_key);
        db_clause_list_free(clause_list);
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return;
    }
    db_clause_list_free(clause_list);
    hsm_key_free(hsm_key);

    /*
     * Get the count of zones we have for the policy
     */
    if (!(clause_list = db_clause_list_new())
        || !(zone = zone_new(connection))
        || !zone_policy_id_clause(clause_list, policy_key_policy_id(policy_key))
        || zone_count(zone, clause_list, &num_zones))
    {
        ods_log_error("[hsm_key_factory_generate] unable to count zones for policy, database or memory allocation error");
        zone_free(zone);
        db_clause_list_free(clause_list);
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return;
    }
    zone_free(zone);
    db_clause_list_free(clause_list);

    /*
     * Calculate the number of keys we need to generate now but exit if we do
     * not have to generate any keys
     */
    if (!policy_key_lifetime(policy_key)) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return;
    }
    generate_keys = (size_t)ceil((double)((duration ? duration : engine->config->automatic_keygen_duration))
        / (double)policy_key_lifetime(policy_key)) * num_zones;
    if (num_keys >= generate_keys) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return;
    }
    generate_keys -= num_keys;

    /*
     * Create a HSM context and check that the repository exists
     */
    if (!(hsm_ctx = hsm_create_context())) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return;
    }
    if (!hsm_token_attached(hsm_ctx, policy_key_repository(policy_key))) {
        if ((hsm_err = hsm_get_error(hsm_ctx))) {
            ods_log_error("[hsm_key_factory_generate] unable to check for repository %s, HSM error: %s", policy_key_repository(policy_key), hsm_err);
            free(hsm_err);
        }
        else {
            ods_log_error("[hsm_key_factory_generate] unable to find repository %s in HSM");
        }
        hsm_destroy_context(hsm_ctx);
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return;
    }

    ods_log_debug("[hsm_key_factory_generate] generating %d keys", generate_keys);

    /*
     * Generate a HSM keys
     */
    while (generate_keys--) {
        /*
         * Find the HSM repository to get the backup configuration
         */
        hsm = engine->config->hsm;
        while (hsm) {
            if (!strcmp(hsm->name, policy_key_repository(policy_key))) {
                break;
            }
            hsm = hsm->next;
        }
        if (!hsm) {
            ods_log_error("[hsm_key_factory_generate] unable to find repository %s needed for key generation", policy_key_repository(policy_key));
            hsm_destroy_context(hsm_ctx);
            pthread_mutex_unlock(__hsm_key_factory_lock);
            return;
        }

        if ((key = hsm_generate_rsa_key(hsm_ctx, policy_key_repository(policy_key), policy_key_bits(policy_key)))) {
            /*
             * The key ID is the locator and we check first that we can get it
             */
            if (!(key_id = hsm_get_key_id(hsm_ctx, key))) {
                if ((hsm_err = hsm_get_error(hsm_ctx))) {
                    ods_log_error("[hsm_key_factory_generate] unable to get the ID of the key generated, HSM error: %s", hsm_err);
                    free(hsm_err);
                }
                else {
                    ods_log_error("[hsm_key_factory_generate] unable to get the ID of the key generated");
                }
                libhsm_key_free(key);
                hsm_destroy_context(hsm_ctx);
                pthread_mutex_unlock(__hsm_key_factory_lock);
                return;
            }

            /*
             * Create the HSM key (database object)
             */
            if (!(hsm_key = hsm_key_new(connection))
                || hsm_key_set_algorithm(hsm_key, policy_key_algorithm(policy_key))
                || hsm_key_set_backup(hsm_key, (hsm->require_backup ? HSM_KEY_BACKUP_BACKUP_REQUIRED : HSM_KEY_BACKUP_NO_BACKUP))
                || hsm_key_set_bits(hsm_key, policy_key_bits(policy_key))
                || hsm_key_set_inception(hsm_key, time_now())
                || hsm_key_set_key_type(hsm_key, HSM_KEY_KEY_TYPE_RSA)
                || hsm_key_set_locator(hsm_key, key_id)
                || hsm_key_set_policy_id(hsm_key, policy_key_policy_id(policy_key))
                || hsm_key_set_repository(hsm_key, policy_key_repository(policy_key))
                || hsm_key_set_role(hsm_key, policy_key_role(policy_key))
                || hsm_key_set_state(hsm_key, HSM_KEY_STATE_UNUSED)
                || hsm_key_create(hsm_key))
            {
                ods_log_error("[hsm_key_factory_generate] hsm key creation failed, database or memory error");
                hsm_key_free(hsm_key);
                free(key_id);
                libhsm_key_free(key);
                hsm_destroy_context(hsm_ctx);
                pthread_mutex_unlock(__hsm_key_factory_lock);
                return;
            }

            ods_log_debug("[hsm_key_factory_generate] generated key %s successfully", key_id);

            hsm_key_free(hsm_key);
            free(key_id);
            libhsm_key_free(key);
        }
        else {
            if ((hsm_err = hsm_get_error(hsm_ctx))) {
                ods_log_error("[hsm_key_factory_generate] key generation failed, HSM error: %s", hsm_err);
                free(hsm_err);
            }
            else {
                ods_log_error("[hsm_key_factory_generate] key generation failed");
            }
            hsm_destroy_context(hsm_ctx);
            pthread_mutex_unlock(__hsm_key_factory_lock);
            return;
        }
    }
    hsm_destroy_context(hsm_ctx);
    pthread_mutex_unlock(__hsm_key_factory_lock);
}

void hsm_key_factory_generate_policy(engine_type* engine, const db_connection_t* connection, const policy_t* policy, time_t duration) {
    policy_key_list_t* policy_key_list;
    const policy_key_t* policy_key;

    if (!engine) {
        return;
    }
    if (!policy) {
        return;
    }
    if (!connection) {
        return;
    }

    if (!__hsm_key_factory_lock) {
        pthread_once(&__hsm_key_factory_once, hsm_key_factory_init);
        if (!__hsm_key_factory_lock) {
            ods_log_error("[hsm_key_factory_generate_policy] mutex init error");
            return;
        }
    }
    if (pthread_mutex_lock(__hsm_key_factory_lock)) {
        ods_log_error("[hsm_key_factory_generate_policy] mutex lock error");
        return;
    }

    ods_log_debug("[hsm_key_factory_generate_policy] policy %s", policy_name(policy));

    /*
     * Get all policy keys for the specified policy and generate new keys if
     * needed
     */
    if (!(policy_key_list = policy_key_list_new_get_by_policy_id(connection, policy_id(policy)))) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return;
    }

    while ((policy_key = policy_key_list_next(policy_key_list))) {
        hsm_key_factory_generate(engine, connection, policy_key, duration);
    }
    policy_key_list_free(policy_key_list);
    pthread_mutex_unlock(__hsm_key_factory_lock);
}

void hsm_key_factory_generate_all(engine_type* engine, const db_connection_t* connection, time_t duration) {
    policy_list_t* policy_list;
    const policy_t* policy;
    policy_key_list_t* policy_key_list;
    const policy_key_t* policy_key;

    if (!engine) {
        return;
    }
    if (!connection) {
        return;
    }

    if (!__hsm_key_factory_lock) {
        pthread_once(&__hsm_key_factory_once, hsm_key_factory_init);
        if (!__hsm_key_factory_lock) {
            ods_log_error("[hsm_key_factory_generate_all] mutex init error");
            return;
        }
    }
    if (pthread_mutex_lock(__hsm_key_factory_lock)) {
        ods_log_error("[hsm_key_factory_generate_all] mutex lock error");
        return;
    }

    ods_log_debug("[hsm_key_factory_generate_all] generating keys");

    /*
     * Get all the policies and for each get all the policy keys and generate
     * new keys for them if needed
     */
    if (!(policy_list = policy_list_new_get(connection))) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return;
    }
    while ((policy = policy_list_next(policy_list))) {
        if (!(policy_key_list = policy_key_list_new_get_by_policy_id(connection, policy_id(policy)))) {
            continue;
        }

        while ((policy_key = policy_key_list_next(policy_key_list))) {
            hsm_key_factory_generate(engine, connection, policy_key, duration);
        }
        policy_key_list_free(policy_key_list);
    }
    policy_list_free(policy_list);
    pthread_mutex_unlock(__hsm_key_factory_lock);
}

static task_type* hsm_key_factory_generate_task(task_type *task) {
    struct __hsm_key_factory_task* task2;

    if (!task) {
        return NULL;
    }
    task2 = (struct __hsm_key_factory_task*)task->context;
    if (!task2
        || !(task2->engine)
        || !(task2->policy_key))
    {
        task_cleanup(task);
        if (task2) {
            free(task2);
        }
        return NULL;
    }

    ods_log_debug("[hsm_key_factory_generate_task] generate for policy key [duration: %d]", task2->duration);
    hsm_key_factory_generate(task2->engine, task->dbconn, task2->policy_key, task2->duration);
    ods_log_debug("[hsm_key_factory_generate_task] generate for policy key done");
    policy_key_free(task2->policy_key);
    task_cleanup(task);
    free(task2);
    return NULL;
}

static task_type* hsm_key_factory_generate_policy_task(task_type *task) {
    struct __hsm_key_factory_task* task2;

    if (!task) {
        return NULL;
    }
    task2 = (struct __hsm_key_factory_task*)task->context;
    if (!task2
        || !(task2->engine)
        || !(task2->policy))
    {
        task_cleanup(task);
        if (task2) {
            free(task2);
        }
        return NULL;
    }

    ods_log_debug("[hsm_key_factory_generate_policy_task] generate for policy [duration: %d]", task2->duration);
    hsm_key_factory_generate_policy(task2->engine, task->dbconn, task2->policy, task2->duration);
    ods_log_debug("[hsm_key_factory_generate_policy_task] generate for policy done");
    policy_free(task2->policy);
    task_cleanup(task);
    free(task2);
    return NULL;
}

static task_type* hsm_key_factory_generate_all_task(task_type *task) {
    struct __hsm_key_factory_task* task2;

    if (!task) {
        return NULL;
    }
    task2 = (struct __hsm_key_factory_task*)task->context;
    if (!task->dbconn
        || !task2
        || !task2->engine)
    {
        task_cleanup(task);
        if (task2) {
            free(task2);
        }
        return NULL;
    }

    ods_log_debug("[hsm_key_factory_generate_all_task] generate for all policies [duration: %d]", task2->duration);
    hsm_key_factory_generate_all(task2->engine, task->dbconn, task2->duration);
    ods_log_debug("[hsm_key_factory_generate_all_task] generate for all policies done");
    task_cleanup(task);
    free(task2);
    return NULL;
}

int hsm_key_factory_schedule_generate(engine_type* engine,
    const policy_key_t* policy_key_orig, time_t duration)
{
    task_id what_id;
    policy_key_t* policy_key;
    task_type* task = NULL;
    struct __hsm_key_factory_task* task2 = NULL;

    if (!(task2 = calloc(1, sizeof(struct __hsm_key_factory_task)))) {
        return 1;
    }
    if (!(policy_key = policy_key_new_copy(policy_key_orig))) {
        free(task2);
        return 1;
    }

    task2->engine = engine;
    task2->policy_key = policy_key;
    task2->duration = duration;

    what_id = task_register("hsmkeygen", "hsm_key_factory_schedule_generation", hsm_key_factory_generate_task);
    if (what_id == TASK_NONE
        || !(task = task_create(what_id, time_now(), "policy_key", task2))
        || schedule_task(engine->taskq, task) != ODS_STATUS_OK)
    {
        free(task2);
        policy_key_free(policy_key);
        task_cleanup(task);
        return 1;
    }
    return 0;
}

int hsm_key_factory_schedule_generate_policy(engine_type* engine,
    const policy_t* policy_orig, time_t duration)
{
    task_id what_id;
    policy_t* policy;
    task_type* task = NULL;
    struct __hsm_key_factory_task* task2 = NULL;

    if (!(task2 = calloc(1, sizeof(struct __hsm_key_factory_task)))) {
        return 1;
    }
    if (!(policy = policy_new_copy(policy_orig))) {
        free(task2);
        return 1;
    }

    task2->engine = engine;
    task2->policy = policy;
    task2->duration = duration;

    what_id = task_register("hsmkeygen", "hsm_key_factory_schedule_generation_policy", hsm_key_factory_generate_policy_task);
    if (what_id == TASK_NONE
        || !(task = task_create(what_id, time_now(), "policy", task2))
        || schedule_task(engine->taskq, task) != ODS_STATUS_OK)
    {
        free(task2);
        policy_free(policy);
        task_cleanup(task);
        return 1;
    }
    return 0;
}

int hsm_key_factory_schedule_generate_all(engine_type* engine, time_t duration) {
    task_id what_id;
    task_type* task = NULL;
    struct __hsm_key_factory_task* task2 = NULL;

    if (!(task2 = calloc(1, sizeof(struct __hsm_key_factory_task)))) {
        return 1;
    }

    task2->engine = engine;
    task2->duration = duration;

    what_id = task_register("hsmkeygen", "hsm_key_factory_schedule_generation", hsm_key_factory_generate_all_task);
    if (what_id == TASK_NONE
        || !(task = task_create(what_id, time_now(), "all policies", task2))
        || schedule_task(engine->taskq, task) != ODS_STATUS_OK)
    {
        free(task2);
        task_cleanup(task);
        return 1;
    }
    return 0;
}

hsm_key_t* hsm_key_factory_get_key(engine_type* engine,
    const db_connection_t* connection, const policy_key_t* policy_key,
    hsm_key_state_t hsm_key_state)
{
    db_clause_list_t* clause_list;
    hsm_key_list_t* hsm_key_list;
    hsm_key_t* hsm_key;

    if (!connection) {
        return NULL;
    }
    if (!policy_key) {
        return NULL;
    }
    if (hsm_key_state != HSM_KEY_STATE_PRIVATE
        && hsm_key_state != HSM_KEY_STATE_SHARED)
    {
        return NULL;
    }

    ods_log_debug("[hsm_key_factory_get_key] get %s key", (hsm_key_state == HSM_KEY_STATE_PRIVATE ? "private" : "shared"));

    /*
     * Get a list of unused HSM keys matching our requirments
     */
    if (!(clause_list = db_clause_list_new())
        || !hsm_key_policy_id_clause(clause_list, policy_key_policy_id(policy_key))
        || !hsm_key_state_clause(clause_list, HSM_KEY_STATE_UNUSED)
        || !hsm_key_bits_clause(clause_list, policy_key_bits(policy_key))
        || !hsm_key_algorithm_clause(clause_list, policy_key_algorithm(policy_key))
        || !hsm_key_role_clause(clause_list, policy_key_role(policy_key))
        || !hsm_key_is_revoked_clause(clause_list, 0)
        || !hsm_key_key_type_clause(clause_list, HSM_KEY_KEY_TYPE_RSA)
        || !hsm_key_repository_clause(clause_list, policy_key_repository(policy_key))
        || !(hsm_key_list = hsm_key_list_new_get_by_clauses(connection, clause_list)))
    {
        ods_log_error("[hsm_key_factory_get_key] unable to list keys, database or memory allocation error");
        db_clause_list_free(clause_list);
        return NULL;
    }
    db_clause_list_free(clause_list);

    /*
     * If there are no keys returned in the list we schedule generation and
     * return NULL
     */
    if (!(hsm_key = hsm_key_list_get_next(hsm_key_list))) {
        ods_log_warning("[hsm_key_factory_get_key] no keys available");
        hsm_key_factory_schedule_generate(engine, policy_key, 0);
        hsm_key_list_free(hsm_key_list);
        return NULL;
    }
    hsm_key_list_free(hsm_key_list);

    /*
     * Update the state of the returned HSM key
     */
    if (hsm_key_set_state(hsm_key, hsm_key_state)
        || hsm_key_update(hsm_key))
    {
        ods_log_debug("[hsm_key_factory_get_key] unable to update fetched key");
        hsm_key_free(hsm_key);
        return NULL;
    }

    /*
     * Schedule generation because we used up a key and return the HSM key
     */
    ods_log_debug("[hsm_key_factory_get_key] key allocated");
    hsm_key_factory_schedule_generate(engine, policy_key, 0);
    return hsm_key;
}

int hsm_key_factory_release_key_id(const db_value_t* hsm_key_id, const db_connection_t* connection) {
    hsm_key_t* hsm_key;
    db_clause_list_t* clause_list = NULL;
    key_data_t* key_data = NULL;
    size_t count;

    if (!hsm_key_id) {
        return 1;
    }
    if (!connection) {
        return 1;
    }

    if (!(hsm_key = hsm_key_new(connection))
        || !(clause_list = db_clause_list_new())
        || !(key_data = key_data_new(connection))
        || !key_data_hsm_key_id_clause(clause_list, hsm_key_id)
        || key_data_count(key_data, clause_list, &count))
    {
        ods_log_debug("[hsm_key_factory_release_key_id] unable to check usage of hsm_key, database or memory allocation error");
        key_data_free(key_data);
        db_clause_list_free(clause_list);
        hsm_key_free(hsm_key);
        return 1;
    }
    key_data_free(key_data);
    db_clause_list_free(clause_list);

    if (count > 0) {
        ods_log_debug("[hsm_key_factory_release_key_id] unable to release hsm_key, in use");
        hsm_key_free(hsm_key);
        return 0;
    }

    if (hsm_key_get_by_id(hsm_key, hsm_key_id)) {
        ods_log_debug("[hsm_key_factory_release_key_id] unable to fetch hsm_key");
        hsm_key_free(hsm_key);
        return 1;
    }

    if (hsm_key_state(hsm_key) == HSM_KEY_STATE_DELETE) {
        ods_log_debug("[hsm_key_factory_release_key_id] hsm_key already DELETE (?)");
        hsm_key_free(hsm_key);
        return 0;
    }

    if (hsm_key_set_state(hsm_key, HSM_KEY_STATE_DELETE)
        || hsm_key_update(hsm_key))
    {
        ods_log_debug("[hsm_key_factory_release_key_id] unable to change hsm_key state to DELETE");
        hsm_key_free(hsm_key);
        return 1;
    }
    ods_log_debug("[hsm_key_factory_release_key_id] key %s marked DELETE", hsm_key_locator(hsm_key));

    hsm_key_free(hsm_key);
    return 0;
}

int hsm_key_factory_release_key(hsm_key_t* hsm_key, const db_connection_t* connection) {
    db_clause_list_t* clause_list = NULL;
    key_data_t* key_data = NULL;
    size_t count;

    if (!hsm_key) {
        return 1;
    }
    if (!connection) {
        return 1;
    }

    if (!(clause_list = db_clause_list_new())
        || !(key_data = key_data_new(connection))
        || !key_data_hsm_key_id_clause(clause_list, hsm_key_id(hsm_key))
        || key_data_count(key_data, clause_list, &count))
    {
        ods_log_debug("[hsm_key_factory_release_key] unable to check usage of hsm_key, database or memory allocation error");
        key_data_free(key_data);
        db_clause_list_free(clause_list);
        return 1;
    }
    key_data_free(key_data);
    db_clause_list_free(clause_list);

    if (count > 0) {
        ods_log_debug("[hsm_key_factory_release_key] unable to release hsm_key, in use");
        return 0;
    }

    if (hsm_key_state(hsm_key) == HSM_KEY_STATE_DELETE) {
        ods_log_debug("[hsm_key_factory_release_key] hsm_key already DELETE (?)");
        return 0;
    }

    if (hsm_key_set_state(hsm_key, HSM_KEY_STATE_DELETE)
        || hsm_key_update(hsm_key))
    {
        ods_log_debug("[hsm_key_factory_release_key] unable to change hsm_key state to DELETE");
        return 1;
    }
    ods_log_debug("[hsm_key_factory_release_key] key %s marked DELETE", hsm_key_locator(hsm_key));

    return 0;
}
