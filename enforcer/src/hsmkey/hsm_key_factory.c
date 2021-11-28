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

#include "db/hsm_key.h"
#include "db/policy.h"
#include "db/policy_key.h"
#include "db/key_data.h"
#include "log.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "enforcer/enforce_task.h"
#include "daemon/engine.h"
#include "duration.h"
#include "libhsm.h"

#include <math.h>
#include <pthread.h>
#include <ldns/ldns.h>
#include <ldns/util.h>

#include "hsmkey/hsm_key_factory.h"


struct __hsm_key_factory_task {
    engine_type* engine;
    /* YBS: I find it scary that these database objects are carried
     * around in our scheduler. Is that safe? */
    policy_key_t* policy_key;
    policy_t* policy;
    time_t duration;
    int reschedule_enforce_task;
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
            /* TODO: This should be fatal */
            ods_log_error("[hsm_key_factory_init] mutex error");
            if (__hsm_key_factory_lock) {
                pthread_mutex_destroy(__hsm_key_factory_lock);
                free(__hsm_key_factory_lock);
                __hsm_key_factory_lock = NULL;
            }
        }
    }
}

void hsm_key_factory_deinit(void)
{
    if (__hsm_key_factory_lock) {
        (void)pthread_mutex_destroy(__hsm_key_factory_lock);
        free(__hsm_key_factory_lock);
        __hsm_key_factory_lock = NULL;
    }
}

int
hsm_key_factory_generate(engine_type* engine, const db_connection_t* connection,
    const policy_t* policy, const policy_key_t* policy_key, time_t duration)
{
    db_clause_list_t* clause_list;
    hsm_key_t* hsm_key = NULL;
    size_t num_keys;
    zone_db_t* zone = NULL;
    size_t num_zones;
    ssize_t generate_keys;
    libhsm_key_t *key = NULL;
    hsm_ctx_t *hsm_ctx;
    char* key_id;
    hsm_repository_t* hsm;
    char* hsm_err;

    if (!engine) {
        return 1;
    }
    if (!policy_key) {
        return 1;
    }

    if (!__hsm_key_factory_lock) {
        pthread_once(&__hsm_key_factory_once, hsm_key_factory_init);
        if (!__hsm_key_factory_lock) {
            ods_log_error("[hsm_key_factory_generate] mutex init error");
            return 1;
        }
    }
    if (pthread_mutex_lock(__hsm_key_factory_lock)) {
        ods_log_error("[hsm_key_factory_generate] mutex lock error");
        return 1;
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
        || !hsm_key_role_clause(clause_list, (hsm_key_role_t)policy_key_role(policy_key))
        || !hsm_key_is_revoked_clause(clause_list, 0)
        || !hsm_key_key_type_clause(clause_list, HSM_KEY_KEY_TYPE_RSA)
        || !hsm_key_repository_clause(clause_list, policy_key_repository(policy_key))
        || hsm_key_count(hsm_key, clause_list, &num_keys))
    {
        ods_log_error("[hsm_key_factory_generate] unable to count unused keys, database or memory allocation error");
        hsm_key_free(hsm_key);
        db_clause_list_free(clause_list);
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return 1;
    }
    db_clause_list_free(clause_list);
    hsm_key_free(hsm_key);

    /*
     * Get the count of zones we have for the policy
     */
    if (!(clause_list = db_clause_list_new())
        || !(zone = zone_db_new(connection))
        || !zone_db_policy_id_clause(clause_list, policy_key_policy_id(policy_key))
        || zone_db_count(zone, clause_list, &num_zones))
    {
        ods_log_error("[hsm_key_factory_generate] unable to count zones for policy, database or memory allocation error");
        zone_db_free(zone);
        db_clause_list_free(clause_list);
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return 1;
    }
    zone_db_free(zone);
    db_clause_list_free(clause_list);

    /*
     * Calculate the number of keys we need to generate now but exit if we do
     * not have to generate any keys
     */
    if (!policy_key_lifetime(policy_key)) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return 1;
    }
    /* OPENDNSSEC-690: this function is called per-zone, and the policy id differs per zone, thus the
     * keys generated will never be shared.
     * Additionally, this used to calculate the number of keys to be generated based upon the
     * duration, times the number of zones.  Not only is this wrong when using shared keys, but
     * also for non-shared keys, this function would be called per-zone, with a different id for each
     * zone.
     */
    duration = (duration ? duration : engine->config->automatic_keygen_duration);
    generate_keys = (ssize_t)ceil(duration / (double)policy_key_lifetime(policy_key));
    if (num_zones == 0 || (ssize_t)num_keys >= generate_keys) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return 0;
    }

    if (policy != NULL) {
        ods_log_info("%lu zone(s) found on policy \"%s\"", num_zones, policy_name(policy));
    } else {
        ods_log_info("%lu zone(s) found on policy <unknown>", num_zones);
    }
    ods_log_info("[hsm_key_factory_generate] %lu keys needed for %lu "
        "zones covering %lld seconds, generating %lu keys for policy %s",
        generate_keys, num_zones, (long long)duration,
        (unsigned long)(generate_keys-num_keys), /* This is safe because we checked num_keys < generate_keys */
        policy_name(policy));
    generate_keys -= num_keys;
    ods_log_info("%ld new %s(s) (%d bits) need to be created.", (long) generate_keys, policy_key_role_text(policy_key), policy_key_bits(policy_key));

    /*
     * Create a HSM context and check that the repository exists
     */
    if (!(hsm_ctx = hsm_create_context())) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return 1;
    }
    if (!hsm_token_attached(hsm_ctx, policy_key_repository(policy_key))) {
        if ((hsm_err = hsm_get_error(hsm_ctx))) {
            ods_log_error("[hsm_key_factory_generate] unable to check for repository %s, HSM error: %s", policy_key_repository(policy_key), hsm_err);
            free(hsm_err);
        }
        else {
            ods_log_error("[hsm_key_factory_generate] unable to find repository %s in HSM", policy_key_repository(policy_key));
        }
        hsm_destroy_context(hsm_ctx);
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return 1;
    }

    /*
     * Generate a HSM keys
     */
    while (generate_keys--) {
        /*
         * Find the HSM repository to get the backup configuration
         */
        hsm = engine->config->repositories;
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
            return 1;
        }

        switch(policy_key_algorithm(policy_key)) {
            case LDNS_DSA: /* */
                key = hsm_generate_dsa_key(hsm_ctx, policy_key_repository(policy_key), policy_key_bits(policy_key));
                break;
            case LDNS_RSASHA1:
            case LDNS_RSASHA1_NSEC3:
            case LDNS_RSASHA256:
            case LDNS_RSASHA512:
                key = hsm_generate_rsa_key(hsm_ctx, policy_key_repository(policy_key), policy_key_bits(policy_key));
                break;
            case LDNS_ECC_GOST:
                key = hsm_generate_gost_key(hsm_ctx, policy_key_repository(policy_key));
                break;
            case LDNS_ECDSAP256SHA256:
                key = hsm_generate_ecdsa_key(hsm_ctx, policy_key_repository(policy_key), "P-256");
                break;
            case LDNS_ECDSAP384SHA384:
                key = hsm_generate_ecdsa_key(hsm_ctx, policy_key_repository(policy_key), "P-384");
                break;
#if USE_ED25519
            case LDNS_ED25519:
                key = hsm_generate_eddsa_key(hsm_ctx, policy_key_repository(policy_key), "edwards25519");
                break;
#endif
#if USE_ED448
            case LDNS_ED448:
                key = hsm_generate_eddsa_key(hsm_ctx, policy_key_repository(policy_key), "edwards448");
                break;
#endif
            default:
                key = NULL;
        }

        if (key) {
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
                return 1;
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
                || hsm_key_set_role(hsm_key, (hsm_key_role_t)policy_key_role(policy_key))
                || hsm_key_set_state(hsm_key, HSM_KEY_STATE_UNUSED)
                || hsm_key_create(hsm_key))
            {
                ods_log_error("[hsm_key_factory_generate] hsm key creation failed, database or memory error");
                hsm_key_free(hsm_key);
                free(key_id);
                free(key);
                hsm_destroy_context(hsm_ctx);
                pthread_mutex_unlock(__hsm_key_factory_lock);
                return 1;
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
            return 1;
        }
    }
    hsm_destroy_context(hsm_ctx);
    pthread_mutex_unlock(__hsm_key_factory_lock);
    return 0;
}

int hsm_key_factory_generate_policy(engine_type* engine, const db_connection_t* connection, const policy_t* policy, time_t duration) {
    policy_key_list_t* policy_key_list;
    const policy_key_t* policy_key;
    int error = 0;

    if (!engine || !policy || !connection) {
        return 1;
    }

    if (!__hsm_key_factory_lock) {
        pthread_once(&__hsm_key_factory_once, hsm_key_factory_init);
        if (!__hsm_key_factory_lock) {
            ods_log_error("[hsm_key_factory_generate_policy] mutex init error");
            return 1;
        }
    }
    if (pthread_mutex_lock(__hsm_key_factory_lock)) {
        ods_log_error("[hsm_key_factory_generate_policy] mutex lock error");
        return 1;
    }

    ods_log_debug("[hsm_key_factory_generate_policy] policy %s", policy_name(policy));

    /*
     * Get all policy keys for the specified policy and generate new keys if
     * needed
     */
    if (!(policy_key_list = policy_key_list_new_get_by_policy_id(connection, policy_id(policy)))) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return 1;
    }

    while ((policy_key = policy_key_list_next(policy_key_list))) {
        error |= hsm_key_factory_generate(engine, connection, policy, policy_key, duration);
    }
    policy_key_list_free(policy_key_list);
    pthread_mutex_unlock(__hsm_key_factory_lock);
    return error;
}

int hsm_key_factory_generate_all(engine_type* engine, const db_connection_t* connection, time_t duration) {
    policy_list_t* policy_list;
    const policy_t* policy;
    policy_key_list_t* policy_key_list;
    const policy_key_t* policy_key;
    int error;

    if (!engine || !connection) {
        return 1;
    }

    if (!__hsm_key_factory_lock) {
        pthread_once(&__hsm_key_factory_once, hsm_key_factory_init);
        if (!__hsm_key_factory_lock) {
            ods_log_error("[hsm_key_factory_generate_all] mutex init error");
            return 1;
        }
    }
    if (pthread_mutex_lock(__hsm_key_factory_lock)) {
        ods_log_error("[hsm_key_factory_generate_all] mutex lock error");
        return 1;
    }

    ods_log_debug("[hsm_key_factory_generate_all] generating keys");

    /*
     * Get all the policies and for each get all the policy keys and generate
     * new keys for them if needed
     */
    if (!(policy_list = policy_list_new_get(connection))) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return 1;
    }
    error = 0;
    while ((policy = policy_list_next(policy_list))) {
        if (!(policy_key_list = policy_key_list_new_get_by_policy_id(connection, policy_id(policy)))) {
            continue;
        }

        while ((policy_key = policy_key_list_next(policy_key_list))) {
            error |= hsm_key_factory_generate(engine, connection, policy, policy_key, duration);
        }
        policy_key_list_free(policy_key_list);
    }
    policy_list_free(policy_list);
    pthread_mutex_unlock(__hsm_key_factory_lock);
    return error;
}

static time_t
hsm_key_factory_generate_cb(task_type* task, char const *owner, void* userdata, void* context)
{
    struct __hsm_key_factory_task* task2;
    policy_t* policy;
    db_connection_t *dbconn = (db_connection_t*) context;
    (void)owner;
    int error;

    if (!userdata) {
        return schedule_SUCCESS;
    }
    task2 = (struct __hsm_key_factory_task*) userdata;

    if ((policy = policy_new(dbconn)) != NULL) {
        if (policy_get_by_id(policy, policy_key_policy_id(task2->policy_key))) {
            policy_free(policy);
            policy = NULL;
        }
    }

    ods_log_debug("[hsm_key_factory_generate_cb] generate for policy key [duration: %lu]", (unsigned long)task2->duration);
    error = hsm_key_factory_generate(task2->engine, dbconn, policy, task2->policy_key, task2->duration);
    ods_log_debug("[hsm_key_factory_generate_cb] generate for policy key done");
    policy_key_free(task2->policy_key);
    task2->policy_key = NULL;
    if (task2->reschedule_enforce_task && policy && !error)
        enforce_task_flush_policy(task2->engine, dbconn, policy);
    policy_free(policy);
    return schedule_SUCCESS;
}

static time_t
hsm_key_factory_generate_policy_cb(task_type* task, char const *owner, void *userdata,
    void *context)
{
    struct __hsm_key_factory_task* task2;
    db_connection_t* dbconn = (db_connection_t*) context;
    (void)owner;
    int error;

    if (!userdata) {
        return schedule_SUCCESS;
    }
    task2 = (struct __hsm_key_factory_task*)userdata;

    ods_log_debug("[hsm_key_factory_generate_policy_cb] generate for policy [duration: %lu]", (unsigned long) task2->duration);
    error = hsm_key_factory_generate_policy(task2->engine, dbconn, task2->policy, task2->duration);
    ods_log_debug("[hsm_key_factory_generate_policy_cb] generate for policy done");
    if (task2->reschedule_enforce_task && task2->policy && !error)
        enforce_task_flush_policy(task2->engine, dbconn, task2->policy);
    return schedule_SUCCESS;
}

static time_t
hsm_key_factory_generate_all_cb(task_type* task, char const *owner, void *userdata,
    void* context)
{
    struct __hsm_key_factory_task* task2;
    db_connection_t *dbconn = (db_connection_t *) context;
    (void)owner;
    int error;
    
    if (!userdata) {
        return schedule_SUCCESS;
    }
    task2 = (struct __hsm_key_factory_task*)userdata;
    
    ods_log_debug("[hsm_key_factory_generate_all_cb] generate for all policies [duration: %lu]", (unsigned long)task2->duration);
    error = hsm_key_factory_generate_all(task2->engine, dbconn, task2->duration);
    ods_log_debug("[hsm_key_factory_generate_all_cb] generate for all policies done");
    if (task2->reschedule_enforce_task && !error)
        enforce_task_flush_all(task2->engine, dbconn);
    return schedule_SUCCESS;
}

/**
 * Schedule a task to generate keys for a specific policy key.
 * \param[in] engine an engine_type.
 * \prama[in] policy_key_orig a policy_key_t pointer to the policy key we will
 * generate keys for.
 * \param[in] duration a time_t specifying the duration to generate keys from,
 * if its zero then the duration from conf.xml is taken.
 * \return non-zero on error.
 */
static int
hsm_key_factory_schedule_generate(engine_type* engine,
    const policy_key_t* policy_key_orig, time_t duration,
    int reschedule_enforce_task)
{
    policy_key_t* policy_key;
    task_type* task;
    struct __hsm_key_factory_task* task2 = NULL;

    if (!(task2 = calloc(1, sizeof(struct __hsm_key_factory_task)))) {
        return 1;
    }
    if (!(policy_key = policy_key_new_copy(policy_key_orig))) {
        free(task2);
        return 1;
    }

    task2->engine = engine;
    task2->duration = duration;
    task2->policy_key = policy_key;
    task2->policy = NULL;
    task2->reschedule_enforce_task = reschedule_enforce_task;

    task = task_create(strdup("hsm_key_factory_schedule_generation"),
        TASK_CLASS_ENFORCER, TASK_TYPE_HSMKEYGEN,
        hsm_key_factory_generate_cb, task2,
        free, time_now());

    if (schedule_task(engine->taskq, task, 1, 0) != ODS_STATUS_OK) {
        if (!task) {
            free(task2);
            policy_key_free(policy_key);
        }
        task_destroy(task);
        return 1;
    }
    return 0;
}

int
hsm_key_factory_schedule_generate_policy(engine_type* engine,
    const policy_t* policy_orig, time_t duration)
{
    policy_t* policy;
    task_type* task;
    struct __hsm_key_factory_task* task2 = NULL;

    if (!(task2 = calloc(1, sizeof(struct __hsm_key_factory_task)))) {
        return 1;
    }
    if (!(policy = policy_new_copy(policy_orig))) {
        free(task2);
        return 1;
    }

    task2->engine = engine;
    task2->duration = duration;
    task2->policy_key = NULL;
    task2->policy = policy;
    task2->reschedule_enforce_task = 1;

    task = task_create(strdup("hsm_key_factory_schedule_generation_policy"),
        TASK_CLASS_ENFORCER, TASK_TYPE_HSMKEYGEN,
        hsm_key_factory_generate_policy_cb, task2,
        free, time_now());

    if (schedule_task(engine->taskq, task, 1, 0) != ODS_STATUS_OK) {
        if (!task) {
            free(task2);
            policy_free(policy);
        }
        task_destroy(task);
        return 1;
    }
    return 0;
}

int
hsm_key_factory_schedule_generate_all(engine_type* engine, time_t duration)
{
    task_type* task;
    struct __hsm_key_factory_task* task2 = NULL;

    if (!(task2 = calloc(1, sizeof(struct __hsm_key_factory_task)))) {
        return 1;
    }

    task2->engine = engine;
    task2->duration = duration;
    task2->policy_key = NULL;
    task2->policy = NULL;
    task2->reschedule_enforce_task = 1;

    task = task_create(strdup("hsm_key_factory_schedule_generation"),
        TASK_CLASS_ENFORCER, TASK_TYPE_HSMKEYGEN,
        hsm_key_factory_generate_all_cb, task2,
        free, time_now());

    if (schedule_task(engine->taskq, task, 1, 0) != ODS_STATUS_OK) {
        if (!task) {
            free(task2);
        }
        task_destroy(task);
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
        || !hsm_key_role_clause(clause_list, (hsm_key_role_t)policy_key_role(policy_key))
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
        if (!engine->config->manual_keygen)
            hsm_key_factory_schedule_generate(engine, policy_key, 0, 1);
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
    if (!engine->config->manual_keygen)
        hsm_key_factory_schedule_generate(engine, policy_key, 0, 0);
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

int
hsm_key_factory_delete_key(const db_connection_t* connection)
{
    db_clause_list_t* clause_list;
    hsm_key_list_t* hsm_key_list;
    libhsm_key_t* hsmkey;
    hsm_key_t* hsm_key;
    hsm_ctx_t *hsm_ctx;
    int count = 0;

    if (!(hsm_ctx = hsm_create_context())) {
        /* might be a transient error, not important for this action so do not log */
        return -1;
    }
    
    ods_log_error("[hsm_key_factory_delete_key] looking for keys to purge from HSM");
    if (!(clause_list = db_clause_list_new())
        || !hsm_key_state_clause(clause_list, HSM_KEY_STATE_DELETE)
        //|| !hsm_key_is_revoked_clause(clause_list, 0)
        || !(hsm_key_list = hsm_key_list_new_get_by_clauses(connection, clause_list)))
    {
        ods_log_error("[hsm_key_factory_delete_key] unable to list keys, database or memory allocation error");
        db_clause_list_free(clause_list);
        return -2;
    }
    db_clause_list_free(clause_list);

    while((hsm_key = hsm_key_list_get_next(hsm_key_list))) {
        hsmkey = hsm_find_key_by_id(hsm_ctx, hsm_key_locator(hsm_key));
        if(hsm_remove_key(hsm_ctx, hsmkey)) {
            // report on error
            ods_log_error("[hsm_key_factory_delete_key] unable to remove key %s", hsm_key_locator(hsm_key));
        } else {
            clause_list = db_clause_list_new();
            db_clause_t* clause;
            clause = db_clause_new();
            db_clause_set_field(clause, "locator");
            db_clause_set_type(clause, DB_CLAUSE_EQUAL);
            db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND);
            db_value_from_text(db_clause_get_value(clause), hsm_key_locator(hsm_key));
            db_clause_list_add(clause_list, clause);
            clause = db_clause_new();
            db_clause_set_field(clause, "rev");
            db_clause_set_type(clause, DB_CLAUSE_EQUAL);
            db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND);
            db_value_copy(db_clause_get_value(clause), &(hsm_key->rev));
            db_clause_list_add(clause_list, clause);
            db_object_delete(hsm_key->dbo, clause_list);
            db_clause_list_free(clause_list);
            ods_log_info("[hsm_key_factory_get_key] removing key %s from HSM", hsm_key_locator(hsm_key));
            ++count;
        }
    }
    hsm_key_list_free(hsm_key_list);
    hsm_destroy_context(hsm_ctx);
    return count;
}
