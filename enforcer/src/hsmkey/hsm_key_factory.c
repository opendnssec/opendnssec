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

#include "db/dbw.h"
#include "db/hsm_key.h"
#include "db/policy.h"
#include "db/policy_key.h"
/*#include "db/key_data.h"*/
#include "log.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "enforcer/enforce_task.h"
#include "daemon/engine.h"
#include "duration.h"
#include "libhsm.h"
#include "presentation.h"

#include <math.h>
#include <pthread.h>

#include "hsmkey/hsm_key_factory.h"


struct __hsm_key_factory_task {
    engine_type* engine;
    /* YBS: I find it scary that these database objects are carried
     * around in our scheduler. Is that safe? */
    /*policy_key_t* policy_key;*/
    /*policy_t* policy;*/
    int id; /* id of record */
    char *policyname;
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

/* 1 if hsmkey and policykey match AND hsmkey is unused. */
static int
hsmkey_matches_policykey(struct dbw_hsmkey *hsmkey, struct dbw_policykey *policykey)
{
    return !strcmp(hsmkey->repository, policykey->repository)
        &&  hsmkey->is_revoked == 0
        &&  hsmkey->algorithm  == policykey->algorithm
        &&  hsmkey->state      == HSM_KEY_STATE_UNUSED
        &&  hsmkey->bits       == policykey->bits
        &&  hsmkey->role       == policykey->role
        &&  hsmkey->bits       == policykey->bits;
}

static int /*0 success 1 failure */
hsm_key_factory_generate(engine_type* engine, const db_connection_t* connection,
    struct dbw_list *policies, struct dbw_policy *policy,
    struct dbw_policykey *policykey, time_t duration)
{
    char *hsm_err;
    if (!policykey->lifetime) return 1; /* Keys life forever. */
    char *repository = policykey->repository;

    /* Find the HSM repository to get the backup configuration*/
    hsm_repository_t *hsm;
    hsm = hsm_find_repository(engine->config->repositories, repository);
    if (!hsm) {
        ods_log_error("[hsm_key_factory_generate] unable to find "
            "repository %s needed for key generation", repository);
        return 1;
    }

    /* Grab lock */
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

    /* Count number of hsmkeys for this policy that match policykey */
    int num_keys = 0;
    for (size_t h = 0; h < policy->hsmkey_count; h++) {
        struct dbw_hsmkey *hsmkey = policy->hsmkey[h];
        if (hsmkey_matches_policykey(hsmkey, policykey)) {
            num_keys++; /* we have found an available hsmkey */
        }
    }

    duration = (duration ? duration : engine->config->automatic_keygen_duration);
    ssize_t generate_keys = (ssize_t)ceil(duration / (double)policykey->lifetime);
    if (policy->zone_count == 0 || (ssize_t)num_keys >= generate_keys) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return 0;
    }

    /* LOGGING */
    ods_log_info("%u zone(s) found on policy \"%s\"", policy->zone_count, policy->name);
    ods_log_info("[hsm_key_factory_generate] %lu keys needed for %u "
        "zones covering %lld seconds, generating %lu keys for policy %s",
        generate_keys, policy->zone_count, (long long)duration,
        (unsigned long)(generate_keys-num_keys), /* safe. num_keys < generate_keys */
        policy->name);
    generate_keys -= num_keys;
    ods_log_info("%ld new %s(s) (%d bits) need to be created.", (long) generate_keys, present_key_role(policykey->role), policykey->bits);

     /*Create a HSM context and check that the repository exists*/
    hsm_ctx_t *hsm_ctx;
    if (!(hsm_ctx = hsm_create_context())) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return 1;
    }
    if (!hsm_token_attached(hsm_ctx, repository)) {
        if ((hsm_err = hsm_get_error(hsm_ctx))) {
            ods_log_error("[hsm_key_factory_generate] unable to check for"
                " repository %s, HSM error: %s", repository, hsm_err);
            free(hsm_err);
        } else {
            ods_log_error("[hsm_key_factory_generate] unable to find "
                "repository %s in HSM", repository);
        }
        hsm_destroy_context(hsm_ctx);
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return 1;
    }


    /*Generate a HSM keys*/
    while (generate_keys--) {
        libhsm_key_t *key;
        switch(policykey->algorithm) {
            case LDNS_DSA: /* */
                key = hsm_generate_dsa_key(hsm_ctx, repository, policykey->bits);
                break;
            case LDNS_RSASHA1:
            case LDNS_RSASHA1_NSEC3:
            case LDNS_RSASHA256:
            case LDNS_RSASHA512:
                key = hsm_generate_rsa_key(hsm_ctx, repository, policykey->bits);
                break;
            case LDNS_ECC_GOST:
                key = hsm_generate_gost_key(hsm_ctx, repository);
                break;
            case LDNS_ECDSAP256SHA256:
                key = hsm_generate_ecdsa_key(hsm_ctx, repository, "P-256");
                break;
            case LDNS_ECDSAP384SHA384:
                key = hsm_generate_ecdsa_key(hsm_ctx, repository, "P-384");
                break;
            default:
                key = NULL;
        }

        if (key) {
            char *key_id; /*The key ID is the locator and we check first that we can get it*/
            if (!(key_id = hsm_get_key_id(hsm_ctx, key))) {
                if ((hsm_err = hsm_get_error(hsm_ctx))) {
                    ods_log_error("[hsm_key_factory_generate] unable to get "
                        "the ID of the key generated, HSM error: %s", hsm_err);
                    free(hsm_err);
                } else {
                    ods_log_error("[hsm_key_factory_generate] unable to get "
                        "the ID of the key generated");
                }
                libhsm_key_free(key);
                hsm_destroy_context(hsm_ctx);
                pthread_mutex_unlock(__hsm_key_factory_lock);
                return 1;
            }

             /*Create the HSM key (database object)*/
            struct dbw_hsmkey *hsmkey = malloc(sizeof (struct dbw_hsmkey));
            if (!hsmkey) {
                ods_log_error("[hsm_key_factory_generate] hsm key creation"
                   " failed, database or memory error");
                free(key_id);
                libhsm_key_free(key);
                hsm_destroy_context(hsm_ctx);
                pthread_mutex_unlock(__hsm_key_factory_lock);
                return 1;
            }
            hsmkey->algorithm = policykey->algorithm;
            hsmkey->backup = (hsm->require_backup ?
                HSM_KEY_BACKUP_BACKUP_REQUIRED : HSM_KEY_BACKUP_NO_BACKUP);
            hsmkey->bits = policykey->bits;
            hsmkey->inception = time_now();
            hsmkey->key_type = HSM_KEY_KEY_TYPE_RSA; /* I don't think we need this, also it is incorrect */
            hsmkey->locator = key_id;
            hsmkey->policy_id = policykey->policy_id;
            hsmkey->repository = strdup(policykey->repository);
            hsmkey->role = policykey->role;
            hsmkey->state = HSM_KEY_STATE_UNUSED;
            hsmkey->is_revoked = 0;
            hsmkey->id = -1; /* Just set it to something that stands out */
            hsmkey->dirty = DBW_INSERT;
            hsmkey->key_count = 0;
            hsmkey->policy = policy;
            dbw_policies_add_hsmkey(policies, hsmkey);
            int b = dbw_update(connection, policies, 1);
            /* TODO free this thing */

            ods_log_debug("[hsm_key_factory_generate] generated key %s successfully", key_id);

            libhsm_key_free(key);
        } else {
            if ((hsm_err = hsm_get_error(hsm_ctx))) {
                ods_log_error("[hsm_key_factory_generate] key generation "
                    "failed, HSM error: %s", hsm_err);
                free(hsm_err);
            } else {
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

int
hsm_key_factory_generate_policy(engine_type* engine, const db_connection_t* connection,
    struct dbw_list *policies, struct dbw_policy *policy, time_t duration)
{
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
    /*
     * Get all policy keys for the specified policy and generate new keys if
     * needed
     */
    ods_log_debug("[hsm_key_factory_generate_policy] policy %s", policy->name);
    for (size_t k = 0; k < policy->policykey_count; k++) {
        struct dbw_policykey *policykey = policy->policykey[k];
        error |= hsm_key_factory_generate(engine, connection, policies,
            policy, policykey, duration);
    }
    pthread_mutex_unlock(__hsm_key_factory_lock);
    return error;
}

int
hsm_key_factory_generate_all(engine_type* engine, db_connection_t* connection,
    time_t duration)
{
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
    struct dbw_list *policies = dbw_policies_all(connection);
    if (!policies) {
        pthread_mutex_unlock(__hsm_key_factory_lock);
        return 1;
    }

    int error = 0;
    for (size_t p = 0; p < policies->n; p++) {
        struct dbw_policy *policy = (struct dbw_policy *)policies->set[p];
        for (size_t k = 0; k < policy->policykey_count; k++) {
            struct dbw_policykey *policykey = policy->policykey[k];
            error |= hsm_key_factory_generate(engine, connection, policies, policy,
                policykey, duration);
        }
    }
    dbw_list_free(policies);
    pthread_mutex_unlock(__hsm_key_factory_lock);
    return error;
}

static time_t
hsm_key_factory_generate_cb(task_type* task, char const *owner, void *userdata,
    void *context)
{
    struct __hsm_key_factory_task* task2;
    db_connection_t* dbconn = (db_connection_t*) context;
    (void)owner;

    if (!userdata) return schedule_SUCCESS;
    task2 = (struct __hsm_key_factory_task*)userdata;
    char *policyname = task2->policyname;
    int id = task2->id;

    struct dbw_list *policies = dbw_policies_all_filtered(dbconn, policyname, NULL, 0);
    for (size_t p = 0; p < policies->n; p++) {
        struct dbw_policy *policy = (struct dbw_policy *)policies->set[p];
        int flush = 0;
        for (size_t k = 0; k < policy->policykey_count; k++) {
            struct dbw_policykey *policykey = policy->policykey[k];
            if (policykey->id == id || id == -1) {
                int error = hsm_key_factory_generate(task2->engine, dbconn,
                    policies, policy, policykey, task2->duration);
                flush = !error && task2->reschedule_enforce_task;
            }
        }
        if (flush) {
            enforce_task_flush_policy(task2->engine, policy);
        }
    }
    dbw_list_free(policies);
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
hsm_key_factory_schedule_generate(engine_type* engine, const char *policyname,
    int policykey_id, time_t duration, int reschedule_enforce_task)
{
    /*policy_key_t* policy_key;*/
    task_type* task;
    struct __hsm_key_factory_task* task2;

    if (!(task2 = calloc(1, sizeof(struct __hsm_key_factory_task)))) {
        return 1;
    }
    task2->engine = engine;
    task2->duration = duration;
    task2->id = policykey_id;
    task2->policyname = policyname?strdup(policyname):NULL;
    task2->reschedule_enforce_task = reschedule_enforce_task;

    task = task_create(strdup("hsm_key_factory_schedule_generation"),
        TASK_CLASS_ENFORCER, TASK_TYPE_HSMKEYGEN,
        hsm_key_factory_generate_cb, task2,
        free, time_now());

    if (!task) {
        free(task2->policyname);
        free(task2);
        return 1;
    }

    if (schedule_task(engine->taskq, task, 1, 0) != ODS_STATUS_OK) {
        free(task2->policyname);
        task_destroy(task); /* will free task2 as well */
        return 1;
    }
    return 0;
}

int
hsm_key_factory_schedule_generate_policy(engine_type* engine,
    const char *policyname, time_t duration)
{
    return hsm_key_factory_schedule_generate(engine, policyname, -1, duration, 1);
}

int
hsm_key_factory_schedule_generate_all(engine_type* engine, time_t duration)
{
    return hsm_key_factory_schedule_generate(engine, NULL, -1, duration, 1);
}

struct dbw_hsmkey *
hsm_key_factory_get_key(engine_type *engine, struct dbw_db *db,
    struct dbw_policykey *pkey)
{
    struct dbw_policy *policy = pkey->policy;
    ods_log_debug("[hsm_key_factory_get_key] get %s key",
        (policy->keys_shared ?  "shared" : "private"));

    /* Get a list of unused HSM keys matching our requirments */
    struct dbw_hsmkey *hkey = NULL;
    for (size_t h = 0; h < policy->hsmkey_count; h++) {
        struct dbw_hsmkey *hsmkey = policy->hsmkey[h];
        if (hsmkey->state != DBW_HSMKEY_UNUSED) continue;
        if (hsmkey->bits != pkey->bits) continue;
        if (hsmkey->algorithm != pkey->algorithm) continue;
        if (hsmkey->role != pkey->role) continue;
        if (hsmkey->is_revoked != 0) continue;
        if (strcmp(hsmkey->repository, pkey->repository)) continue;
        if (hsmkey->bits != pkey->bits) continue;
        /* we have found an available hsmkey */
        hkey = hsmkey;
        break;
    }

     /* If there are no keys returned in the list we schedule generation and
      * return NULL */
    if (!hkey) {
        ods_log_warning("[hsm_key_factory_get_key] no keys available");
        hsm_key_factory_schedule_generate(engine, policy->name, pkey->id, 0, 1);
        return NULL;
    }
     /*Update the state of the returned HSM key*/
    hkey->state = policy->keys_shared? DBW_HSMKEY_SHARED : DBW_HSMKEY_PRIVATE;
    hkey->dirty = DBW_UPDATE;

    /*Schedule generation because we used up a key and return the HSM key*/
    ods_log_debug("[hsm_key_factory_get_key] key allocated");
    hsm_key_factory_schedule_generate(engine, policy->name, pkey->id, 0, 0);
    return hkey;
}


void
hsm_key_factory_release_key(struct dbw_hsmkey *hsmkey, struct dbw_key *key)
{
    int c = hsmkey->key_count;
    if (c == 1 && hsmkey->key[0] == key) c--;
    if (c > 0) {
        ods_log_debug("[hsm_key_factory_release_key] unable to release hsm_key, in use");
    } else {
        ods_log_debug("[hsm_key_factory_release_key] key %s marked DELETE", hsmkey->locator);
        hsmkey->state = DBW_HSMKEY_DELETE;
        hsmkey->dirty = DBW_UPDATE;
    }
}

