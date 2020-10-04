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
#include "log.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "enforcer/enforce_task.h"
#include "daemon/engine.h"
#include "duration.h"
#include "libhsm.h"

#include <pthread.h>
#include <math.h>

#include "hsmkey/hsm_key_factory.h"

/* List of database ID's of recently assigned non-shared hsmkeys. So we can
 * avoid races assigning the same key twice. This avoids backoffs.
 * For shared keys this problem isn't as pronounced since they will generally
 * not need a completely new key */
#define RU_COUNT 8
static int ru_nonshared_keys[RU_COUNT];
static int ru_index;

struct __hsm_key_factory_task {
    engine_type* engine;
    int id; /* id of record */
    char *policyname;
    time_t duration;
    int reschedule_enforce_task;
};

struct generate_request {
    int policykey_id;
    int count;
    char *zonename;
    struct generate_request *next;
};

static pthread_once_t __hsm_key_factory_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t* __hsm_key_factory_lock = NULL;
static struct generate_request *genq = NULL;

static void hsm_key_factory_init(void)
{
    pthread_mutexattr_t attr;
    for (int i = 0; i < RU_COUNT; i++)
        ru_nonshared_keys[i] = -1;
    ru_index = 0;
    genq = NULL;

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

static void
genq_free(struct generate_request *req)
{
    free(req->zonename);
    free(req);
}

static void
genq_push(int policykey_id, const char *zonename, int count)
{
    pthread_once(&__hsm_key_factory_once, hsm_key_factory_init);
    struct generate_request *req = calloc(1, sizeof (struct generate_request));
    if (!req) return;
    if (zonename) req->zonename = strdup(zonename);
    req->policykey_id = policykey_id;
    req->count = count;

    (void) pthread_mutex_lock(__hsm_key_factory_lock);
        /* If zone is explicitly mentioned drop request. */
        struct generate_request *p = genq;
        while (p) {
            if (((zonename && p->zonename && !strcmp(zonename, p->zonename)) ||
                (!zonename && !p->zonename)) && p->policykey_id == policykey_id)
            {
                genq_free(req);
                (void) pthread_mutex_unlock(__hsm_key_factory_lock);
                return;
            }
            p = p->next;
        }
        req->next = genq;
        genq = req;
    (void) pthread_mutex_unlock(__hsm_key_factory_lock);
}

static struct generate_request *
genq_pop()
{
    pthread_once(&__hsm_key_factory_once, hsm_key_factory_init);
    (void) pthread_mutex_lock(__hsm_key_factory_lock);
        struct generate_request *req = genq;
        if (genq) genq = genq->next;
    (void) pthread_mutex_unlock(__hsm_key_factory_lock);
    return req;
}

static int
genq_exists(const char *zonename)
{
    int exists = 0;
    pthread_once(&__hsm_key_factory_once, hsm_key_factory_init);
    (void) pthread_mutex_lock(__hsm_key_factory_lock);
        struct generate_request *p = genq;
        while (p) {
            if (p->zonename && !strcmp(zonename, p->zonename)) {
                exists = 1;
                break;
            }
            p = p->next;
        }
    (void) pthread_mutex_unlock(__hsm_key_factory_lock);
    return exists;
}

/* 1 if hsmkey and policykey match AND hsmkey is unused. */
static int
hsmkey_matches_policykey(struct dbw_hsmkey *hsmkey, struct dbw_policykey *policykey)
{
    return !strcmp(hsmkey->repository, policykey->repository)
        &&  hsmkey->is_revoked == 0
        &&  hsmkey->algorithm  == policykey->algorithm
        &&  hsmkey->state      == DBW_HSMKEY_UNUSED
        &&  hsmkey->bits       == policykey->bits
        &&  hsmkey->role       == policykey->role
        &&  hsmkey->bits       == policykey->bits;
}

static void
log_hsm_error(hsm_ctx_t *ctx, const char *msg)
{
    ods_log_error("%s", msg);
    char *hsm_err = hsm_get_error(ctx);
    if (hsm_err) {
        ods_log_error("[hsm_key_factory_generate] %s", hsm_err);
        free(hsm_err);
    }
}

char *
generate_libhsm_key(hsm_ctx_t *ctx, struct dbw_policykey *policykey)
{
    libhsm_key_t *key;
    switch(policykey->algorithm) {
        case LDNS_DSA: /* */
            key = hsm_generate_dsa_key(ctx, policykey->repository, policykey->bits);
            break;
        case LDNS_RSASHA1:
        case LDNS_RSASHA1_NSEC3:
        case LDNS_RSASHA256:
        case LDNS_RSASHA512:
            key = hsm_generate_rsa_key(ctx, policykey->repository, policykey->bits);
            break;
        case LDNS_ECC_GOST:
            key = hsm_generate_gost_key(ctx, policykey->repository);
            break;
        case LDNS_ECDSAP256SHA256:
            key = hsm_generate_ecdsa_key(ctx, policykey->repository, "P-256");
            break;
        case LDNS_ECDSAP384SHA384:
            key = hsm_generate_ecdsa_key(ctx, policykey->repository, "P-384");
            break;
        case LDNS_ED25519:
            key = hsm_generate_eddsa_key(ctx, policykey->repository, "edwards25519");
            break;
        case LDNS_ED448:
            key = hsm_generate_eddsa_key(ctx, policykey->repository, "edwards448");
            break;
        default:
            ods_log_error("[hsmkey_factory] Unsupported algorithm (%d) requested.", policykey->algorithm);
            key = NULL;
    }
    if (!key) {
        ods_log_error("[hsmkey_factory] error generating key for policy %s.", policykey->policy->name);
        return NULL;
    }
    char *locator = hsm_get_key_id(ctx, key);
    libhsm_key_free(key);
    return locator;
}

static struct dbw_hsmkey *
create_hsmkey(struct dbw_policykey *policykey, char *locator, int require_backup)
{
     /*Create the HSM key (database object)*/
    struct dbw_hsmkey *hsmkey = calloc(1, sizeof (struct dbw_hsmkey));
    if (!hsmkey) {
        ods_log_error("[hsm_key_factory_generate] hsm key creation"
           " failed, database or memory error");
        return NULL;
    }
    hsmkey->algorithm = policykey->algorithm;
    hsmkey->backup = require_backup;
    hsmkey->bits = policykey->bits;
    hsmkey->inception = time_now();
    hsmkey->key_type = HSM_KEY_KEY_TYPE_RSA; /* I don't think we need this, also it is incorrect */
    hsmkey->locator = locator;
    hsmkey->policy_id = policykey->policy_id;
    hsmkey->repository = strdup(policykey->repository);
    hsmkey->role = policykey->role;
    hsmkey->state = HSM_KEY_STATE_UNUSED;
    hsmkey->is_revoked = 0;
    hsmkey->dirty = DBW_INSERT;
    hsmkey->key_count = 0;
    return hsmkey;
}

static int /*0 success 1 failure */
generate_one_key(engine_type *engine, struct dbw_db *db,
    struct dbw_policykey *policykey)
{

     /*Create a HSM context and check that the repository exists*/
    hsm_ctx_t *hsm_ctx;
    if (!(hsm_ctx = hsm_create_context())) {
        return 1;
    }
    if (!hsm_token_attached(hsm_ctx, policykey->repository)) {
        log_hsm_error(hsm_ctx, "unable to find repository");
        hsm_destroy_context(hsm_ctx);
        return 1;
    }
    /* Find the HSM repository to get the backup configuration*/
    struct engineconfig_repository *hsm;
    hsm = hsm_find_repository(engine->config->repositories, policykey->repository);
    if (!hsm) {
        ods_log_error("[hsm_key_factory_generate] unable to find "
            "repository %s needed for key generation", policykey->repository);
        hsm_destroy_context(hsm_ctx);
        return 1;
    }
    char *locator = generate_libhsm_key(hsm_ctx, policykey);
    if (!locator) {
        log_hsm_error(hsm_ctx, "[hsm_key_factory] failed to generate key");
        hsm_destroy_context(hsm_ctx);
        return 1;
    }
    struct dbw_hsmkey *hsmkey = create_hsmkey(policykey, locator,
            hsm->require_backup? HSM_KEY_BACKUP_BACKUP_REQUIRED : HSM_KEY_BACKUP_NO_BACKUP);
    if (!hsmkey) {
        ods_log_error("[hsm_key_factory_generate] hsm key creation"
                   " failed, database or memory error");
        free(locator);
        hsm_destroy_context(hsm_ctx);
        return 1;
    }
    if (!dbw_add_hsmkey(db, policykey->policy, hsmkey))//TODO return val
        ods_log_debug("[hsm_key_factory_generate] generated key %s successfully", locator);

    hsm_destroy_context(hsm_ctx);
    return 0;
}

static int
unassigned_key_count(struct dbw_policykey *pkey)
{
    int count = 0;
    for (size_t hk = 0; hk < pkey->policy->hsmkey_count; hk++) {
        struct dbw_hsmkey *hkey = pkey->policy->hsmkey[hk];
        if (hkey->algorithm != pkey->algorithm) continue;
        if (hkey->state != DBW_HSMKEY_UNUSED) continue;
        if (hkey->bits != pkey->bits) continue;
        if (hkey->role != pkey->role) continue;
        if (hkey->is_revoked) continue;
        if (strcasecmp(hkey->repository, pkey->repository)) continue;
        count++;
    }
    return count;
}

static time_t
generate_cb(task_type* task, char const *owner, void *userdata,
    void *context)
{
    db_connection_t* dbconn = (db_connection_t*) context;
    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) return schedule_DEFER;
    engine_type* engine = userdata;

    int duration_time = engine->config->automatic_keygen_duration;

    while (genq) {
        struct generate_request *req = genq_pop();
        struct dbw_policykey *pkey = dbw_get_policykey(db, req->policykey_id);
        if (!pkey) {
            genq_free(req);
            continue;
        }
        if (req->count == -1 && duration_time) {
            /* generate as much as needed to satisfy policy */
            int multiplier = pkey->policy->keys_shared? 1 : pkey->policy->zone_count;
            req->count = ceil(duration_time / (double)pkey->lifetime);
            req->count *= multiplier;
            req->count -= unassigned_key_count(pkey);
        }
        int error = 0;
        int keys_generated = 0;
        for (int i = 0; i < req->count; i++) {
            ods_log_info("Generating %s for policy %s.\n",
                dbw_enum2txt(dbw_key_role_txt, pkey->role), pkey->policy->name);
            error += generate_one_key(engine, db, pkey);
            keys_generated++;
        }
        if (!error && keys_generated) {
            if (req->zonename) {
                struct dbw_zone *zone = dbw_get_zone(db, req->zonename);
                if (zone) zone->scratch = 1;
            } else {
                pkey->policy->scratch = 1;
            }
        }
    }
    (void)dbw_commit(db);
    for (size_t p = 0; p < db->policies->n; p++) {
        struct dbw_policy *policy = (struct dbw_policy *)db->policies->set[p];
        if (policy->scratch)
            enforce_task_flush_policy(engine, policy);
    }
    for (size_t z = 0; z < db->zones->n; z++) {
        struct dbw_zone *zone = (struct dbw_zone *)db->zones->set[z];
        if (zone->scratch && !zone->policy->scratch) {
            enforce_task_flush_zone(engine, zone->name);
        }
    }
    dbw_free(db);
    (void) pthread_mutex_lock(__hsm_key_factory_lock);
        struct generate_request *req = genq;
    (void) pthread_mutex_unlock(__hsm_key_factory_lock);
    return req ? schedule_IMMEDIATELY : schedule_SUCCESS;
}

/* schedule generate task for zone. 1 single key */
static int
schedule_generate(engine_type* engine)
{
    task_type* task;
    char *id_str = strdup("[key factory]");
    task = task_create(id_str, TASK_CLASS_ENFORCER, TASK_TYPE_HSMKEYGEN,
        generate_cb, engine, NULL, schedule_IMMEDIATELY);
    if (!task) {
        free(id_str);
        return 1;
    }
    if (schedule_task(engine->taskq, task, SCHEDULE_REPLACE, 0) != ODS_STATUS_OK) {
        task_destroy(task);
        return 1;
    }
    return 0;
}

void
hsm_key_factory_schedule(engine_type *engine, int id, int count)
{
    genq_push(id, NULL, count);
    schedule_generate(engine);
}

static int
in_lru(int id)
{
    for (int i = 0; i < RU_COUNT; i++) {
        if (ru_nonshared_keys[i] == id) return 1;
    }
    return 0;
}

struct dbw_hsmkey *
hsm_key_factory_get_key(engine_type *engine, struct dbw_db *db,
    struct dbw_policykey *pkey, struct dbw_zone *zone)
{
    struct dbw_policy *policy = pkey->policy;
    ods_log_debug("[hsm_key_factory_get_key] get %s key",
        (policy->keys_shared ?  "shared" : "private"));

    /* Get a list of unused HSM keys matching our requirements */
    pthread_once(&__hsm_key_factory_once, hsm_key_factory_init);
    (void) pthread_mutex_lock(__hsm_key_factory_lock);
        struct dbw_hsmkey *hkey = NULL;
        for (size_t h = 0; h < policy->hsmkey_count; h++) {
            struct dbw_hsmkey *hsmkey = policy->hsmkey[h];
            if (hsmkey->state != DBW_HSMKEY_UNUSED) continue;
            if (hsmkey->bits != pkey->bits) continue;
            if (hsmkey->algorithm != pkey->algorithm) continue;
            if (hsmkey->role != pkey->role) continue;
            if (hsmkey->is_revoked != 0) continue;
            if (strcmp(hsmkey->repository, pkey->repository)) continue;
            /* we have found an available hsmkey */
            /* did anyone else grab it? */
            if (!policy->keys_shared && in_lru(hsmkey->id)) {
                continue;
            }
            hkey = hsmkey;
            ru_nonshared_keys[(++ru_index) % RU_COUNT] = hsmkey->id;
            break;
        }
        /* Slowly clear out the list when no key is found. */
        if (!hkey) ru_nonshared_keys[(++ru_index) % RU_COUNT] = -1;
    (void) pthread_mutex_unlock(__hsm_key_factory_lock);
     /* If there are no keys returned in the list we schedule generation and
      * return NULL */
    if (!hkey) {
        ods_log_warning("[hsm_key_factory_get_key] no keys available");
        if (!engine->config->manual_keygen) {
            if (!policy->keys_shared) {
                genq_push(pkey->id, zone->name, 1);
            } else {
                genq_push(pkey->id, NULL, 1);
            }
            schedule_generate(engine);
        }
    } else {
         /*Update the state of the returned HSM key*/
        hkey->state = policy->keys_shared? DBW_HSMKEY_SHARED : DBW_HSMKEY_PRIVATE;
        dbw_mark_dirty((struct dbrow *)hkey);
        ods_log_debug("[hsm_key_factory_get_key] key allocated");
    }
    if (!engine->config->manual_keygen)
        hsm_key_factory_schedule(engine, pkey->id, -1);
    return hkey;
}

void
hsm_key_factory_release_key_mockup(struct dbw_hsmkey *hsmkey, struct dbw_key *key, int mockup)
{
    int c = hsmkey->key_count;
    if (c == 1 && hsmkey->key[0] == key) c--;
    if (c > 0) {
        ods_log_debug("[hsm_key_factory_release_key] unable to release hsm_key, in use");
    } else {
        ods_log_debug("[hsm_key_factory_release_key] key %s marked DELETE", hsmkey->locator);
        hsmkey->dirty = DBW_DELETE;
        /* state will not be committed to the database but will prevent this 
         * key to be used in the current iteration. */
        hsmkey->state = DBW_HSMKEY_DELETE;
        if (!mockup) {
            hsm_ctx_t *hsm_ctx;
            if (!(hsm_ctx = hsm_create_context())) return;
            libhsm_key_t *hkey = hsm_find_key_by_id(hsm_ctx, hsmkey->locator);
            if (hsm_remove_key(hsm_ctx, hkey)) {
                ods_log_error("Unable to remove key from HSM");
            } else {
                ods_log_info("Successfully removed key from HSM");
            }
            hsm_destroy_context(hsm_ctx);
        }
    }
}

void
hsm_key_factory_release_key(struct dbw_hsmkey *hsmkey, struct dbw_key *key)
{
    hsm_key_factory_release_key_mockup(hsmkey, key, 0);
}
