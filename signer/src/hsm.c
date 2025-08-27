/*
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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

/**
 * Hardware Security Module support.
 *
 */

#include "daemon/engine.h"
#include "hsm.h"
#include "log.h"

#include <pthread.h>

pthread_mutex_t _hsm_get_dnskey_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char* hsm_str = "hsm";

/**
 * Clear key cache.
 *
 */
static void
lhsm_clear_key_cache(key_type* key)
{
    if (!key) {
        return;
    }
    if (key->dnskey) {
        /* DNSKEY still exists in zone */
        key->dnskey = NULL;
    }
    if (key->params) {
        hsm_sign_params_free(key->params);
        key->params = NULL;
    }
}

static const libhsm_key_t*
keylookup(hsm_ctx_t* ctx, const char* locator)
{
    const libhsm_key_t* key;
    key = keycache_lookup(ctx, locator);
    if (key == NULL) {
        char* error = hsm_get_error(ctx);
            if (error) {
                ods_log_error("[%s] %s", hsm_str, error);
                free((void*)error);
            }
            /* could not find key */
            ods_log_error("[%s] unable to get key: key %s not found", hsm_str, locator);
    }
    return key;
}

/**
 * Get key from one of the HSMs.
 *
 */
ods_status
lhsm_get_key(hsm_ctx_t* ctx, ldns_rdf* owner, key_type* key_id, int skip_hsm_access)
{
    char *error = NULL;
    int retries = 0;

    if (!owner || !key_id) {
        ods_log_error("[%s] unable to get key: missing required elements",
            hsm_str);
        return ODS_STATUS_ASSERT_ERR;
    }

llibhsm_key_start:

    /* set parameters */
    if (!key_id->params) {
        key_id->params = hsm_sign_params_new();
        if (key_id->params) {
            key_id->params->owner = ldns_rdf_clone(owner);
            key_id->params->algorithm = key_id->algorithm;
            key_id->params->flags = key_id->flags;
        } else {
            /* could not create params */
            ods_log_error("[%s] unable to get key: create params for key %s "
                "failed", hsm_str, key_id->locator?key_id->locator:"(null)");
            return ODS_STATUS_ERR;
        }
    }
    if (skip_hsm_access) return ODS_STATUS_OK;

    /* get dnskey */
    if (!key_id->dnskey) {
        pthread_mutex_lock(&_hsm_get_dnskey_mutex);
        key_id->dnskey = hsm_get_dnskey(ctx, keylookup(ctx, key_id->locator), key_id->params);
        pthread_mutex_unlock(&_hsm_get_dnskey_mutex);
    }
    if (!key_id->dnskey) {
        error = hsm_get_error(ctx);
        if (error) {
            ods_log_error("[%s] %s", hsm_str, error);
            free((void*)error);
        } else if (!retries) {
            lhsm_clear_key_cache(key_id);
            retries++;
            goto llibhsm_key_start;
        }
        ods_log_error("[%s] unable to get key: hsm failed to create dnskey",
            hsm_str);
        return ODS_STATUS_ERR;
    }
    key_id->params->keytag = ldns_calc_keytag(key_id->dnskey);
    return ODS_STATUS_OK;
}


/**
 * Get RRSIG from one of the HSMs, given a RRset and a key.
 *
 */
ldns_rr*
lhsm_sign(hsm_ctx_t* ctx, ldns_rr_list* rrset, key_type* key_id,
    ldns_rdf* owner, time_t inception, time_t expiration)
{
    char* error = NULL;
    ldns_rr* result = NULL;
    hsm_sign_params_t* params = NULL;

    if (!owner || !key_id || !rrset || !inception || !expiration) {
        ods_log_error("[%s] unable to sign: missing required elements",
            hsm_str);
        return NULL;
    }
    ods_log_assert(key_id->dnskey);
    ods_log_assert(key_id->params);
    /* adjust parameters */
    params = hsm_sign_params_new();
    params->owner = ldns_rdf_clone(key_id->params->owner);
    params->algorithm = key_id->algorithm;
    params->flags = key_id->flags;
    params->inception = inception;
    params->expiration = expiration;
    params->keytag = key_id->params->keytag;
    ods_log_deeebug("[%s] sign RRset[%i] with key %s tag %u", hsm_str,
        ldns_rr_get_type(ldns_rr_list_rr(rrset, 0)),
        key_id->locator?key_id->locator:"(null)", params->keytag);
    result = hsm_sign_rrset(ctx, rrset, keylookup(ctx, key_id->locator), params);
    hsm_sign_params_free(params);
    if (!result) {
        error = hsm_get_error(ctx);
        if (error) {
            ods_log_error("[%s] %s", hsm_str, error);
            free((void*)error);
        }
        ods_log_crit("[%s] error signing rrset with libhsm", hsm_str);
    }
    return result;
}
