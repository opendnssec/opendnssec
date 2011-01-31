/*
 * $Id$
 *
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

#include "shared/hsm.h"
#include "shared/log.h"

static const char* hsm_str = "hsm";


/**
 * Get key from one of the HSMs.
 *
 */
int
hsm_get_key(hsm_ctx_t* ctx, ldns_rdf* dname, key_type* key_id)
{
    if (!dname || !key_id) {
        ods_log_error("[%s] unable to get key: missing required elements",
            hsm_str);
        return 1;
    }
    ods_log_assert(dname);
    ods_log_assert(key_id);

    if (!key_id->params) {
        key_id->params = hsm_sign_params_new();
        if (key_id->params) {
            key_id->params->owner = ldns_rdf_clone(dname);
            key_id->params->algorithm = key_id->algorithm;
            key_id->params->flags = key_id->flags;
        } else {
            /* could not create params */
            ods_log_error("[%s] unable to get key: create params for key %s "
                "failed", hsm_str, key_id->locator?key_id->locator:"(null)");
            return 1;
        }
    }

    /* lookup key */
    if (!key_id->hsmkey) {
        key_id->hsmkey = hsm_find_key_by_id(ctx, key_id->locator);

        if (key_id->hsmkey) {
            key_id->dnskey = hsm_get_dnskey(ctx, key_id->hsmkey,
                key_id->params);
        } else {
            /* could not find key */
            ods_log_error("[%s] unable to get key: key %s not found", hsm_str,
                key_id->locator?key_id->locator:"(null)");
            return 1;
        }
    }

    if (!key_id->dnskey) {
        return 1;
    }
    key_id->params->keytag = ldns_calc_keytag(key_id->dnskey);
    return 0;
}

/**
 * Get RRSIG from one of the HSMs, given a RRset and a key.
 *
 */
ldns_rr*
hsm_sign_rrset_with_key(hsm_ctx_t* ctx, ldns_rdf* dname, key_type* key_id,
    ldns_rr_list* rrset, time_t inception, time_t expiration)
{

    if (!dname || !key_id || !rrset || !inception || !expiration) {
        ods_log_error("[%s] unable to sign: missing required elements",
            hsm_str);
        return NULL;
    }
    ods_log_assert(dname);
    ods_log_assert(key_id);
    ods_log_assert(rrset);
    ods_log_assert(inception);
    ods_log_assert(expiration);

    if (!key_id->params) {
        key_id->params = hsm_sign_params_new();
        if (key_id->params) {
            key_id->params->owner = ldns_rdf_clone(dname);
            key_id->params->algorithm = key_id->algorithm;
            key_id->params->flags = key_id->flags;
        } else {
            /* could not create params */
            ods_log_error("[%s] could not create params for key %s", hsm_str,
                key_id->locator?key_id->locator:"(null)");
            return NULL;
        }
    }

    key_id->params->inception = inception;
    key_id->params->expiration = expiration;

    /* lookup key */
    if (!key_id->hsmkey) {
        key_id->hsmkey = hsm_find_key_by_id(ctx, key_id->locator);

        if (!key_id->hsmkey) {
            /* could not find key */
            ods_log_error("[%s] could not find key %s", hsm_str,
                key_id->locator?key_id->locator:"(null)");
            return NULL;
        }
    }

    if (!key_id->dnskey) {
        key_id->dnskey = hsm_get_dnskey(ctx, key_id->hsmkey, key_id->params);
        if (!key_id->dnskey) {
            /* could not find key */
            ods_log_error("[%s] could not create DNSKEY for %s", hsm_str,
                key_id->locator?key_id->locator:"(null)");
            return NULL;
        }
    }

    if (!key_id->params->keytag) {
        key_id->params->keytag = ldns_calc_keytag(key_id->dnskey);
    }

    ods_log_debug("[%s] sign RRset[%i] with key %s tag %u", hsm_str,
        ldns_rr_get_type(ldns_rr_list_rr(rrset, 0)),
        key_id->locator?key_id->locator:"(null)", key_id->params->keytag);
    return hsm_sign_rrset(ctx, rrset, key_id->hsmkey, key_id->params);
}
