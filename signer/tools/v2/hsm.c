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

#include "v2/hsm.h"

/**
 * Get key from one of the HSMs.
 *
 */
ldns_rr*
hsm_get_key(hsm_ctx_t* ctx, ldns_rdf* dname, key_type* key_id)
{
    hsm_sign_params_t* params;
    hsm_key_t* hsmkey;
    ldns_rr* rrkey = NULL;
    int error = 0;

    params = hsm_sign_params_new();
    params->owner = ldns_rdf_clone(dname);
    params->algorithm = key_id->algorithm;
    params->flags = key_id->flags;

    /* lookup key */
    hsmkey = hsm_find_key_by_id(ctx, key_id->locator);
    if (hsmkey) {
        rrkey = hsm_get_dnskey(ctx, hsmkey, params);
    } else {
        /* could not find key */
        fprintf(stderr, "could not find key %s\n", key_id->locator);
        error = 1;
    }
    hsm_sign_params_free(params);

    if (!error) {
        return rrkey;
    }
    if (rrkey) {
        ldns_rr_free(rrkey);
    }
    return NULL;
}

/**
 * Get RRSIG from one of the HSMs, given a RRset and a key.
 *
 */
ldns_rr*
hsm_sign_rrset_with_key(hsm_ctx_t* ctx, ldns_rdf* dname, key_type* key_id,
    ldns_rr_list* rrset, time_t inception, time_t expiration)
{
    hsm_sign_params_t* params;
    hsm_key_t* hsmkey;
    ldns_rr* rrkey = NULL;
    ldns_rr* rrsig = NULL;
    int error = 0;

    /* lookup key */
    hsmkey = hsm_find_key_by_id(ctx, key_id->locator);
    if (hsmkey) {
        params = hsm_sign_params_new();
        params->owner = ldns_rdf_clone(dname);
        params->algorithm = key_id->algorithm;
        params->flags = key_id->flags;

        rrkey = hsm_get_dnskey(ctx, hsmkey, params);

        params->keytag = ldns_calc_keytag(rrkey);
        params->inception = inception;
        params->expiration = expiration;

        rrsig = hsm_sign_rrset(ctx, rrset, hsmkey, params);

        ldns_rr_free(rrkey);
        hsm_sign_params_free(params);
    } else {
        /* could not find key */
        fprintf(stderr, "could not find key %s\n", key_id->locator);
        error = 1;
    }

    if (!error) {
        return rrsig;
    }
    if (rrsig) {
        ldns_rr_free(rrsig);
    }
    return NULL;
}

