/*
 * $Id$
 *
 * Copyright (c) 2009 Nominet UK.
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
 */

#include "config.h"
#include "hsmtest.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <libhsm.h>
#include <libhsmdns.h>


static int
hsm_test_sign (hsm_ctx_t *ctx, hsm_key_t *key)
{
    int result;
    ldns_rr_list *rrset;
    ldns_rr *rr, *sig, *dnskey_rr;
    ldns_status status;
    hsm_sign_params_t *sign_params;

    rrset = ldns_rr_list_new();

    status = ldns_rr_new_frm_str(&rr, "example.com. IN A 192.168.0.1", 0, NULL, NULL);
    if (status == LDNS_STATUS_OK) ldns_rr_list_push_rr(rrset, rr);

    status = ldns_rr_new_frm_str(&rr, "example.com. IN A 192.168.0.2", 0, NULL, NULL);
    if (status == LDNS_STATUS_OK) ldns_rr_list_push_rr(rrset, rr);

    sign_params = hsm_sign_params_new();
    sign_params->algorithm = LDNS_RSASHA1;
    sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, "example.com.");
    dnskey_rr = hsm_get_dnskey(ctx, key, sign_params);
    sign_params->keytag = ldns_calc_keytag(dnskey_rr);

    sig = hsm_sign_rrset(ctx, rrset, key, sign_params);
    if (sig) {
        result = 0;
        ldns_rr_free(sig);
    } else {
        result = 1;
    }

    ldns_rr_list_deep_free(rrset);
    hsm_sign_params_free(sign_params);
    ldns_rr_free(dnskey_rr);

    return result;
}

static void
hsm_test_random()
{
    hsm_ctx_t *ctx = NULL;

    int result;
    unsigned char rnd_buf[1024];
    uint32_t r32;
    uint64_t r64;

    printf("Generating %lu bytes of random data... ", sizeof(rnd_buf));
    result = hsm_random_buffer(ctx, rnd_buf, sizeof(rnd_buf));
    if (result) {
        printf("Failed, error: %d\n", result);
        hsm_print_error(ctx);
        return;
    } else {
        printf("OK\n");
    }

    printf("Generating 32-bit random data... ");
    r32 = hsm_random32(ctx);
    printf("%u\n", r32);

    printf("Generating 64-bit random data... ");
    r64 = hsm_random64(ctx);
    printf("%llu\n", r64);
}

void
hsm_test (const char *repository)
{
    int result;
    const unsigned int keysizes[] = { 512, 768, 1024, 1536, 2048, 4096 };
    unsigned int keysize;

    hsm_ctx_t *ctx = NULL;
    hsm_key_t *key = NULL;
    char *id;

    /* Check for repository before starting any tests */
    if (hsm_token_attached(ctx, repository) == 0) {
        hsm_print_error(ctx);
        return;        
    }

    /*
     * Test key generation, signing and deletion for a number of key size
     */
    for (unsigned int i=0; i<(sizeof(keysizes)/sizeof(unsigned int)); i++) {
        keysize = keysizes[i];

        printf("Generating %d-bit RSA key... ", keysize);
        key = hsm_generate_rsa_key(ctx, repository, keysize);
        if (!key) {
            printf("Failed\n");
            hsm_print_error(ctx);
            printf("\n");
            continue;
        } else {
            printf("OK\n");
        }

        printf("Extracting key identifier... ");
        id = hsm_get_key_id(ctx, key);
        if (!id) {
            printf("Failed\n");
            hsm_print_error(ctx);
            printf("\n");
        } else {
            printf("OK, %s\n", id);
        }

        printf("Signing with key... ");
        result = hsm_test_sign(ctx, key);
        if (result) {
            printf("Failed, error: %d\n", result);
            hsm_print_error(ctx);
        } else {
            printf("OK\n");
        }

        printf("Deleting key... ");
        result = hsm_remove_key(ctx, key);
        if (result) {
            printf("Failed: error: %d\n", result);
            hsm_print_error(ctx);
        } else {
            printf("OK\n");
        }

        printf("\n");
    }
    
    hsm_test_random();
}
