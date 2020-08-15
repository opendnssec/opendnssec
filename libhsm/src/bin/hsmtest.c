/*
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "libhsm.h"
#include <libhsmdns.h>
#include "hsmtest.h"

static int
hsm_test_sign (hsm_ctx_t *ctx, libhsm_key_t *key, ldns_algorithm alg)
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
    sign_params->algorithm = alg;
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

static int
hsm_test_random(hsm_ctx_t *ctx)
{
    int result;
    unsigned char rnd_buf[1024];
    uint32_t r32;
    uint64_t r64;

    printf("Generating %lu bytes of random data... ",
        (unsigned long) sizeof(rnd_buf));
    result = hsm_random_buffer(ctx, rnd_buf, sizeof(rnd_buf));
    if (result) {
        printf("Failed, error: %d\n", result);
        hsm_print_error(ctx);
        return 1;
    } else {
        printf("OK\n");
    }

    printf("Generating 32-bit random data... ");
    r32 = hsm_random32(ctx);
    printf("%u\n", r32);

    printf("Generating 64-bit random data... ");
    r64 = hsm_random64(ctx);
    printf("%llu\n", (long long unsigned int)r64);

    return 0;
}

int
hsm_test (const char *repository, hsm_ctx_t* ctx)
{
    int result;
    const unsigned int rsa_keysizes[] = { 512, 768, 1024, 1536, 2048, 4096 };
    const unsigned int dsa_keysizes[] = { 512, 768, 1024 };
    unsigned int keysize;
/* TODO: We can remove the directive if we require LDNS >= 1.6.13 */
#if !defined LDNS_BUILD_CONFIG_USE_ECDSA || LDNS_BUILD_CONFIG_USE_ECDSA
    const ldns_algorithm ec_curves[] = {
        LDNS_ECDSAP256SHA256,
        LDNS_ECDSAP384SHA384
    };
#endif
    const ldns_algorithm ed_curves[] = {
#ifdef USE_ED25519
        LDNS_ED25519,
#endif
#ifdef USE_ED448
        LDNS_ED448,
#endif
        // placeholder to ensure the array is not empty
        LDNS_INDIRECT
    };
    ldns_algorithm curve;

    libhsm_key_t *key = NULL;
    char *id;
    int errors = 0;
    unsigned int i = 0;

    /* Check for repository before starting any tests */
    if (hsm_token_attached(ctx, repository) == 0) {
        hsm_print_error(ctx);
        return 1;
    }

    /*
     * Test key generation, signing and deletion for a number of key size
     */
    for (i=0; i<(sizeof(rsa_keysizes)/sizeof(unsigned int)); i++) {
        keysize = rsa_keysizes[i];

        printf("Generating %d-bit RSA key... ", keysize);
        key = hsm_generate_rsa_key(ctx, repository, keysize);
        if (!key) {
            errors++;
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
            errors++;
            printf("Failed\n");
            hsm_print_error(ctx);
            printf("\n");
        } else {
            printf("OK, %s\n", id);
        }
        free(id);

        printf("Signing (RSA/SHA1) with key... ");
        result = hsm_test_sign(ctx, key, LDNS_RSASHA1);
        if (result) {
            errors++;
            printf("Failed, error: %d\n", result);
            hsm_print_error(ctx);
        } else {
            printf("OK\n");
        }

        printf("Signing (RSA/SHA256) with key... ");
        result = hsm_test_sign(ctx, key, LDNS_RSASHA256);
        if (result) {
            errors++;
            printf("Failed, error: %d\n", result);
            hsm_print_error(ctx);
        } else {
            printf("OK\n");
        }

        if ( keysize >= 1024) {
            printf("Signing (RSA/SHA512) with key... ");
            result = hsm_test_sign(ctx, key, LDNS_RSASHA512);
            if (result) {
                errors++;
                printf("Failed, error: %d\n", result);
                hsm_print_error(ctx);
            } else {
                printf("OK\n");
            }
        }

        printf("Deleting key... ");
        result = hsm_remove_key(ctx, key);
        if (result) {
            errors++;
            printf("Failed: error: %d\n", result);
            hsm_print_error(ctx);
        } else {
            printf("OK\n");
        }

        libhsm_key_free(key);

        printf("\n");
    }

    /*
     * Test key generation, signing and deletion for a number of key size
     */
    for (i=0; i<(sizeof(dsa_keysizes)/sizeof(unsigned int)); i++) {
        keysize = dsa_keysizes[i];

        printf("Generating %d-bit DSA key... ", keysize);
        key = hsm_generate_dsa_key(ctx, repository, keysize);
        if (!key) {
            errors++;
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
            errors++;
            printf("Failed\n");
            hsm_print_error(ctx);
            printf("\n");
        } else {
            printf("OK, %s\n", id);
        }
        free(id);

        printf("Signing (DSA/SHA1) with key... ");
        result = hsm_test_sign(ctx, key, LDNS_DSA);
        if (result) {
            errors++;
            printf("Failed, error: %d\n", result);
            hsm_print_error(ctx);
        } else {
            printf("OK\n");
        }

        printf("Deleting key... ");
        result = hsm_remove_key(ctx, key);
        if (result) {
            errors++;
            printf("Failed: error: %d\n", result);
            hsm_print_error(ctx);
        } else {
            printf("OK\n");
        }

        libhsm_key_free(key);

        printf("\n");
    }

    /*
     * Test key generation, signing and deletion for a number of key size
     */
    for (i=0; i<1; i++) {
        printf("Generating 512-bit GOST key... ");
        key = hsm_generate_gost_key(ctx, repository);
        if (!key) {
            errors++;
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
            errors++;
            printf("Failed\n");
            hsm_print_error(ctx);
            printf("\n");
        } else {
            printf("OK, %s\n", id);
        }
        free(id);

        printf("Signing (GOST) with key... ");
        result = hsm_test_sign(ctx, key, LDNS_ECC_GOST);
        if (result) {
            errors++;
            printf("Failed, error: %d\n", result);
            hsm_print_error(ctx);
        } else {
            printf("OK\n");
        }

        printf("Deleting key... ");
        result = hsm_remove_key(ctx, key);
        if (result) {
            errors++;
            printf("Failed: error: %d\n", result);
            hsm_print_error(ctx);
        } else {
            printf("OK\n");
        }

        libhsm_key_free(key);

        printf("\n");
    }

    /*
     * Test key generation, signing and deletion for a number of key size
     */
/* TODO: We can remove the directive if we require LDNS >= 1.6.13 */
#if !defined LDNS_BUILD_CONFIG_USE_ECDSA || LDNS_BUILD_CONFIG_USE_ECDSA
    for (i=0; i<(sizeof(ec_curves)/sizeof(ldns_algorithm)); i++) {
        curve = ec_curves[i];

        if (curve == LDNS_ECDSAP256SHA256) {
            printf("Generating ECDSA Curve P-256 key... ");
            key = hsm_generate_ecdsa_key(ctx, repository, "P-256");
        } else if (curve == LDNS_ECDSAP384SHA384) {
            printf("Generating ECDSA Curve P-384 key... ");
            key = hsm_generate_ecdsa_key(ctx, repository, "P-384");
        } else {
            printf("Failed: Unknown ECDSA curve\n");
            continue;
        }
        if (!key) {
            errors++;
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
            errors++;
            printf("Failed\n");
            hsm_print_error(ctx);
            printf("\n");
        } else {
            printf("OK, %s\n", id);
        }
        free(id);

        if (curve == LDNS_ECDSAP256SHA256) {
            printf("Signing (ECDSA/SHA256) with key... ");
        } else if (curve == LDNS_ECDSAP384SHA384) {
            printf("Signing (ECDSA/SHA384) with key... ");
        } else {
            printf("Signing with key... ");
        }
    }
#endif

    for (i=0; i<(sizeof(ed_curves)/sizeof(ldns_algorithm)); i++) {
        curve = ed_curves[i];

        switch(curve) {
#ifdef USE_ED25519
        case LDNS_ED25519:
            printf("Generating ED25519 key... ");
            key = hsm_generate_eddsa_key(ctx, repository, "edwards25519");
            break;
#endif
#ifdef USE_ED448
         case LDNS_ED448:
            printf("Generating ED448 key... ");
            key = hsm_generate_eddsa_key(ctx, repository, "edwards448");
            break;
#endif
        default:
            continue;
        }
        if (!key) {
            errors++;
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
            errors++;
            printf("Failed\n");
            hsm_print_error(ctx);
            printf("\n");
        } else {
            printf("OK, %s\n", id);
        }
        free(id);

        printf("Signing with key... ");
        result = hsm_test_sign(ctx, key, curve);
        if (result) {
            errors++;
            printf("Failed, error: %d\n", result);
            hsm_print_error(ctx);
        } else {
            printf("OK\n");
        }

        printf("Deleting key... ");
        result = hsm_remove_key(ctx, key);
        if (result) {
            errors++;
            printf("Failed: error: %d\n", result);
            hsm_print_error(ctx);
        } else {
            printf("OK\n");
        }

        libhsm_key_free(key);

        printf("\n");
    }

    if (hsm_test_random(ctx)) {
        errors++;
    }

    return errors;
}
