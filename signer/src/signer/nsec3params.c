/*
 * Copyright (c) 2009-2018 NLNet Labs.
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

/**
 * NSEC3 Parameters.
 *
 */

#include "status.h"
#include "log.h"
#include "util.h"
#include "signer/nsec3params.h"
#include "signer/signconf.h"

#include <ctype.h>
#include <ldns/ldns.h>
#include <stdlib.h>
#include <string.h>

static const char* nsec3_str = "nsec3";


/**
 * Create NSEC3 salt.
 *
 */
ods_status
nsec3params_create_salt(const char* salt_str, uint8_t* salt_len,
    uint8_t** salt)
{
    uint8_t c;
    uint8_t* salt_tmp;

    if (!salt_str) {
        *salt_len = 0;
        *salt = NULL;
        return ODS_STATUS_OK;
    }
    *salt_len = (uint8_t) strlen(salt_str);
    if (*salt_len == 1 && salt_str[0] == '-') {
        *salt_len = 0;
        *salt = NULL;
        return ODS_STATUS_OK;
    } else if (*salt_len % 2 != 0) {
        ods_log_error("[%s] invalid salt %s", nsec3_str, salt_str);
        *salt = NULL;
        return ODS_STATUS_ERR;
    }
    /* construct salt data */
    salt_tmp = (uint8_t*) calloc(*salt_len / 2, sizeof(uint8_t));
    if (!salt_tmp) {
        ods_log_error("[%s] construct salt data for %s failed", nsec3_str,
            salt_str);
        *salt = NULL;
        return ODS_STATUS_MALLOC_ERR;
    }
    for (c = 0; c < *salt_len; c += 2) {
        if (isxdigit((int) salt_str[c]) && isxdigit((int) salt_str[c+1])) {
            salt_tmp[c/2] = (uint8_t) ldns_hexdigit_to_int(salt_str[c]) * 16 +
                                      ldns_hexdigit_to_int(salt_str[c+1]);
        } else {
            ods_log_error("[%s] invalid salt %s", nsec3_str, salt_str);
            free((void*)salt_tmp);
            *salt = NULL;
            return ODS_STATUS_ERR;
        }
    }
    *salt_len = *salt_len / 2; /* update length */
    *salt = salt_tmp;
    return ODS_STATUS_OK;
}


/**
 * Create new NSEC3 parameters.
 *
 */
nsec3params_type*
nsec3params_create(void* sc, uint8_t algo, uint8_t flags, uint16_t iter,
    const char* salt)
{
    nsec3params_type* nsec3params = NULL;
    uint8_t salt_len; /* calculate salt len */
    uint8_t* salt_data; /* calculate salt data */

    if (!sc) {
        return NULL;
    }
    CHECKALLOC(nsec3params = (nsec3params_type*) malloc(sizeof(nsec3params_type)));
    nsec3params->sc = sc;
    nsec3params->algorithm = algo;
    nsec3params->flags = flags;
    nsec3params->iterations = iter;
    /* construct the salt from the string */
    if (nsec3params_create_salt(salt, &salt_len, &salt_data) != 0) {
        ods_log_error("[%s] unable to create: create salt failed", nsec3_str);
        free(nsec3params);
        return NULL;
    }
    nsec3params->salt_len = salt_len;
    nsec3params->salt_data = salt_data;
    nsec3params->rr = NULL;
    return nsec3params;
}


/**
 * Clean up NSEC3 parameters.
 *
 */
void
nsec3params_cleanup(nsec3params_type* nsec3params)
{
    if (!nsec3params) {
        return;
    }
    free(nsec3params->salt_data);
    free(nsec3params);
}
