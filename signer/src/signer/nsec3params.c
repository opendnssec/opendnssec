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
 * NSEC3 Parameters.
 *
 */

#include "shared/allocator.h"
#include "shared/log.h"
#include "shared/util.h"
#include "signer/backup.h"
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
    signconf_type* signconf = (signconf_type*) sc;
    uint8_t salt_len; /* calculate salt len */
    uint8_t* salt_data; /* calculate salt data */

    if (!sc) {
        return NULL;
    }
    nsec3params = (nsec3params_type*) allocator_alloc(signconf->allocator,
        sizeof(nsec3params_type));
    if (!nsec3params) {
        ods_log_error("[%s] unable to create: allocator_alloc() failed",
            nsec3_str);
        return NULL;
    }
    nsec3params->sc = sc;
    nsec3params->algorithm = algo;
    nsec3params->flags = flags;
    nsec3params->iterations = iter;
    /* construct the salt from the string */
    if (nsec3params_create_salt(salt, &salt_len, &salt_data) != 0) {
        ods_log_error("[%s] unable to create: create salt failed", nsec3_str);
        allocator_deallocate(signconf->allocator, (void*)nsec3params);
        return NULL;
    }
    nsec3params->salt_len = salt_len;
    nsec3params->salt_data = salt_data;
    nsec3params->rr = NULL;
    return nsec3params;
}


/**
 * Backup NSEC3 parameters.
 *
 */
void
nsec3params_backup(FILE* fd, uint8_t algo, uint8_t flags,
    uint16_t iter, const char* salt, ldns_rr* rr, const char* version)
{
    if (!fd) {
        return;
    }
    fprintf(fd, ";;Nsec3parameters: salt %s algorithm %u optout %u "
        "iterations %u\n", salt?salt:"-", (unsigned) algo,
        (unsigned) flags, (unsigned) iter);
    if (strcmp(version, ODS_SE_FILE_MAGIC_V2) == 0) {
        if (rr) {
            (void)util_rr_print(fd, rr);
        }
        fprintf(fd, ";;Nsec3done\n");
        fprintf(fd, ";;\n");
    }
    return;
}


/**
 * Convert salt to string.
 *
 */
const char*
nsec3params_salt2str(nsec3params_type* nsec3params)
{
    uint8_t *data;
    uint8_t salt_length = 0;
    uint8_t salt_pos = 0;
    int written = 0;
    char* str = NULL;
    ldns_buffer* buffer = NULL;

    salt_length = nsec3params->salt_len;
    data = nsec3params->salt_data;
    /* from now there are variable length entries so remember pos */
    if (salt_length == 0) {
        buffer = ldns_buffer_new(2);
        written = ldns_buffer_printf(buffer, "-");
    } else {
        buffer = ldns_buffer_new(salt_pos+1);
        for (salt_pos = 0; salt_pos < salt_length; salt_pos++) {
            written = ldns_buffer_printf(buffer, "%02x", data[salt_pos]);
        }
    }
    if (ldns_buffer_status(buffer) == LDNS_STATUS_OK) {
        str = ldns_buffer2str(buffer);
    } else if (written) {
        ods_log_error("[%s] unable to convert nsec3 salt to string: %s",
            nsec3_str, ldns_get_errorstr_by_id(ldns_buffer_status(buffer)));
    } else {
        ods_log_error("[%s] unable to convert nsec3 salt to string: zero "
            "bytes written", nsec3_str);
    }
    ldns_buffer_free(buffer);
    return (const char*) str;
}


/**
 * Clean up NSEC3 parameters.
 *
 */
void
nsec3params_cleanup(nsec3params_type* nsec3params)
{
    signconf_type* sc = NULL;
    if (!nsec3params) {
        return;
    }
    sc = (signconf_type*) nsec3params->sc;
    allocator_deallocate(sc->allocator, (void*) nsec3params->salt_data);
    allocator_deallocate(sc->allocator, (void*) nsec3params);
    return;
}
