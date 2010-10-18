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

#include "signer/backup.h"
#include "signer/nsec3params.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <ctype.h> /* isxdigit() */
#include <ldns/ldns.h> /* ldns_hexdigit_to_int() */
#include <string.h> /* strlen() */

/**
 * Create NSEC3 salt.
 *
 */
int
nsec3params_create_salt(const char* salt_str, uint8_t* salt_len, uint8_t** salt)
{
    uint8_t c;
    uint8_t* salt_tmp;

    if (!salt_str) {
        *salt_len = 0;
        *salt = NULL;
        return 0;
    }

    *salt_len = (uint8_t) strlen(salt_str);
    if (*salt_len == 1 && salt_str[0] == '-') {
        *salt_len = 0;
        *salt = NULL;
        return 0;
    } else if (*salt_len % 2 != 0) {
        se_log_error("invalid salt %s", salt_str?salt_str:"(null)");
        *salt = NULL;
        return 1;
    }

    /* construct salt data */
    salt_tmp = (uint8_t*) se_calloc(*salt_len / 2, sizeof(uint8_t));
    for (c = 0; c < *salt_len; c += 2) {
        if (isxdigit((int) salt_str[c]) && isxdigit((int) salt_str[c+1])) {
            salt_tmp[c/2] = (uint8_t) ldns_hexdigit_to_int(salt_str[c]) * 16 +
                                      ldns_hexdigit_to_int(salt_str[c+1]);
        } else {
            se_log_error("invalid salt %s", salt_str?salt_str:"(null)");
            se_free((void*)salt_tmp);
            *salt = NULL;
            return 1;
        }
    }

    *salt_len = *salt_len / 2; /* update length */
    *salt = salt_tmp;
    return 0;
}


/**
 * Create new NSEC3 parameters.
 *
 */
nsec3params_type*
nsec3params_create(uint8_t algo, uint8_t flags, uint16_t iter, const char* salt)
{
    nsec3params_type* nsec3params = (nsec3params_type*)
                                    se_malloc(sizeof(nsec3params_type));
    uint8_t salt_len; /* calculate salt len */
    uint8_t* salt_data; /* calculate salt data */

    nsec3params->algorithm = algo; /* algorithm identifier */
    nsec3params->flags = flags; /* flags */
    nsec3params->iterations = iter; /* iterations */
    /* construct the salt from the string */
    if (nsec3params_create_salt(salt, &salt_len, &salt_data) != 0) {
        se_free((void*)nsec3params);
        return NULL;
    }
    nsec3params->salt_len = salt_len; /* salt length */
    nsec3params->salt_data = salt_data; /* salt data */
    return nsec3params;
}


/**
 * Recover NSEC3 parameters from backup.
 *
 */
nsec3params_type*
nsec3params_recover_from_backup(FILE* fd, ldns_rr** rr)
{
    const char* salt = NULL;
    uint8_t algorithm = 0;
    uint8_t flags = 0;
    uint16_t iterations = 0;
    ldns_rr* nsec3params_rr = NULL;
    nsec3params_type* nsec3params = NULL;
    uint8_t salt_len; /* calculate salt len */
    uint8_t* salt_data; /* calculate salt data */

    se_log_assert(fd);

    if (!backup_read_str(fd, &salt) ||
        !backup_read_uint8_t(fd, &algorithm) ||
        !backup_read_uint8_t(fd, &flags) ||
        !backup_read_uint16_t(fd, &iterations) ||
        ldns_rr_new_frm_fp(&nsec3params_rr, fd, NULL, NULL, NULL)
            != LDNS_STATUS_OK ||
        !backup_read_check_str(fd, ";END"))
    {
        se_log_error("nsec3params part in backup file is corrupted");
        if (nsec3params_rr) {
            ldns_rr_free(nsec3params_rr);
            nsec3params_rr = NULL;
        }
        if (salt) {
            se_free((void*) salt);
            salt = NULL;
        }
        return NULL;
    }

    nsec3params = (nsec3params_type*) se_malloc(sizeof(nsec3params_type));
    nsec3params->algorithm = algorithm; /* algorithm identifier */
    nsec3params->flags = flags; /* flags */
    nsec3params->iterations = iterations; /* iterations */
    /* construct the salt from the string */
    if (nsec3params_create_salt(salt, &salt_len, &salt_data) != 0) {
        se_free((void*)nsec3params);
        se_free((void*)salt);
        ldns_rr_free(nsec3params_rr);
        return NULL;
    }
    nsec3params->salt_len = salt_len; /* salt length */
    nsec3params->salt_data = salt_data; /* salt data */
    *rr = nsec3params_rr;
    return nsec3params;
}


/**
 * Convert Salt to string.
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
    } else {
        se_log_error("failed to convert nsec3 salt to string: %s",
            ldns_get_errorstr_by_id(ldns_buffer_status(buffer)));
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
    if (nsec3params) {
        se_free((void*) nsec3params->salt_data);
	se_free((void*) nsec3params);
    } else {
        se_log_warning("cleanup empty nsec3 parameters");
    }
    return;
}
