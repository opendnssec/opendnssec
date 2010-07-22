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
 * Signer configuration.
 *
 */

#ifndef SIGNER_SIGNCONF_H
#define SIGNER_SIGNCONF_H

#include "signer/se_key.h"
#include "util/duration.h"

#include <ldns/ldns.h>
#include <time.h>


/**
 * Signer Configuration.
 *
 */
typedef struct signconf_struct signconf_type;
struct signconf_struct {
    /* Zone */
    const char* name;
    /* Signatures */
    duration_type* sig_resign_interval;
    duration_type* sig_refresh_interval;
    duration_type* sig_validity_default;
    duration_type* sig_validity_denial;
    duration_type* sig_jitter;
    duration_type* sig_inception_offset;
    /* Denial of existence */
    ldns_rr_type nsec_type;
    int nsec3_optout;
    uint32_t nsec3_algo;
    uint32_t nsec3_iterations;
    const char* nsec3_salt;
    /* Keys */
    duration_type* dnskey_ttl;
    keylist_type* keys;
    /* Source of authority */
    duration_type* soa_ttl;
    duration_type* soa_min;
    const char* soa_serial;
    /* Other useful information */
    const char* filename;
    time_t last_modified;
    int audit;
};

/**
 * Create a new signer configuration with the 'empty' settings.
 * \return signconf_type* signer configuration
 *
 */
signconf_type* signconf_create(void);

/**
 * Read signer configuration.
 * \param[in] filename file name
 * \param[in] last_modified last modified
 * \return signconf_type* signer configuration
 *
 */
signconf_type* signconf_read(const char* filename, time_t last_modified);

/**
 * Check signer configuration.
 * \param sc signer configuration settings
 * \return 0 on success, 1 on fail
 *
 */
int signconf_check(signconf_type* sc);

/**
 * Compare two signer configurations.
 * \param a one signconf
 * \param b the other signconf
 * \return what task to perform
 *
 */
int signconf_compare(signconf_type* a, signconf_type* b);

/**
 * Clean up signer configuration.
 * \param[in] sc signconf to cleanup
 *
 */
void signconf_cleanup(signconf_type* sc);

/**
 * Print signer configuration.
 * \param[in] out file descriptor
 * \param[in] sc signconf to print
 * \param[in] name zone name
 *
 */
void signconf_print(FILE* out, signconf_type* sc, const char* name);

#endif /* SIGNER_SIGNCONF_H */
