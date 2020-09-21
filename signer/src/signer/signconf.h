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

#ifndef SIGNER_SIGNCONF_H
#define SIGNER_SIGNCONF_H

#include <ldns/ldns.h>
#include <time.h>

typedef struct signconf_struct signconf_type;

#include "scheduler/task.h"
#include "status.h"
#include "duration.h"
#include "signer/keys.h"
#include "signer/nsec3params.h"

struct signconf_struct {
    /* Zone */
    const char* name;
    int passthrough;
    /* Signatures */
    duration_type* sig_resign_interval;
    duration_type* sig_refresh_interval;
    duration_type* sig_validity_default;
    duration_type* sig_validity_denial;
    duration_type* sig_validity_keyset;
    duration_type* sig_jitter;
    duration_type* sig_inception_offset;
    /* Denial of existence */
    duration_type* nsec3param_ttl;
    ldns_rr_type nsec_type;
    int nsec3_optout;
    uint32_t nsec3_algo;
    uint32_t nsec3_iterations;
    const char* nsec3_salt;
    nsec3params_type* nsec3params;
    /* Keys */
    duration_type* dnskey_ttl;
    const char** dnskey_signature; /* may be NULL and must be NULL terminated */
    keylist_type* keys;
    /* Source of authority */
    duration_type* soa_ttl;
    duration_type* soa_min;
    const char* soa_serial;
    /* Other useful information */
    duration_type* max_zone_ttl;
    const char* filename;
    time_t last_modified;
};

/**
 * Create a new signer configuration with the 'empty' settings.
 * \return signconf_type* signer configuration
 *
 */
extern signconf_type* signconf_create(void);

/**
 * Update signer configuration.
 * \param[out] signconf signer configuration
 * \param[in] scfile signer configuration file name
 * \param[in] last_modified last known modification
 * \return ods_status status
 *
 */
extern ods_status signconf_update(signconf_type** signconf, const char* scfile,
    time_t last_modified);

/**
 * Backup signer configuration.
 * \param[in] fd file descriptor
 * \param[in] sc signer configuration settings
 * \param[in] version version string
 *
 */
void signconf_backup(FILE* fd, signconf_type* sc, const char* version);

/**
 * Check signer configuration.
 * \param signconf signer configuration
 * \return ods_status status
 *
 */
extern ods_status signconf_check(signconf_type* signconf);

/**
 * Compare signer configurations on denial of existence material.
 * \param[in] a a signer configuration
 * \param[in] b another signer configuration
 * \return task_id what task needs to be scheduled
 *
 */
extern task_id signconf_compare_denial(signconf_type* a, signconf_type* b);

/**
 * Log signer configuration.
 * \param[in] sc signconf to log
 * \param[in] name zone name
 *
 */
extern void signconf_log(signconf_type* sc, const char* name);

/**
 * Clean up signer configuration.
 * \param[in] sc signconf to cleanup
 *
 */
extern void signconf_cleanup(signconf_type* sc);

#endif /* SIGNER_SIGNCONF_H */
