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

#ifndef SIGNER_NSEC3PARAMS_H
#define SIGNER_NSEC3PARAMS_H

#include "config.h"
#include <ctype.h>
#include <stdint.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <ldns/ldns.h>

typedef struct nsec3params_struct nsec3params_type;

#include "status.h"
#include "signconf.h"

struct nsec3params_struct {
    signconf_type* sc;
    uint8_t        algorithm;
    uint8_t        flags;
    uint16_t       iterations;
    uint8_t        salt_len;
    uint8_t*       salt_data;
    ldns_rr*       rr;
};

/**
 * Create NSEC3 salt.
 * \param[in] salt_str the salt in string format
 * \param[out] salt_len lenght of the salt data
 * \param[out] salt salt in raw data format
 * \return ods_status status
 *
 */
extern ods_status nsec3params_create_salt(const char* salt_str, uint8_t* salt_len,
    uint8_t** salt);

/**
 * Create new NSEC3 parameters.
 * \param[in] sc signer configuration reference
 * \param[in] algo algorithm
 * \param[in] flags flags, Opt-Out or Opt-In
 * \param[in] iter number of iterations
 * \param[in] salt salt
 * \return nsec3params_type* the created nsec3params
 *
 */
extern nsec3params_type* nsec3params_create(void* sc, uint8_t algo, uint8_t flags,
    uint16_t iter, const char* salt);

/**
 * Backup NSEC3 parameters.
 * \param[in] fd file descriptor
 * \param[in] algo algorithm
 * \param[in] flags glags, Opt-Out or Opt-In
 * \param[in] iter number of iterations
 * \param[in] salt salt
 * \param[in] rr NSEC3PARAM RR
 * \param[in] version version string
 *
 */
void nsec3params_backup(FILE* fd, uint8_t algo, uint8_t flags,
    uint16_t iter, const char* salt, ldns_rr* rr, const char* version);

/**
 * Clean up the NSEC3 parameters.
 * \param[in] nsec3params the nsec3param to be deleted
 *
 */
extern void nsec3params_cleanup(nsec3params_type* nsec3params);

#endif /* SIGNER_NSEC3PARAMS_H */
