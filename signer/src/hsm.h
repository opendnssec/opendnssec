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

/**
 * Hardware Security Module support.
 *
 */

#ifndef SHARED_HSM_H
#define SHARED_HSM_H

#include "config.h"
#include "status.h"
#include "signer/keys.h"
#include "libhsm.h"

#include <ctype.h>
#include <stdint.h>

#include <ldns/ldns.h>
#include <libhsmdns.h>

/**
 * Get key from one of the HSMs, store the DNSKEY and HSM key.
 * \param[in] ctx HSM context
 * \param[in] owner the zone owner name
 * \param[in] key_id key credentials
 * \return ods_status status
 *
 */
extern ods_status lhsm_get_key(hsm_ctx_t* ctx, ldns_rdf* owner, key_type* key_id, int skip_hsm_access);

/**
 * Get RRSIG from one of the HSMs, given a RRset and a key.
 * \param[in] ctx HSM context
 * \param[in] rrset RRset to be signed
 * \param[in] key_id key credentials
 * \param[in] owner owner of the keys
 * \param[in] inception signature inception
 * \param[in] expiration signature expiration
 * \return ldns_rr* RRSIG record
 *
 */
extern ldns_rr* lhsm_sign(hsm_ctx_t* ctx, ldns_rr_list* rrset, key_type* key_id,
    ldns_rdf* owner, time_t inception, time_t expiration);

#endif /* SHARED_HSM_H */
