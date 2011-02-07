/*
 * $Id$
 *
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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
 * Denial of Existence.
 *
 */

#ifndef SIGNER_DENIAL_H
#define SIGNER_DENIAL_H

#include "config.h"
#include "shared/allocator.h"
#include "signer/nsec3params.h"
#include "signer/rrset.h"

#include <ldns/ldns.h>

struct domain_struct;

/**
 * Denial of Existence data point.
 *
 */
typedef struct denial_struct denial_type;
struct denial_struct {
    allocator_type* allocator;
    ldns_rdf* owner;
    rrset_type* rrset;
    struct domain_struct* domain;
    uint8_t bitmap_changed;
    uint8_t nxt_changed;
};

/**
 * Create new Denial of Existence data point.
 * \param[in] owner owner name of the NSEC or NSEC3 RRset
 * \return denial_type* denial of existence data
 *
 */
denial_type* denial_create(ldns_rdf* owner);

/**
 * Add NSEC to the Denial of Existence data point.
 * \param[in] denial Denial of Existence data point
 * \param[in] nxt next Denial of Existence data point
 * \param[in] ttl ttl
 * \param[in] klass class
 * \return ods_status status
 *
 */
ods_status denial_nsecify(denial_type* denial, denial_type* nxt, uint32_t ttl,
    ldns_rr_class klass);

/**
 * Add NSEC3 to the Denial of Existence data point.
 * \param[in] denial Denial of Existence data point
 * \param[in] nxt next Denial of Existence data point
 * \param[in] ttl ttl
 * \param[in] klass class
 * \param[in] nsec3params NSEC3 parameters
 * \return ods_status status
 *
 */
ods_status denial_nsecify3(denial_type* denial, denial_type* nxt, uint32_t ttl,
    ldns_rr_class klass, nsec3params_type* nsec3params);

/**
 * Clean up Denial of Existence data point.
 * \param[in] denial Denial of Existence data point
 *
 */
void denial_cleanup(denial_type* denial);

#endif /* SIGNER_DENIAL_H */
