/*
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
#include <ldns/ldns.h>
#include <time.h>

typedef struct denial_struct denial_type;

#include "status.h"
#include "signer/nsec3params.h"
#include "signer/zone.h"
#include "signer/rrset.h"
#include "signer/domain.h"
#include "signer/zone.h"

/**
 * Denial of Existence data point.
 *
 */
struct denial_struct {
    ldns_rdf* dname;
    rrset_type* rrset;
    unsigned changed : 1;
};

/**
 * Create new Denial of Existence data point.
 * \param[in] zoneptr zone reference
 * \param[in] dname owner name
 * \return denial_type* denial of existence data point
 *
 */
denial_type* denial_create(zone_type* zoneptr, ldns_rdf* dname);

/**
 * Add NSEC(3) to the Denial of Existence data point.
 * \param[in] denial Denial of Existence data point
 * \param[in] rr NSEC(3) resource record
 *
 */
void denial_add_rr(zone_type* zone, denial_type* denial, ldns_rr* rr);

/**
 * Nsecify Denial of Existence data point.
 * \param[in] denial Denial of Existence data point
 * \param[in] nxt next Denial of Existence data point
 * \param[out] num_added number of RRs added
 *
 */
void denial_nsecify(zone_type* zone, domain_type* domain, ldns_rdf* nxt, uint32_t* num_added);

/**
 * Print Denial of Existence data point.
 * \param[in] fd file descriptor
 * \param[in] denial denial of existence data point
 * \param[out] status status
 *
 */
void denial_print(FILE* fd, denial_type* denial, ods_status* status);

/**
 * Cleanup Denial of Existence data point.
 * \param[in] denial denial of existence data point
 *
 */
void denial_cleanup(denial_type* denial);

#endif /* SIGNER_DENIAL_H */
