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
 * Resource Records RDATA.
 *
 */

#ifndef SIGNER_RDATAS_H
#define SIGNER_RDATAS_H

#include "config.h"
#include "shared/allocator.h"

#include <ldns/ldns.h>

/**
 * RR ods-style (only RDATA elements).
 */
typedef struct ods_struct_rr ods_rr;
struct ods_struct_rr
{
        /**  Number of data fields */
        size_t rd_count;
        /**  The array of rdata's (in network order) */
        ldns_rdf** rdata_fields;
};

/**
 * Singly linked list of ods rrs.
 */
typedef struct ods_struct_dnssec_rrs ods_dnssec_rrs;
struct ods_struct_dnssec_rrs
{
        ods_rr *rr;
        ods_dnssec_rrs *next;
};

/**
 * Create new RR.
 * \param[in] ldnsrr RR in ldns-format.
 * \return ods_rr* RR in opendnssec-format.
 *
 */
ods_rr* ods_rr_new(ldns_rr* ldnsrr);

/**
 * Get a RDATA element.
 * \param[in] rr RR
 * \param[in] pos position of the RDATA element
 * \return ldns_rdf* RDATA element
 *
 */
ldns_rdf* ods_rr_rdf(ods_rr* rr, size_t pos);

/**
 * Set a RDATA element.
 * \param[in] rr RR
 * \param[in] rdf RDATA element
 * \param[in] pos position of the RDATA element
 * \return ldns_rdf* the old RDATA element
 *
 */
ldns_rdf* ods_rr_set_rdf(ods_rr* rr, const ldns_rdf* rdf, size_t pos);

/**
 * Clone RR.
 * \param[in] rr the RR to clone
 * \return ods_rr* the new RR or NULL on failure
 *
 */
ods_rr* ods_rr_clone(const ods_rr* rr);

/**
 * Create new ldns RR, based on a given opendnssec-format RR.
 * \param[in] owner RR owner
 * \param[in] ttl RR TTL
 * \param[in] klass RR class
 * \param[in] rrtype RRtype
 * \param[in] odsrr RR in opendnssec-format.
 * \return ldns_rr* RR in ldns-format.
 *
 */
ldns_rr* ods_rr_2ldns(ldns_rdf* owner, uint32_t ttl, ldns_rr_class klass,
    ldns_rr_type rrtype, ods_rr* odsrr);

/**
 * Print the RR to a given file stream.
 * \param[in] fd file descriptor
 * \param[in] owner RR owner
 * \param[in] ttl RR TTL
 * \param[in] klass RR class
 * \param[in] rrtype RRtype
 * \param[in] odsrr RR RDATAs
 *
 */
void ods_rr_print(FILE *fd, ldns_rdf* owner, uint32_t ttl, ldns_rr_class klass,
    ldns_rr_type rrtype, ods_rr* odsrr);

/**
 * Clean up RR.
 * \param[in] rr RR
 *
 */
void ods_rr_free(ods_rr *rr);

/**
 * Creates a new entry for 1 pointer to an rr and 1 pointer to the next rrs
 * \return ods_dnssec_rrs* the allocated data
 *
 */
ods_dnssec_rrs* ods_dnssec_rrs_new(void);

/**
 * Compare RRs.
 * \param[in] rr1 RR
 * \param[in] rr2 another RR
 * \param[in] rrtype RRtype
 * \param[out] cmp compare value
 * \return ldns_status compare status
 *
 */
ldns_status ods_dnssec_rrs_compare(ods_rr* rr1, ods_rr* rr2,
    ldns_rr_type rrtype, int* cmp);

/**
 * Adds an RR to the list of RRs.
 * The list will remain ordered
 * \param[in] rrs the list to add to
 * \param[in] rr the RR to add
 * \param[in] rrtype RRtype
 * \return ldns_status status
 *
 */
ldns_status ods_dnssec_rrs_add_rr(ods_dnssec_rrs *rrs, ods_rr *rr,
    ldns_rr_type rrtype);

/**
 * Print the list of rrs.
 * \param[in] fd file descriptor
 * \param[in] owner RR owner
 * \param[in] ttl RR TTL
 * \param[in] klass RR class
 * \param[in] rrtype RRtype
 * \param[in] rrs the data structure to print
 *
 */
void ods_dnssec_rrs_print(FILE *fd, ldns_rdf* owner, uint32_t ttl,
    ldns_rr_class klass, ldns_rr_type rrtype, ods_dnssec_rrs *rrs);

/**
 * Frees the list of rrs, but *not* the individual ods_rr records.
 * \param[in] rrs the data structure to free
 *
 */
void ods_dnssec_rrs_free(ods_dnssec_rrs *rrs);

/**
 * Frees the list of rrs, *and* the individual ldns_rr records.
 * \param[in] rrs the data structure to free
 *
 */
void ods_dnssec_rrs_deep_free(ods_dnssec_rrs *rrs);

#endif /* SIGNER_RDATAS_H */
