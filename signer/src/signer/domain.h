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

#ifndef SIGNER_DOMAIN_H
#define SIGNER_DOMAIN_H

#include "config.h"
#include <ldns/ldns.h>
#include <time.h>


typedef struct domain_struct domain_type;

#include "status.h"
#include "signer/rrset.h"
#include "signer/signconf.h"
#include "signer/zone.h"

#define SE_NSEC_RDATA_NXT          0
#define SE_NSEC_RDATA_BITMAP       1
#define SE_NSEC3_RDATA_NSEC3PARAMS 4
#define SE_NSEC3_RDATA_NXT         4
#define SE_NSEC3_RDATA_BITMAP      5

/**
 * Domain.
 *
 */
 struct domain_struct {
    denial_type* denial;
    ldns_rbnode_t* node;
    ldns_rdf* dname;
    domain_type* parent;
    rrset_type* rrsets;
    unsigned is_new : 1;
    unsigned is_apex : 1; /* apex */
};

/**
 * Log domain name.
 * \param[in] rdf domain name
 * \param[in] pre log message
 * \param[in] level log level
 *
 */
void log_dname(ldns_rdf* rdf, const char* pre, int level);

/**
 * Create domain.
 * \param[in] zoneptr zone reference
 * \param[in] dname owner name
 * \return domain_type* domain
 *
 */
domain_type* domain_create(zone_type* zone, ldns_rdf* dname);

/**
 * Count the number of RRsets at this domain with RRs that have is_added.
 * \param[in] domain domain
 * \return size_t number of RRsets
 *
 */
size_t domain_count_rrset_is_added(domain_type* domain);

/**
 * Look up RRset at this domain.
 * \param[in] domain the domain
 * \param[in] rrtype RRtype
 * \return rrset_type* RRset, if found
 *
 */
rrset_type* domain_lookup_rrset(domain_type* domain, ldns_rr_type rrtype);

/**
 * Add RRset to domain.
 * \param[in] domain domain
 * \param[in] rrset RRset
 *
 */
void domain_add_rrset(domain_type* domain, rrset_type* rrset);

/**
 * Apply differences at domain.
 * \param[in] domain domain
 * \param[in] is_ixfr true if incremental change
 * \param[in] more_coming more transactions possible
 *
 */
void domain_diff(zone_type* zone, domain_type* domain, unsigned is_ixfr, unsigned more_coming);

/**
 * Rollback differences at domain.
 * \param[in] domain domain
 * \param[in] keepsc keep RRs that did not came from the adapter
 *
 */
void domain_rollback(domain_type* domain, int keepsc);

/**
 * Check whether a domain is an empty non-terminal to an unsigned delegation.
 * \param[in] domain domain
 * \return int yes or no
 *
 */
int domain_ent2unsignedns(domain_type* domain);

/**
 * Check whether a domain is a delegation, regardless of parent.
 * \param[in] domain domain
 * \return ldns_rr_type RRtype that hints whether the domain is occluded.
 *         LDNS_RR_TYPE_NS Unsigned delegation
 *         LDNS_RR_TYPE_DS Signed delegation
 *         LDNS_RR_TYPE_SOA Authoritative data (or signed delegation)
 *
 */
ldns_rr_type domain_is_delegpt(domain_type* domain);

/**
 * Check whether the domain is occluded.
 * \param[in] domain domain
 * \return ldns_rr_type RRtype that hints whether the domain is occluded.
 *         LDNS_RR_TYPE_DNAME Occluded
 *         LDNS_RR_TYPE_A Glue
 *         LDNS_RR_TYPE_SOA Authoritative data or delegation
 *
 */
ldns_rr_type domain_is_occluded(domain_type* domain);

/**
 * Print domain.
 * \param[in] fd file descriptor
 * \param[in] domain domain
 * \param[out] status status
 *
 */
void domain_print(FILE* fd, domain_type* domain, ods_status* status);

/**
 * Clean up domain.
 * \param[in] domain domain to cleanup
 *
 */
void domain_cleanup(domain_type* domain);

#endif /* SIGNER_DOMAIN_H */
