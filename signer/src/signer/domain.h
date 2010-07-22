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
 * Domain.
 *
 */

#ifndef SIGNER_DOMAIN_H
#define SIGNER_DOMAIN_H

#include "config.h"
#include "signer/hsm.h"
#include "signer/nsec3params.h"
#include "signer/rrset.h"
#include "signer/signconf.h"

#include <ldns/ldns.h>
#include <time.h>

#define DOMAIN_STATUS_NONE      0
#define DOMAIN_STATUS_APEX      1
#define DOMAIN_STATUS_AUTH      2
#define DOMAIN_STATUS_NS        3
#define DOMAIN_STATUS_ENT_AUTH  4
#define DOMAIN_STATUS_ENT_NS    5
#define DOMAIN_STATUS_ENT_GLUE  6
#define DOMAIN_STATUS_OCCLUDED  7
#define DOMAIN_STATUS_HASH      8

#define SE_NSEC_RDATA_NXT          0
#define SE_NSEC_RDATA_BITMAP       1
#define SE_NSEC3_RDATA_NSEC3PARAMS 4
#define SE_NSEC3_RDATA_NXT         6
#define SE_NSEC3_RDATA_BITMAP      7

/**
 * Domain.
 *
 */
typedef struct domain_struct domain_type;
struct domain_struct {
    ldns_rdf* name;
    domain_type* parent;
    domain_type* nsec3;
    ldns_rbtree_t* rrsets;
    rrset_type* nsec_rrset;
    int domain_status;
    uint32_t inbound_serial;
    uint32_t outbound_serial;
    uint32_t nsec_serial;
    uint8_t nsec_bitmap_changed;
    uint8_t nsec_nxt_changed;
};

/**
 * Create empty domain.
 * \param[in] dname owner name
 * \return domain_type* empty domain
 *
 */
domain_type* domain_create(ldns_rdf* dname);

/**
 * Check if the domain can be opted-out.
 * \param[in] domain domain
 * \return int 1 if can be opted-out, 0 otherwise
 *
 */
int domain_optout(domain_type* domain);

/**
 * Lookup a RRset within the domain.
 * \param[in] domain domain
 * \param[in] type RRtype to look for
 * \return rrset_type* RRset if found
 *
 */
rrset_type* domain_lookup_rrset(domain_type* domain, ldns_rr_type type);

/**
 * Add a RRset to the domain.
 * \param[in] domain domain
 * \param[in] rrset RRset
 * \return rrset_type* added RRset
 *
 */
rrset_type* domain_add_rrset(domain_type* domain, rrset_type* rrset);

/**
 * Delete a RRset from the domain.
 * \param[in] domain domain
 * \param[in] rrset RRset
 * \return rrset_type* RRset if failed
 *
 */
rrset_type* domain_del_rrset(domain_type* domain, rrset_type* rrset);

/**
 * Return the number of RRsets at this domain.
 * \param[in] domain domain
 * \return int number of RRsets at domain
 *
 */
int domain_count_rrset(domain_type* domain);

/**
 * Update domain with pending changes.
 * \param[in] domain domain
 * \param[in] serial version to update to
 * \return int 0 on success, 1 on error
 *
 */
int domain_update(domain_type* domain, uint32_t serial);

/**
 * Update domain status.
 * \param[in] domain domain
 *
 */
void domain_update_status(domain_type* domain);

/**
 * Add NSEC record to domain.
 * \param[in] domain domain
 * \param[in] to next domain
 * \param[in] ttl denial of existence ttl
 * \param[in] klass corresponding klass
 * \return int 0 on success, 1 on error
 *
 */
int domain_nsecify(domain_type* domain, domain_type* to, uint32_t ttl,
    ldns_rr_class klass);

/**
 * Add NSEC3 record to domain.
 * \param[in] domain domain
 * \param[in] to next domain
 * \param[in] ttl denial of existence ttl
 * \param[in] klass corresponding klass
 * \return int 0 on success, 1 on error
 *
 */
int domain_nsecify3(domain_type* domain, domain_type* to, uint32_t ttl,
    ldns_rr_class klass, nsec3params_type* nsec3params);

/**
 * Sign domain.
 * \param[in] ctx HSM context
 * \param[in] domain domain
 * \param[in] owner owner of the zone
 * \param[in] sc sign configuration
 * \param[in] signtime time zone is being signed
 * \return int 0 on success, 1 on error
 *
 */
int domain_sign(hsm_ctx_t* ctx, domain_type* domain, ldns_rdf* owner,
    signconf_type* sc, time_t signtime);

/**
 * Add RR to domain.
 * \param[in] domain domain
 * \param[in] rr RR
 * \return int 0 on success, 1 on error
 *
 */
int domain_add_rr(domain_type* domain, ldns_rr* rr);

/**
 * Delete RR from domain.
 * \param[in] domain domain
 * \param[in] rr RR
 * \return int 0 on success, 1 on error
 *
 */
int domain_del_rr(domain_type* domain, ldns_rr* rr);

/**
 * Delete all RRs from domain.
 * \param[in] domain domain
 * \return int 0 on success, 1 on error
 *
 */
int domain_del_rrs(domain_type* domain);

/**
 * Clean up domain.
 * \param[in] domain domain to cleanup
 *
 */
void domain_cleanup(domain_type* domain);

/**
 * Print domain.
 * \param[in] out file descriptor
 * \param[in] domain domain to print
 * \param[in] internal if true, print in internal format
 *
 */
void domain_print(FILE* fd, domain_type* domain, int internal);

/**
 * Print NSEC(3)s at domain.
 * \param[in] out file descriptor
 * \param[in] domain domain to print
 *
 */
void domain_print_nsec(FILE* fd, domain_type* domain);

/**
 * Print RRSIGs at domain.
 * \param[in] out file descriptor
 * \param[in] domain domain to print
 *
 */
void domain_print_rrsig(FILE* fd, domain_type* domain);

#endif /* SIGNER_DOMAIN_H */
