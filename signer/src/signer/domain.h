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
#include "shared/hsm.h"
#include "signer/nsec3params.h"
#include "signer/rrset.h"
#include "signer/signconf.h"
#include "signer/stats.h"

#include <ldns/ldns.h>
#include <time.h>

#define DOMAIN_STATUS_NONE      0 /* initial domain status */
#define DOMAIN_STATUS_APEX      1 /* apex of the zone */
#define DOMAIN_STATUS_AUTH      2 /* authoritative domain */
#define DOMAIN_STATUS_NS        3 /* unsigned delegation */
#define DOMAIN_STATUS_DS        4 /* signed delegation */
#define DOMAIN_STATUS_ENT_AUTH  5 /* empty non-terminal to authoritative data */
#define DOMAIN_STATUS_ENT_NS    6 /* empty non-terminal to unsigned delegation */
#define DOMAIN_STATUS_ENT_GLUE  7 /* empty non-terminal to occluded data */
#define DOMAIN_STATUS_OCCLUDED  8 /* occluded data (glue) */
#define DOMAIN_STATUS_HASH      9 /* hashed domain */

#define SE_NSEC_RDATA_NXT          0
#define SE_NSEC_RDATA_BITMAP       1
#define SE_NSEC3_RDATA_NSEC3PARAMS 4
#define SE_NSEC3_RDATA_NXT         4
#define SE_NSEC3_RDATA_BITMAP      5

/**
 * Domain.
 *
 */
typedef struct domain_struct domain_type;
struct domain_struct {
    /* General domain info */
    ldns_rdf* dname;
    domain_status dstatus;
    allocator_type* allocator;

    /* Family */
    domain_type* parent;

    /* Denial of Existence */
    denial_type* denial;
 
    domain_type* nsec3;
    rrset_type* nsec_rrset;
    size_t subdomain_count;
    size_t subdomain_auth;
    uint32_t internal_serial;
    uint32_t outbound_serial;
    uint8_t nsec_bitmap_changed;
    uint8_t nsec_nxt_changed;

    /* RRsets */
    ldns_rbtree_t* rrsets;
};

/**
 * Create empty domain.
 * \param[in] dname owner name
 * \return domain_type* empty domain
 *
 */
domain_type* domain_create(ldns_rdf* dname);

/**
 * Recover domain from backup.
 * \param[in] fd backup file descriptor
 * \return domain_type* recovered domain
 *
 */
domain_type* domain_recover_from_backup(FILE* fd);

/**
 * Count the number of RRsets at this domain.
 * \param[in] domain domain
 * \return size_t number of RRsets
 *
 */
size_t domain_count_rrset(domain_type* domain);

/**
 * Look up RRset at this domain.
 * \param[in] domain the domain
 * \param[in] rrtype RRtype
 * \return rrset_type* RRset, if found
 *
 */
rrset_type* domain_lookup_rrset(domain_type* domain, ldns_rr_type type);

/**
 * Add RRset to domain.
 * \param[in] domain domain
 * \param[in] rrset RRset
 * \param[in] recover if true, don't update domain status
 * \return rrset_type* added RRset
 *
 */
rrset_type* domain_add_rrset(domain_type* domain, rrset_type* rrset, int recover);

/**
 * Delete RRset from domain.
 * \param[in] domain domain
 * \param[in] rrset RRset
 * \param[in] recover if true, don't update domain status
 * \return rrset_type* RRset if failed
 *
 */
rrset_type* domain_del_rrset(domain_type* domain, rrset_type* rrset, int recover);

/**
 * Examine domain and verify if data exists.
 * \param[in] domain domain
 * \param[in] rrtype RRtype look for a specific RRset
 * \param[in] skip_glue skip glue records
 * \retun int 0 if data is alone, 1 otherwise
 *
 */
int domain_examine_data_exists(domain_type* domain, ldns_rr_type rrtype,
    int skip_glue);

/**
 * Examine domain NS RRset and verify its RDATA.
 * \param[in] domain domain
 * \param[in] nsdname domain name that should match one of the NS RDATA
 * \return int 0 if nsdname exists as NS RDATA, 1 otherwise
 *
 */
int domain_examine_ns_rdata(domain_type* domain, ldns_rdf* nsdname);

/**
 * Examine domain and verify if it is a valid zonecut (or no NS RRs).
 * \param[in] domain domain
 * \retun int 0 if the RRset is a valid zonecut (or no zonecut), 1 otherwise
 *
 */
int domain_examine_valid_zonecut(domain_type* domain);

/**
 * Examine domain and verify if there is no other data next to a RRset.
 * \param[in] domain domain
 * \param[in] rrtype RRtype
 * \retun int 0 if the RRset is alone, 1 otherwise
 *
 */
int domain_examine_rrset_is_alone(domain_type* domain, ldns_rr_type rrtype);

/**
 * Examine domain and verify if the RRset is a singleton.
 * \param[in] domain domain
 * \param[in] rrtype RRtype
 * \retun int 0 if the RRset is a singleton, 1 otherwise
 *
 */
int domain_examine_rrset_is_singleton(domain_type* domain, ldns_rr_type rrtype);

/**
 * Update domain with pending changes.
 * \param[in] domain domain
 * \param[in] serial version to update to
 * \return int 0 on success, 1 on error
 *
 */
int domain_update(domain_type* domain, uint32_t serial);

/**
 * Cancel update.
 * \param[in] domain domain
 *
 */
void domain_cancel_update(domain_type* domain);

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
 * \param[out] stats update statistics
 * \return int 0 on success, 1 on error
 *
 */
int domain_nsecify(domain_type* domain, domain_type* to, uint32_t ttl,
    ldns_rr_class klass, stats_type* stats);

/**
 * Add NSEC3 record to domain.
 * \param[in] domain domain
 * \param[in] to next domain
 * \param[in] ttl denial of existence ttl
 * \param[in] klass corresponding klass
 * \param[out] stats update statistics
 * \return int 0 on success, 1 on error
 *
 */
int domain_nsecify3(domain_type* domain, domain_type* to, uint32_t ttl,
    ldns_rr_class klass, nsec3params_type* nsec3params, stats_type* stats);

/**
 * Sign domain.
 * \param[in] ctx HSM context
 * \param[in] domain domain
 * \param[in] owner owner of the zone
 * \param[in] sc sign configuration
 * \param[in] signtime time zone is being signed
 * \param[in] serial outbound serial
 * \param[out] stats update statistics
 * \return int 0 on success, 1 on error
 *
 */
int domain_sign(hsm_ctx_t* ctx, domain_type* domain, ldns_rdf* owner,
    signconf_type* sc, time_t signtime, uint32_t serial, stats_type* stats);

/**
 * Add RR to domain.
 * \param[in] domain domain
 * \param[in] rr RR
 * \return int 0 on success, 1 on error
 *
 */
int domain_add_rr(domain_type* domain, ldns_rr* rr);

/**
 * Recover RR from backup.
 * \param[in] domain domain
 * \param[in] rr RR
 * \return int 0 on success, 1 on error
 *
 */
int domain_recover_rr_from_backup(domain_type* domain, ldns_rr* rr);

/**
 * Recover RRSIG from backup.
 * \param[in] domain domain
 * \param[in] rrsig RRSIG
 * \param[in] type_covered RRtype that is covered by rrsig
 * \param[in] locator key locator
 * \param[in] flags key flags
 * \return int 0 on success, 1 on error
 *
 */
int domain_recover_rrsig_from_backup(domain_type* domain, ldns_rr* rrsig,
    ldns_rr_type type_covered, const char* locator, uint32_t flags);

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
 * \param[in] fd output file descriptor
 * \param[in] domain domain
 *
 */
void domain_print(FILE* fd, domain_type* domain);

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
