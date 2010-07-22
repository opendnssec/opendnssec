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
 * Zone data.
 *
 */

#ifndef SIGNER_ZONEDATA_H
#define SIGNER_ZONEDATA_H

#include "config.h"
#include "signer/domain.h"
#include "signer/signconf.h"

#include <ldns/ldns.h>

/**
 * Zone data.
 *
 */
typedef struct zonedata_struct zonedata_type;
struct zonedata_struct {
    ldns_rbtree_t* domains;
    ldns_rbtree_t* nsec3_domains;
    int initialized;
    uint32_t default_ttl; /* fallback ttl */
    uint32_t inbound_serial; /* last seen inbound soa serial */
    uint32_t outbound_serial; /* last written outbound soa serial */
};

/**
 * Create empty zone data..
 * \return zonedata_type* empty zone data tree
 *
 */
zonedata_type* zonedata_create(void);

/**
 * Look up domain in zone data.
 * \param[in] zd zone data
 * \param[in] name domain name to look for
 * \return domain_type* domain, if found
 *
 */
domain_type* zonedata_lookup_domain(zonedata_type* zd, ldns_rdf* name);

/**
 * Add domain to zone data.
 * \param[in] zd zone data
 * \param[in] domain domain to add
 * \param[in] at_apex if is at apex of the zone
 * \return domain_type* added domain
 *
 */
domain_type* zonedata_add_domain(zonedata_type* zd, domain_type* domain,
    int at_apex);

/**
 * Delete domain from zone data.
 * \param[in] zd zone data
 * \param[in] domain domain to delete
 * \return domain_type* domain if failed
 *
 */
domain_type* zonedata_del_domain(zonedata_type* zd, domain_type* domain);

/**
 * Add empty non-terminals to zone data.
 * \param[in] zd zone data
 * \param[in] apex apex domain name
 * \return int 0 on success, 1 on false
 *
 */
int zonedata_entize(zonedata_type* zd, ldns_rdf* apex);

/**
 * Add NSEC records to zone data.
 * \param[in] zd zone data
 * \param[in] klass class of zone
 * \return int 0 on success, 1 on false
 *
 */
int zonedata_nsecify(zonedata_type* zd, ldns_rr_class klass);

/**
 * Add NSEC3 records to zone data.
 * \param[in] zd zone data
 * \param[in] klass class of zone
 * \param[in] nsec3params NSEC3 paramaters
 * \return int 0 on success, 1 on false
 *
 */
int zonedata_nsecify3(zonedata_type* zd, ldns_rr_class klass,
    nsec3params_type* nsec3params);

/**
 * Add RRSIG records to zone data.
 * \param[in] zd zone data
 * \param[in] owner zone owner
 * \param[in] sc signer configuration
 * \return int 0 on success, 1 on false
 *
 */
int zonedata_sign(zonedata_type* zd, ldns_rdf* owner, signconf_type* sc);

/**
 * Update zone data with pending changes.
 * \param[in] zd zone data
 * \param[in] sc signer configuration
 * \return int 0 on success, 1 on false
 *
 */
int zonedata_update(zonedata_type* zd, signconf_type* sc);

/**
 * Add RR to zone data.
 * \param[in] zd zone data
 * \param[in] rr RR to add
 * \param[in] at_apex if is at apex of the zone
 * \return int 0 on success, 1 on false
 *
 */
int zonedata_add_rr(zonedata_type* zd, ldns_rr* rr, int at_apex);

/**
 * Delete RR from zone data.
 * \param[in] zd zone data
 * \param[in] rr RR to delete
 * \return int 0 on success, 1 on false
 *
 */
int zonedata_del_rr(zonedata_type* zd, ldns_rr* rr);

/**
 * Delete all current RRs from zone data.
 * \param[in] zd zone data
 * \return int 0 on success, 1 on false
 *
 */
int zonedata_del_rrs(zonedata_type* zd);

/**
 * Clean up zone data.
 * \param[in] zonedata zone data to cleanup
 *
 */
void zonedata_cleanup(zonedata_type* zonedata);

/**
 * Print zone data.
 * \param[in] out file descriptor
 * \param[in] zd zone data to print
 * \param[in] internal if true, print in internal format
 *
 */
void zonedata_print(FILE* fd, zonedata_type* zd, int skip_soa);

/**
 * Print NSEC(3)s in zone data.
 * \param[in] out file descriptor
 * \param[in] zd zone data to print
 *
 */
void zonedata_print_nsec(FILE* fd, zonedata_type* zd);

/**
 * Print RRSIGs in zone data.
 * \param[in] out file descriptor
 * \param[in] zd zone data to print
 *
 */
void zonedata_print_rrsig(FILE* fd, zonedata_type* zd);

#endif /* SIGNER_ZONEDATA_H */
