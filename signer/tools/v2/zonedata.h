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
#include "v2/domain.h"
#include "v2/nsec3params.h"

#include <ldns/ldns.h>

/**
 * Zone data.
 *
 */
typedef struct zonedata_struct zonedata_type;
struct zonedata_struct {
    ldns_rbtree_t* domains;
    ldns_rbtree_t* nsec3_domains;
};

/**
 * Create empty zone data..
 * \return zonedata_type* empty zone data tree
 *
 */
zonedata_type* zonedata_create(void);

/**
 * Add RR to zone data.
 * \param[in] zd zone data
 * \param[in] rr RR to add
 * \param[in] at_apex if is at apex of the zone
 * \return int 0 on success, 1 on false.
 *
 */
int zonedata_add_rr(zonedata_type* zd, ldns_rr* rr, int at_apex);



/**
 * Add domain to zone data.
 * \param[in] zd zone data
 * \param[in] domain domain to add
 * \param[in] at_apex if is at apex of the zone
 * \return domain_type* added domain
 *
 */
domain_type* zonedata_add_domain(zonedata_type* zd, domain_type* domain, int at_apex);

/**
 * Add empty non-terminals to the zonedata, discover glue.
 * \param[in] zd zone data
 * \param[in] apex apex domain name
 * \return 0 on success, 1 on error
 *
 */
int zonedata_entize(zonedata_type* zd, ldns_rdf* apex);

/**
 * Add NSEC records to the zonedata.
 * \param[in] zd zone data
 * \param[in] ttl ttl to use for NSEC records
 * \param[in] klass class to use for NSEC records
 * \return 0 on success, 1 on error
 *
 */
int zonedata_nsecify_nsec(zonedata_type* zd, uint32_t ttl,
    ldns_rr_class klass);

/**
 * Add NSEC3 records to the zonedata.
 * \param[in] zd zone data
 * \param[in] ttl ttl to use for NSEC3 records
 * \param[in] klass class to use for NSEC records
 * \param[in] nsec3params NSEC3 paramaeters
 * \return 0 on success, 1 on error
 *
 */
int zonedata_nsecify_nsec3(zonedata_type* zd, uint32_t ttl,
    ldns_rr_class klass, nsec3params_type* nsec3params);

/**
 * Look up domain in zone data.
 * \param[in] zd zone data
 * \param[in] domain domain to look for
 * \return domain_type* domain, if found
 *
 */
domain_type* zonedata_lookup_domain(zonedata_type* zd, domain_type* domain);

/**
 * Clean up domains in zone data.
 * \param[in] domain_tree tree with domains
 *
 */
void zonedata_cleanup_domains(ldns_rbtree_t* domain_tree);

/**
 * Clean up zone data.
 * \param[in] zonedata zone data to cleanup
 *
 */
void zonedata_cleanup(zonedata_type* zonedata);

/**
 * Print zone data.
 * \param[in] out file descriptor
 * \param[in] zone data zone data to print
 *
 */
void zonedata_print(FILE* fd, zonedata_type* zonedata);

#endif /* SIGNER_ZONEDATA_H */
