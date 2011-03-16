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
#include "adapter/adapter.h"
#include "daemon/worker.h"
#include "scheduler/fifoq.h"
#include "shared/allocator.h"
#include "shared/status.h"
#include "signer/denial.h"
#include "signer/domain.h"
#include "signer/keys.h"
#include "signer/signconf.h"
#include "signer/stats.h"
#include "signer/nsec3params.h"

#include <ldns/ldns.h>
#include <stdio.h>


/**
 * Zone data.
 *
 */
typedef struct zonedata_struct zonedata_type;
struct zonedata_struct {
    allocator_type* allocator;
    ldns_rbtree_t* domains;
    ldns_rbtree_t* denial_chain;
    int initialized;
    uint32_t default_ttl; /* fallback ttl */
    uint32_t inbound_serial; /* last seen inbound soa serial */
    uint32_t internal_serial; /* latest internal soa serial */
    uint32_t outbound_serial; /* last written outbound soa serial */
};

/**
 * Initialize denial of existence chain.
 * \param[in] zd zone data
 *
 */
void zonedata_init_denial(zonedata_type* zd);

/**
 * Create empty zone data.
 * \param[in] allocator memory allocator
 * \return zonedata_type* empty zone data tree
 *
 */
zonedata_type* zonedata_create(allocator_type* allocator);

/**
 * Recover zone data from backup.
 * \param[in] zd zone data
 * \param[in] fd backup file descriptor
 * \return ods_status status
 *
 */
ods_status zonedata_recover(zonedata_type* zd, FILE* fd);

/**
 * Recover RR from backup.
 * \param[in] zd zone data
 * \param[in] rr RR to add
 * \return int 0 on success, 1 on false
 *
 */
/*
int zonedata_recover_rr_from_backup(zonedata_type* zd, ldns_rr* rr);
*/

/**
 * Recover RRSIG from backup.
 * \param[in] zd zone data
 * \param[in] rrsig RRSIG to add
 * \param[in] locator key locaotor
 * \param[in] flags key flags
 * \return int 0 on success, 1 on false
 *
 */
/*
int zonedata_recover_rrsig_from_backup(zonedata_type* zd, ldns_rr* rrsig,
    const char* locator, uint32_t flags);
*/

/**
 * Look up domain.
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
 * \return domain_type* added domain
 *
 */
domain_type* zonedata_add_domain(zonedata_type* zd, domain_type* domain);

/**
 * Delete domain from zone data.
 * \param[in] zd zone data
 * \param[in] domain domain to delete
 * \return domain_type* domain if failed
 *
 */
domain_type* zonedata_del_domain(zonedata_type* zd, domain_type* domain);

/**
 * Look up denial of existence data point.
 * \param[in] zd zone data
 * \param[in] name domain name to look for
 * \return domain_type* domain, if found
 *
 */
denial_type* zonedata_lookup_denial(zonedata_type* zd, ldns_rdf* name);

/**
 * Add denial of existence data point to zone data.
 * \param[in] zd zone data
 * \param[in] domain corresponding domain
 * \param[in] apex apex
 * \param[in] nsec3params NSEC3 parameters
 * \return ods_status status
 *
 */
ods_status zonedata_add_denial(zonedata_type* zd, domain_type* domain,
    ldns_rdf* apex, nsec3params_type* nsec3params);

/**
 * Delete denial of existence data point from zone data.
 * \param[in] zd zone data
 * \param[in] denial denial of existence data point
 * \return denial_type* denial of existence data point if failed
 *
 */
denial_type* zonedata_del_denial(zonedata_type* zd, denial_type* denial);

/**
 * Examine updates to zone data.
 * \param[in] zd zone data
 * \param[in] apex apex domain name
 * \param[in] mode adapter mode
 * \return ods_status status
 *
 */
ods_status zonedata_examine(zonedata_type* zd, ldns_rdf* apex,
    adapter_mode mode);

/**
 * Calculate differences at the zonedata between current and new RRsets.
 * \param[in] zd zone data
 * \param[in] kl current key list
 * \return ods_status status
 *
 */
ods_status zonedata_diff(zonedata_type* zd, keylist_type* kl);

/**
 * Commit updates to zone data.
 * \param[in] zd zone data
 * \return ods_status status
 *
 */
ods_status zonedata_commit(zonedata_type* zd);

/**
 * Rollback updates from zone data.
 * \param[in] zd zone data
 *
 */
void zonedata_rollback(zonedata_type* zd);

/**
 * Add empty non-terminals to zone data.
 * \param[in] zd zone data
 * \param[in] apex zone apex
 * \return ods_status status
 *
 */
ods_status zonedata_entize(zonedata_type* zd, ldns_rdf* apex);

/**
 * Add NSEC records to zone data.
 * \param[in] zd zone data
 * \param[in] klass zone class
 * \param[in] ttl NSEC ttl
 * \param[out] num_added number of NSEC RRs added
 * \return ods_status status
 *
 */
ods_status zonedata_nsecify(zonedata_type* zd, ldns_rr_class klass,
    uint32_t ttl, uint32_t* num_added);

/**
 * Add NSEC3 records to zone data.
 * \param[in] zd zone data
 * \param[in] klass zone class
 * \param[in] ttl NSEC3 ttl
 * \param[in] nsec3params NSEC3 parameters
 * \param[out] num_added number of NSEC3 RRs added
 * \return ods_status status
 *
 */
ods_status zonedata_nsecify3(zonedata_type* zd, ldns_rr_class klass,
    uint32_t ttl, nsec3params_type* nsec3params, uint32_t* num_added);

/**
 * Update the serial.
 * \param[in] zd zone data
 * \param[in] sc signer configuration
 * \return ods_status status
 *
 */
ods_status zonedata_update_serial(zonedata_type* zd, signconf_type* sc);

/**
 * Queue all RRsets.
 * \param[in] zd zone data
 * \param[in] q queue
 * \param[in] worker owner of data
 * \return ods_status status
 *
 */
ods_status zonedata_queue(zonedata_type* zd, fifoq_type* q,
    worker_type* worker);

/**
 * Wipe out all NSEC(3) RRsets.
 * \param[in] zd zone data
 *
 */
void zonedata_wipe_denial(zonedata_type* zd);

/**
 * Clean up denial of existence chain.
 * \param[in] zd zone data
 *
 */
void zonedata_cleanup_chain(zonedata_type* zd);

/**
 * Clean up zone data.
 * \param[in] zd zone data to cleanup
 *
 */
void zonedata_cleanup(zonedata_type* zd);

/**
 * Backup zone data.
 * \param[in] fd output file descriptor
 * \param[in] zd zone data
 *
 */
void zonedata_backup(FILE* fd, zonedata_type* zd);

/**
 * Print zone data.
 * \param[in] fd output file descriptor
 * \param[in] zd zone data
 * \return ods_status status
 *
 */
ods_status zonedata_print(FILE* fd, zonedata_type* zd);

/**
 * Log RDF.
 * \param[in] rdf RDF
 * \param[in] pre string to log before RDF
 * \param[in] level log level
 *
 */
void log_rdf(ldns_rdf* rdf, const char* pre, int level);

#endif /* SIGNER_ZONEDATA_H */
