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
 * Zone.
 *
 */

#ifndef SIGNER_ZONE_H
#define SIGNER_ZONE_H

#include "config.h"
#include "adapter/adapter.h"
#include "scheduler/task.h"
#include "shared/allocator.h"
#include "shared/locks.h"
#include "shared/status.h"
#include "signer/denial.h"
#include "signer/domain.h"
#include "signer/nsec3params.h"
#include "signer/signconf.h"
#include "signer/stats.h"

#include <ldns/ldns.h>

#define DEFAULT_TTL 3600;

struct schedule_struct;

/**
 * Zone.
 *
 */
typedef struct zone_struct zone_type;
struct zone_struct {
    /** common stuff */
    allocator_type* allocator;
    ldns_rdf* origin; /* wire format zone name */
    ldns_rr_class klass; /* class */
    uint32_t default_ttl;

    /** from conf.xml */
    const char* notify_ns; /* master name server reload command */
    int fetch; /* zone fetcher enabled */

    /** from zonelist.xml */
    const char* name; /* string format zone name */
    const char* policy_name; /* policy identifier */
    const char* signconf_filename; /* signconf filename */
    int just_added;
    int just_updated;
    int tobe_removed;

    /** adapters */
    adapter_type* adinbound; /* inbound adapter */
    adapter_type* adoutbound; /* outbound adapter */

    /** from signconf.xml */
    signconf_type* signconf; /* signer configuration values */
    nsec3params_type* nsec3params; /* NSEC3 parameters */

    /** zone data */
    ldns_rbtree_t* domains;
    ldns_rbtree_t* denials;

    /** serial management */
    uint32_t inbound_serial;
    uint32_t internal_serial;
    uint32_t outbound_serial;
    int initialized;

    /** worker variables */
    void* task; /* next assigned task */
    int processed; /* for single run usage */

    /** statistics */
    stats_type* stats;

    lock_basic_type zone_lock;
};

/**
 * Create a new zone.
 * \param[in] name zone name
 * \param[in] klass zone class
 * \return zone_type* zone
 *
 */
zone_type* zone_create(char* name, ldns_rr_class klass);

/**
 * Initialize zone data domains.
 * \param[in] zone zone
 *
 */
void zone_init_domains(zone_type* zone);

/**
 * Initialize denial of existence chain.
 * \param[in] zone zone
 *
 */
void zone_init_denials(zone_type* zone);

/**
 * Look up domain.
 * \param[in] zone zone
 * \param[in] name domain name to look for
 * \return domain_type* domain, if found
 *
 */
domain_type* zone_lookup_domain(zone_type* zone, ldns_rdf* name);

/**
 * Add domain to zone.
 * \param[in] zone zone
 * \param[in] domain domain to add
 * \return domain_type* added domain
 *
 */
domain_type* zone_add_domain(zone_type* zone, domain_type* domain);

/**
 * Delete domain from zone.
 * \param[in] zone zone
 * \param[in] domain domain to delete
 * \return domain_type* domain if failed
 *
 */
domain_type* zone_del_domain(zone_type* zone, domain_type* domain);

/**
 * Look up denial of existence data point.
 * \param[in] zone zone data
 * \param[in] name domain name to look for
 * \return domain_type* domain, if found
 *
 */
denial_type* zone_lookup_denial(zone_type* zone, ldns_rdf* name);

/**
 * Add denial of existence data point to zone.
 * \param[in] zone zone
 * \param[in] domain corresponding domain
 * \return ods_status status
 *
 */
ods_status zone_add_denial(zone_type* zone, domain_type* domain);

/**
 * Delete denial of existence data point from zone data.
 * \param[in] zone zone data
 * \param[in] denial denial of existence data point
 * \return denial_type* denial of existence data point if failed
 *
 */
denial_type* zone_del_denial(zone_type* zone, denial_type* denial);

/**
 * Add RR.
 * \param[in] zone zone
 * \param[in] rr rr
 * \param[in] do_stats true if we need to maintain statistics
 * \return ods_status status
 *
 */
ods_status zone_add_rr(zone_type* zone, ldns_rr* rr, int do_stats);

/**
 * Delete RR.
 * \param[in] zone zone
 * \param[in] rr rr
 * \param[in] do_stats true if we need to maintain statistics
 * \return ods_status status
 *
 */
ods_status zone_del_rr(zone_type* zone, ldns_rr* rr, int do_stats);

/**
 * Calculate zone differences between current and new RRsets.
 * \param[in] zone zone
 * \param[in] kl key list
 * \return ods_status status
 *
 */
ods_status zonedata_diff(zone_type* zone, keylist_type* kl);

/**
 * Commit updates to zone data.
 * \param[in] zone zone
 * \return ods_status status
 *
 */
ods_status zonedata_commit(zone_type* zone);

/**
 * Rollback updates from zone data.
 * \param[in] zone zone
 *
 */
void zonedata_rollback(zone_type* zone);

/**
 * Queue all RRsets.
 * \param[in] zone zone
 * \param[in] q queue
 * \param[in] worker owner of data
 * \return ods_status status
 *
 */
ods_status zonedata_queue(zone_type* zone, fifoq_type* q, worker_type* worker);

/**
 * Add empty non-terminals to zone.
 * \param[in] zone zone
 * \return ods_status status
 *
 */
ods_status zone_entize(zone_type* zone);

/**
 * Load signer configuration for zone.
 * \param[in] zone zone
 * \return ods_status status
 *
 */
ods_status zone_load_signconf(zone_type* zone);

/**
 * Publish DNSKEYs.
 * \param[in] zone zone
 * \param[in] recover true if in recovery mode
 * \return ods_status status
 *
 */
ods_status zone_publish_dnskeys(zone_type* zone, int recover);

/**
 * Prepare for NSEC3.
 * \param[in] zone zone
 * \param[in] recover true if in recovery mode
 * \return ods_status status
 *
 */
ods_status zone_prepare_nsec3(zone_type* zone, int recover);

/**
 * Add NSEC records to zone.
 * \param[in] zone zone
 * \param[out] num_added number of NSEC RRs added
 * \return ods_status status
 *
 */
ods_status zone_nsecify(zone_type* zone, uint32_t* num_added);

/**
 * Add NSEC3 records to zone.
 * \param[in] zone zone
 * \param[out] num_added number of NSEC3 RRs added
 * \return ods_status status
 *
 */
ods_status zone_nsecify3(zone_type* zone, uint32_t* num_added);

/**
 * Merge zones.
 * \param[in] z1 zone
 * \param[in] z2 zone with new values
 *
 */
void zone_merge(zone_type* z1, zone_type* z2);

/**
 * Update serial.
 * \param[in] zone zone
 * \return ods_status status
 *
 */
ods_status zone_update_serial(zone_type* zone);

/**
 * Examine zone.
 * \param[in] zone zone
 * \return ods_status status
 *
 */
ods_status zone_examine(zone_type* zone);

/**
 * Print zone.
 * \param[in] zone zone
 * \return ods_status status
 *
 */
ods_status zone_print(FILE* fd, zone_type* zone);

/**
 * Wipe out all NSEC(3) RRsets.
 * \param[in] zd zone data
 *
 */
void zone_wipe_denials(zone_type* zone);

/**
 * Clean up denial of existence chain.
 * \param[in] zd zone data
 *
 */
void zone_cleanup_domains(zone_type* zone);

/**
 * Clean up domains.
 * \param[in] zd zone data
 *
 */
void zone_cleanup_denials(zone_type* zone);

/**
 * Clean up zone data.
 * \param[in] zone zone
 *
 */
void zonedata_cleanup(zone_type* zone);

/**
 * Clean up zone.
 * \param[in] zone zone
 *
 */
void zone_cleanup(zone_type* zone);

/**
 * Log RDF.
 * \param[in] rdf RDF
 * \param[in] pre string to log before RDF
 * \param[in] level log level
 *
 */
void log_rdf(ldns_rdf* rdf, const char* pre, int level);

/**
 * Backup zone.
 * \param[in] zone corresponding zone
 * \return ods_status status
 *
 */
ods_status zone_backup(zone_type* zone);

/**
 * Recover zone from backup.
 * \param[in] zone corresponding zone
 *
 */
ods_status zone_recover(zone_type* zone);

#endif /* SIGNER_ZONE_H */
