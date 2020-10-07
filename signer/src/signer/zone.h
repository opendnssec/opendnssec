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

#ifndef SIGNER_ZONE_H
#define SIGNER_ZONE_H

#include "config.h"
#include <ldns/ldns.h>

enum zone_zl_status_enum {
    ZONE_ZL_OK = 0,
    ZONE_ZL_ADDED,
    ZONE_ZL_UPDATED,
    ZONE_ZL_REMOVED
};
typedef enum zone_zl_status_enum zone_zl_status;

typedef struct zone_struct zone_type;

#include "adapter/adapter.h"
#include "scheduler/schedule.h"
#include "locks.h"
#include "status.h"
#include "signer/ixfr.h"
#include "signer/namedb.h"
#include "signer/signconf.h"
#include "signer/stats.h"
#include "signer/rrset.h"
#include "wire/buffer.h"
#include "wire/notify.h"
#include "wire/xfrd.h"
#include "datastructure.h"
#include "daemon/engine.h"

struct schedule_struct;

struct zone_struct {
    ldns_rdf* apex; /* wire format zone name */
    ldns_rr_class klass; /* class */
    uint32_t default_ttl; /* ttl */
    /* from conf.xml */
    char *notify_command; /* placeholder for the whole notify command */
    const char* notify_ns; /* master name server reload command */
    char** notify_args; /* reload command arguments */
    /* from zonelist.xml */
    const char* name; /* string format zone name */
    const char* policy_name; /* policy identifier */
    const char* signconf_filename; /* signconf filename */
    zone_zl_status zl_status; /* zonelist status */
    /* adapters */
    adapter_type* adinbound; /* inbound adapter */
    adapter_type* adoutbound; /* outbound adapter */
    /* from signconf.xml */
    signconf_type* signconf; /* signer configuration values */
    /* zone data */
    namedb_type* db;
    ixfr_type* ixfr;
    /* zone transfers */
    xfrd_type* xfrd;
    notify_type* notify;
    /* statistics */
    stats_type* stats;
    pthread_mutex_t zone_lock;
    pthread_mutex_t xfr_lock;
    /* backing store for rrsigs (both domain as denial) */
    collection_class rrstore;
    int zoneconfigvalid; /* flag indicating whether the signconf has at least once been read */
};


/**
 * Create a new zone.
 * \param[in] name zone name
 * \param[in] klass zone class
 * \return zone_type* zone
 *
 */
extern zone_type* zone_create(char* name, ldns_rr_class klass);

/**
 * Load signer configuration for zone.
 * \param[in] zone zone
 * \param[out] new_signconf new signer configuration
 * \return ods_status status
 *         ODS_STATUS_OK: new signer configuration loaded
 *         ODS_STATUS_UNCHANGED: signer configuration has not changed
 *         other: signer configuration not loaded, error occurred
 *
 */
extern ods_status zone_load_signconf(zone_type* zone, signconf_type** new_signconf);

/**
 * Reschedule task for zone.
 * \param[in] zone zone
 * \param[in] taskq task queue
 * \param[in] what new task identifier
 * \return ods_status status
 *
 */
extern ods_status zone_reschedule_task(zone_type* zone, schedule_type* taskq,
    task_id what);

/**
 * Publish the keys as indicated by the signer configuration.
 * \param[in] zone zone
 * \return ods_status status
 *
 */
extern ods_status zone_publish_dnskeys(zone_type* zone, int skip_hsm_access);

/**
 * Unlink DNSKEY RRs.
 * \param[in] zone zone
 *
 */
extern void zone_rollback_dnskeys(zone_type* zone);

/**
 * Publish the NSEC3 parameters as indicated by the signer configuration.
 * \param[in] zone zone
 * \return ods_status status
 *
 */
extern ods_status zone_publish_nsec3param(zone_type* zone);

/**
 * Unlink NSEC3PARAM RR.
 * \param[in] zone zone
 *
 */
extern void zone_rollback_nsec3param(zone_type* zone);

/**
 * Prepare keys for signing.
 * \param[in] zone zone
 * \return ods_status status
 *
 */
extern ods_status zone_prepare_keys(zone_type* zone);

/**
 * Update serial.
 * \param[in] zone zone
 * \return ods_status status
 *
 */
extern ods_status zone_update_serial(zone_type* zone);

/**
 * Lookup RRset.
 * \param[in] zone zone
 * \param[in] owner RRset owner
 * \param[in] type RRtype
 * \return rrset_type* RRset, if found
 *
 */
extern rrset_type* zone_lookup_rrset(zone_type* zone, ldns_rdf* owner,
    ldns_rr_type type);

/**
 * Add RR.
 * \param[in] zone zone
 * \param[in] rr rr
 * \param[in] do_stats true if we need to maintain statistics
 * \return ods_status status
 *         ODS_STATUS_OK: rr to be added to zone
 *         ODS_STATUS_UNCHANGED: rr not added to zone, rr already exists
 *         other: rr not added to zone, error occurred
 *
 */
extern ods_status zone_add_rr(zone_type* zone, ldns_rr* rr, int do_stats);

/**
 * Delete RR.
 * \param[in] zone zone
 * \param[in] rr rr
 * \param[in] do_stats true if we need to maintain statistics
 * \return ods_status status
 *         ODS_STATUS_OK: rr to be removed from zone
 *         ODS_STATUS_UNCHANGED: rr not removed from zone, rr does not exist
 *         other: rr not removed from zone, error occurred
 *
 */
extern ods_status zone_del_rr(zone_type* zone, ldns_rr* rr, int do_stats);

/**
 * Remove all NSEC3PARAM RRs from the zone
 * \return ODS_STATUS_UNCHANGED or ODS_STATUS_OK
 */ 
extern ods_status zone_del_nsec3params(zone_type* zone);

/**
 * Merge zones. Values that are merged:
 * - policy name
 * - signconf filename
 * - input and output adapter
 *
 * \param[in] z1 zone
 * \param[in] z2 zone with new values
 *
 */
extern void zone_merge(zone_type* z1, zone_type* z2);

/**
 * Clean up zone.
 * \param[in] zone zone
 *
 */
extern void zone_cleanup(zone_type* zone);

/**
 * Backup zone.
 * \param[in] zone corresponding zone
 * \return ods_status status
 *
 */
extern ods_status zone_backup2(zone_type* zone, time_t nextResign);

/**
 * Recover zone from backup.
 * \param[in] zone corresponding zone
 *
 */
extern ods_status zone_recover2(engine_type* engine, zone_type* zone);

#endif /* SIGNER_ZONE_H */
