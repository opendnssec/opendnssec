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
#include "signer/nsec3params.h"
#include "signer/signconf.h"
#include "signer/stats.h"
#include "signer/zonedata.h"

#include <ldns/ldns.h>

struct schedule_struct;

/**
 * Zone.
 *
 */
typedef struct zone_struct zone_type;
struct zone_struct {
    allocator_type* allocator; /* memory allocator */
    ldns_rdf* dname; /* wire format zone name */
    ldns_rr_class klass; /* class */

    /* from conf.xml */
    const char* notify_ns; /* master name server reload command */
    int fetch; /* zone fetcher enabled */

    /* from zonelist.xml */
    const char* name; /* string format zone name */
    const char* policy_name; /* policy identifier */
    const char* signconf_filename; /* signconf filename */
    int just_added;
    int just_updated;
    int tobe_removed;
    int processed;
    int prepared;

    /* adapters */
    adapter_type* adinbound; /* inbound adapter */
    adapter_type* adoutbound; /* outbound adapter */

    /* from signconf.xml */
    signconf_type* signconf; /* signer configuration values */
    nsec3params_type* nsec3params; /* NSEC3 parameters */

    /* zone data */
    zonedata_type* zonedata;

    /* worker variables */
    void* task; /* next assigned task */

    /* statistics */
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
 * Load signer configuration for zone.
 * \param[in] zone zone
 * \param[out] tbs task to be scheduled
 * \return ods_status status
 *
 */
ods_status zone_load_signconf(zone_type* zone, task_id* tbs);

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
 * Print zone.
 * \param[in] zone zone
 * \return ods_status status
 *
 */
ods_status zone_print(FILE* fd, zone_type* zone);

/**
 * Examine zone.
 * \param[in] zone zone
 * \return ods_status status
 *
 */
ods_status zone_examine(zone_type* zone);

/**
 * Clean up zone.
 * \param[in] zone zone
 *
 */
void zone_cleanup(zone_type* zone);

#endif /* SIGNER_ZONE_H */
