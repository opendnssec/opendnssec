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
#include "scheduler/locks.h"
#include "signer/nsec3params.h"
#include "signer/signconf.h"
#include "signer/stats.h"
#include "signer/zonedata.h"

#include <ldns/ldns.h>

struct task_struct;
struct tasklist_struct;
struct worker_struct;

/**
 * Zone.
 *
 */
typedef struct zone_struct zone_type;
struct zone_struct {
    const char* name; /* string format zone name */
    ldns_rdf* dname; /* wire format zone name */
    ldns_rr_class klass; /* class */
    nsec3params_type* nsec3params; /* NSEC3 parameters */
    zonedata_type* zonedata; /* zone data */

    /* from conf.xml */
    const char* notify_ns; /* master name server reload command */

    /* from signconf.xml */
    signconf_type* signconf; /* signer configuration values */

    /* from zonelist.xml */
    const char* policy_name; /* policy identifier */
    const char* signconf_filename; /* signer configuration filename */
    adapter_type* inbound_adapter; /* inbound adapter */
    adapter_type* outbound_adapter; /* outbound adapter */
    int just_added;
    int just_updated;
    int tobe_removed;
    int processed;

    /* worker variables */
    struct task_struct* task; /* current scheduled task */
    struct worker_struct* worker; /* current active worker */
    time_t backoff; /* backoff value if there is something failing */
    int in_progress; /* in progress (check with active worker?) */
    stats_type* stats; /* statistics */
    lock_basic_type zone_lock;
};

/**
 * Create a new zone.
 * \param[in] name zone name
 * \param[in] klass zone class
 * \return zone_type* zone
 *
 */
zone_type* zone_create(const char* name, ldns_rr_class klass);

/**
 * Update zone configuration settings from zone list.
 * \param[in] z1 zone to be updated
 * \param[in] z2 update
 *
 */
void zone_update_zonelist(zone_type* z1, zone_type* z2);

/**
 * Update signer configuration file.
 * \param[in] zone corresponding zone
 * \param[in] tl task list
 * \param[in] buf feedback buffer
 * \return int 0 on success, 1 on error
 *
 */
int zone_update_signconf(zone_type* zone, struct tasklist_struct* tl,
    char* buf);

/**
 * Update zone data.
 * \param[in] zone corresponding zone
 * \return int 0 on success, 1 on error
 *
 */
int zone_update_zonedata(zone_type* zone);

/**
 * Add DNSKEY and NSEC3PARAM records to the zone.
 * \param[in] zone corresponding zone
 * \return int 0 on success, 1 on error
 *
 */
int zone_add_dnskeys(zone_type* zone);

/**
 * Add a RR to the zone.
 * \param[in] zone zone structure
 * \param[in] rr RR
 * \param[in] recover true if we are recovering from backup
 * \return int 0 on success, 1 on error
 *
 */
int zone_add_rr(zone_type* zone, ldns_rr* rr, int recover);

/**
 * Delete a RR from the zone.
 * \param[in] zone zone structure
 * \param[in] rr RR
 * \return int 0 on success, 1 on error
 *
 */
int zone_del_rr(zone_type* zone, ldns_rr* rr);

/**
 * Nsecify zone.
 * \param[in] zone zone to nsecify
 * \return int 0 on success, 1 on error
 *
 */
int zone_nsecify(zone_type* zone);

/**
 * Sign zone.
 * \param[in] zone zone to sign
 * \return int 0 on success, 1 on error
 *
 */
int zone_sign(zone_type* zone);

/**
 * Backup zone state.
 * \param[in] zone corresponding zone
 * \return int 0 on success, 1 on error
 *
 */
int zone_backup_state(zone_type* zone);

/**
 * Recover from backup.
 * \param[in] zone corresponding zone
 * \param[in] tl task list
 *
 */
void zone_recover_from_backup(zone_type* zone, struct tasklist_struct* tl);

/**
 * Clean up a zone.
 * \param[in] zone zone to cleanup
 *
 */
void zone_cleanup(zone_type* zone);

/**
 * Print a zone.
 * \param[in] out file descriptor
 * \param[in] zone zone to print
 *
 */
void zone_print(FILE* fd, zone_type* zone);

#endif /* SIGNER_ZONE_H */
