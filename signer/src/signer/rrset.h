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
 * RRset.
 *
 */

#ifndef SIGNER_RRSET_H
#define SIGNER_RRSET_H

#include "config.h"
#include "daemon/worker.h"
#include "scheduler/fifoq.h"
#include "shared/allocator.h"
#include "shared/hsm.h"
#include "shared/locks.h"
#include "shared/status.h"
#include "signer/keys.h"
#include "signer/rrsigs.h"
#include "signer/signconf.h"
#include "signer/stats.h"

#include <ldns/ldns.h>

#define COUNT_RR  0
#define COUNT_ADD 1
#define COUNT_DEL 2

typedef struct rrset_struct rrset_type;
struct rrset_struct {
    allocator_type* allocator;
    ldns_rr_type rr_type;
    uint32_t rr_count;
    uint32_t add_count;
    uint32_t del_count;
    uint32_t rrsig_count;
    int needs_signing;
    ldns_dnssec_rrs* rrs;
    ldns_dnssec_rrs* add;
    ldns_dnssec_rrs* del;
    rrsigs_type* rrsigs;
};

/**
 * Create new RRset.
 * \param[in] rrtype RRtype
 * \return rrset_type* new RRset
 *
 */
rrset_type* rrset_create(ldns_rr_type rrtype);

/**
 * Recover RRSIG from backup.
 * \param[in] rrset RRset
 * \param[in] rrsig RRSIG
 * \param[in] locator key locator
 * \param[in] flags key flags
 * \return ods_status status
 *
 */
ods_status rrset_recover(rrset_type* rrset, ldns_rr* rrsig,
    const char* locator, uint32_t flags);

/**
 * Count the number of RRs in this RRset.
 * \param[in] rrset RRset
 * \param[in] which which RRset to be counted
 * \return size_t number of RRs
 *
 */
size_t rrset_count_rr(rrset_type* rrset, int which);

/**
 * Return the number of RRs in RRset after an update.
 * \param[in] rrset RRset
 * \return size_t number of RRs after an update
 *
 */
size_t rrset_count_RR(rrset_type* rrset);

/**
 * Add RR to RRset.
 * \param[in] rrset RRset
 * \param[in] rr RR
 * \return ldns_rr* added RR
 *
 */
ldns_rr* rrset_add_rr(rrset_type* rrset, ldns_rr* rr);

/**
 * Delete RR from RRset.
 * \param[in] rrset RRset
 * \param[in] rr RR
 * \param[in] dupallowed if true, allow duplicate deletions
 * \return ldns_rr* RR if failed
 *
 */
ldns_rr* rrset_del_rr(rrset_type* rrset, ldns_rr* rr, int dupallowed);

/**
 * Wipe out current RRs in RRset.
 * \param[in] rrset RRset
 * \return ods_status status
 *
 */
ods_status rrset_wipe_out(rrset_type* rrset);

/**
 * Calculate differences between the current RRset and the pending new one.
 * \param[in] rrset RRset
 * \param[in] kl current key list
 * \return ods_status status
 *
 */
ods_status rrset_diff(rrset_type* rrset, keylist_type* kl);

/**
 * Commit updates from RRset.
 * \param[in] rrset RRset
 * \return ods_status status
 *
 */
ods_status rrset_commit(rrset_type* rrset);

/**
 * Rollback updates from RRset.
 * \param[in] rrset RRset
 *
 */
void rrset_rollback(rrset_type* rrset);

/**
 * Sign RRset.
 * \param[in] ctx HSM context
 * \param[in] rrset RRset
 * \param[in] owner owner of the zone
 * \param[in] sc signer configuration
 * \param[in] signtime time when the zone is being signd
 * \param[out] stats update statistics
 * \return ods_status status
 *
 */
ods_status rrset_sign(hsm_ctx_t* ctx, rrset_type* rrset, ldns_rdf* owner,
    signconf_type* sc, time_t signtime, stats_type* stats);

/**
 * Queue RRset.
 * \param[in] rrset RRset
 * \param[in] q queue
 * \param[in] worker owner of RRset
 * \return ods_status status
 *
 */
ods_status rrset_queue(rrset_type* rrset, fifoq_type* q, worker_type* worker);

/**
 * Examine NS RRset and verify its RDATA.
 * \param[in] rrset NS RRset
 * \param[in] nsdname domain name that should match NS RDATA
 * \return int 1 if match, 0 otherwise
 *
 */
int rrset_examine_ns_rdata(rrset_type* rrset, ldns_rdf* nsdname);

/**
 * Clean up RRset.
 * \param[in] rrset RRset to be cleaned up
 *
 */
void rrset_cleanup(rrset_type* rrset);

/**
 * Log RR.
 * \param[in] rr RR
 * \param[in] pre string to log before RR
 * \param[in] level log level
 *
 */
void log_rr(ldns_rr* rr, const char* pre, int level);

/**
 * Print RRset.
 * \param[in] fd file descriptor
 * \param[in] rrset RRset to be printed
 * \param[in] skip_rrsigs if true, don't print RRSIG records
 *
 */
void rrset_print(FILE* fd, rrset_type* rrset, int skip_rrsigs);

/**
 * Backup RRset.
 * \param[in] fd file descriptor
 * \param[in] rrset RRset
 *
 */
void rrset_backup(FILE* fd, rrset_type* rrset);

#endif /* SIGNER_RRSET_H */
