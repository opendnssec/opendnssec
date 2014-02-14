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
#include "shared/status.h"
#include "signer/stats.h"

#include <ldns/ldns.h>
#include <libhsm.h>

/**
 * RRSIG.
 *
 */
typedef struct rrsig_struct rrsig_type;
struct rrsig_struct {
    ldns_rr* rr;
    void* owner;
    const char* key_locator;
    uint32_t key_flags;
};

/**
 * RR.
 *
 */
typedef struct rr_struct rr_type;
struct rr_struct {
    ldns_rr* rr;
    void* owner;
    unsigned exists : 1;
    unsigned is_added : 1;
    unsigned is_removed : 1;
};

/**
 * RRset.
 *
 */
typedef struct rrset_struct rrset_type;
struct rrset_struct {
    rrset_type* next;
    void* zone;
    void* domain;
    ldns_rr_type rrtype;
    rr_type* rrs;
    rrsig_type* rrsigs;
    size_t rr_count;
    size_t rrsig_count;
    unsigned needs_signing : 1;
};

/**
 * Log RR.
 * \param[in] rr RR
 * \param[in] pre log message
 * \param[in] level log level
 *
 */
void log_rr(ldns_rr* rr, const char* pre, int level);

/**
 * Log RRset.
 * \param[in] dname domain name
 * \param[in] type RRtype
 * \param[in] pre log message
 * \param[in] level log level
 *
 */
void log_rrset(ldns_rdf* dname, ldns_rr_type type, const char* pre, int level);

/**
 * Get the string-format of RRtype.
 * \param[in] type RRtype
 * \return const char* string-format of RRtype
 *
 */
const char* rrset_type2str(ldns_rr_type type);

/**
 * Create RRset.
 * \param[in] zoneptr zone reference
 * \param[in] type RRtype
 * \return rrset_type* RRset
 *
 */
rrset_type* rrset_create(void* zoneptr, ldns_rr_type type);

/**
 * Lookup RR in RRset.
 * \param[in] rrset RRset
 * \param[in] rr RR
 * \return rr_type* RR if found
 *
 */
rr_type* rrset_lookup_rr(rrset_type* rrset, ldns_rr* rr);

/**
 * Count the number of RRs in this RRset that have is_added.
 * \param[in] rrset RRset
 * \return size_t number of RRs
 *
 */
size_t rrset_count_rr_is_added(rrset_type* rrset);

/**
 * Add RR to RRset.
 * \param[in] rrset RRset
 * \param[in] rr RR
 * \return rr_type* added RR
 *
 */
rr_type* rrset_add_rr(rrset_type* rrset, ldns_rr* rr);

/**
 * Delete RR from RRset.
 * \param[in] rrset RRset
 * \param[in] rrnum position of RR
 *
 */
void rrset_del_rr(rrset_type* rrset, uint16_t rrnum);

/**
 * Add RRSIG to RRset.
 * \param[in] rrset RRset
 * \param[in] rr RRSIG
 * \param[in] locator key locator
 * \param[in] flags key flags
 * \return rr_type* added RRSIG
 *
 */
rrsig_type* rrset_add_rrsig(rrset_type* rrset, ldns_rr* rr,
    const char* locator, uint32_t flags);

/**
 * Delete RRSIG from RRset.
 * \param[in] rrset RRset
 * \param[in] rrnum position of RRSIG
 *
 */
void rrset_del_rrsig(rrset_type* rrset, uint16_t rrnum);

/**
 * Apply differences at RRset.
 * \param[in] rrset RRset
 * \param[in] is_ixfr true if incremental change
 * \param[in] more_coming more transactions possible
 *
 */
void rrset_diff(rrset_type* rrset, unsigned is_ixfr, unsigned more_coming);

/**
 * Sign RRset.
 * \param[in] ctx HSM context
 * \param[in] rrset RRset
 * \param[in] signtime time when the zone is being signed
 * \return ods_status status
 *
 */
ods_status rrset_sign(hsm_ctx_t* ctx, rrset_type* rrset, time_t signtime);

/**
 * Print RRset.
 * \param[in] fd file descriptor
 * \param[in] rrset RRset to be printed
 * \param[in] skip_rrsigs if true, don't print RRSIG records
 * \param[out] status status
 *
 */
void rrset_print(FILE* fd, rrset_type* rrset, int skip_rrsigs,
    ods_status* status);

/**
 * Clean up RRset.
 * \param[in] rrset RRset to be cleaned up
 *
 */
void rrset_cleanup(rrset_type* rrset);

/**
 * Backup RRset.
 * \param[in] fd file descriptor
 * \param[in] rrset RRset
 *
 */
void rrset_backup2(FILE* fd, rrset_type* rrset);

#endif /* SIGNER_RRSET_H */
