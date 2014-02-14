/*
 * $Id$
 *
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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
 * Denial of Existence.
 *
 */

#include "config.h"
#include "shared/log.h"
#include "signer/denial.h"
#include "signer/domain.h"
#include "signer/zone.h"

#define SE_MAX_RRTYPE_COUNT 65536

static const char* denial_str = "denial";


/**
 * Create new Denial of Existence data point.
 *
 */
denial_type*
denial_create(void* zoneptr, ldns_rdf* dname)
{
    denial_type* denial = NULL;
    zone_type* zone = (zone_type*) zoneptr;
    if (!dname || !zoneptr) {
        return NULL;
    }
    denial = (denial_type*) allocator_alloc(
        zone->allocator, sizeof(denial_type));
    if (!denial) {
        ods_log_error("[%s] unable to create denial: allocator_alloc() "
            "failed", denial_str);
        return NULL;
    }
    denial->dname = dname;
    denial->zone = zoneptr;
    denial->domain = NULL; /* no back reference yet */
    denial->node = NULL; /* not in db yet */
    denial->rrset = NULL;
    denial->bitmap_changed = 0;
    denial->nxt_changed = 0;
    return denial;
}


/**
 * Create NSEC(3) Type Bitmaps Field.
 *
 */
static void
denial_create_bitmap(denial_type* denial, ldns_rr_type types[],
    size_t* types_count)
{
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;

    ods_log_assert(denial);
    ods_log_assert(denial->domain);

    domain = (domain_type*) denial->domain;
    rrset = domain->rrsets;
    while (rrset) {
        ldns_rr_type dstatus = domain_is_occluded(domain);
        if (dstatus == LDNS_RR_TYPE_SOA) {
            /* Authoritative or delegation */
            dstatus = domain_is_delegpt(domain);
            if (dstatus == LDNS_RR_TYPE_SOA ||
                rrset->rrtype == LDNS_RR_TYPE_NS ||
                rrset->rrtype == LDNS_RR_TYPE_DS) {

                types[*types_count] = rrset->rrtype;
                *types_count = *types_count + 1;
            }
        }
        rrset = rrset->next;
    }
    return;
}


/**
 * Create NSEC3 Next Hashed Owner Name Field.
 *
 */
static ldns_rdf*
denial_create_nsec3_nxt(ldns_rdf* nxt)
{
    ldns_status status = LDNS_STATUS_OK;
    ldns_rdf* next_owner_label = NULL;
    ldns_rdf* next_owner_rdf = NULL;
    char* next_owner_string = NULL;

    ods_log_assert(nxt);
    next_owner_label = ldns_dname_label(nxt, 0);
    if (!next_owner_label) {
        ods_log_alert("[%s] unable to create NSEC3 Next: "
            "ldns_dname_label() failed", denial_str);
        return NULL;
    }
    next_owner_string = ldns_rdf2str(next_owner_label);
    if (!next_owner_string) {
        ods_log_alert("[%s] unable to create NSEC3 Next: "
            "ldns_rdf2str() failed", denial_str);
        ldns_rdf_deep_free(next_owner_label);
        return NULL;
    }
    if (next_owner_string[strlen(next_owner_string)-1] == '.') {
        next_owner_string[strlen(next_owner_string)-1] = '\0';
    }
    status = ldns_str2rdf_b32_ext(&next_owner_rdf, next_owner_string);
    if (status != LDNS_STATUS_OK) {
        ods_log_alert("[%s] unable to create NSEC3 Next: "
            "ldns_str2rdf_b32_ext() failed", denial_str);
    }
    free((void*)next_owner_string);
    ldns_rdf_deep_free(next_owner_label);
    return next_owner_rdf;
}


/**
 * Create NSEC(3) RR.
 *
 */
static ldns_rr*
denial_create_nsec(denial_type* denial, denial_type* nxt, uint32_t ttl,
    ldns_rr_class klass, nsec3params_type* n3p)
{
    ldns_rr* nsec_rr = NULL;
    ldns_rr_type rrtype = LDNS_RR_TYPE_NSEC;
    ldns_rr_type dstatus = LDNS_RR_TYPE_FIRST;
    ldns_rdf* rdf = NULL;
    domain_type* domain = NULL;
    ldns_rr_type types[SE_MAX_RRTYPE_COUNT];
    size_t types_count = 0;
    int i = 0;
    ods_log_assert(denial);
    ods_log_assert(denial->dname);
    ods_log_assert(nxt);
    ods_log_assert(nxt->dname);
    nsec_rr = ldns_rr_new();
    if (!nsec_rr) {
        ods_log_alert("[%s] unable to create NSEC(3) RR: "
            "ldns_rr_new() failed", denial_str);
        return NULL;
    }
    /* RRtype */
    if (n3p) {
        rrtype = LDNS_RR_TYPE_NSEC3;
    }
    ldns_rr_set_type(nsec_rr, rrtype);
    /* owner */
    rdf = ldns_rdf_clone(denial->dname);
    if (!rdf) {
        ods_log_alert("[%s] unable to create NSEC(3) RR: "
            "ldns_rdf_clone(owner) failed", denial_str);
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    ldns_rr_set_owner(nsec_rr, rdf);
    /* NSEC3 parameters */
    if (n3p) {
        /* set all to NULL first, then call nsec3_add_param_rdfs. */
        for (i=0; i < SE_NSEC3_RDATA_NSEC3PARAMS; i++) {
            ldns_rr_push_rdf(nsec_rr, NULL);
        }
        ldns_nsec3_add_param_rdfs(nsec_rr, n3p->algorithm, n3p->flags,
            n3p->iterations, n3p->salt_len, n3p->salt_data);
    }
    /* NXT */
    if (n3p) {
        rdf = denial_create_nsec3_nxt(nxt->dname);
    } else {
        rdf = ldns_rdf_clone(nxt->dname);
    }
    if (!rdf) {
        ods_log_alert("[%s] unable to create NSEC(3) RR: "
            "create next field failed", denial_str);
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    ldns_rr_push_rdf(nsec_rr, rdf);
    /* Type Bit Maps */
    denial_create_bitmap(denial, types, &types_count);
    if (n3p) {
        domain = (domain_type*) denial->domain;
        dstatus = domain_is_occluded(domain);
        if (dstatus == LDNS_RR_TYPE_SOA) {
            dstatus = domain_is_delegpt(domain);
            if (dstatus != LDNS_RR_TYPE_NS && domain->rrsets) {
                 /* Authoritative domain, not empty: add RRSIGs */
                 types[types_count] = LDNS_RR_TYPE_RRSIG;
                 types_count++;
            }
        }
        /* and don't add NSEC3 type... */
    } else {
        types[types_count] = LDNS_RR_TYPE_RRSIG;
        types_count++;
        types[types_count] = LDNS_RR_TYPE_NSEC;
        types_count++;
    }
    rdf = ldns_dnssec_create_nsec_bitmap(types, types_count, rrtype);
    if (!rdf) {
        ods_log_alert("[%s] unable to create NSEC(3) RR: "
            "ldns_dnssec_create_nsec_bitmap() failed", denial_str);
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    ldns_rr_push_rdf(nsec_rr, rdf);
    ldns_rr_set_ttl(nsec_rr, ttl);
    ldns_rr_set_class(nsec_rr, klass);
    return nsec_rr;
}


/**
 * Apply differences at denial.
 *
 */
void
denial_diff(denial_type* denial)
{
    if (denial && denial->rrset) {
        rrset_diff(denial->rrset, 0, 0);
    }
    return;
}


/**
 * Add NSEC(3) to the Denial of Existence data point.
 *
 */
void
denial_add_rr(denial_type* denial, ldns_rr* rr)
{
    rr_type* record = NULL;
    zone_type* zone = NULL;
    ods_log_assert(denial);
    ods_log_assert(rr);
    zone = (zone_type*) denial->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->signconf);
    if (!denial->rrset) {
        if (zone->signconf->nsec3params) {
            denial->rrset = rrset_create(denial->zone, LDNS_RR_TYPE_NSEC3);
        } else {
            denial->rrset = rrset_create(denial->zone, LDNS_RR_TYPE_NSEC);
        }
        if (!denial->rrset) {
            ods_fatal_exit("[%s] unable to nsecify: rrset_create() failed",
                denial_str);
        }
    }
    ods_log_assert(denial->rrset);
    record = rrset_add_rr(denial->rrset, rr);
    ods_log_assert(record);
    ods_log_assert(record->rr);
    record->owner = (void*) denial;
    denial_diff(denial);
    denial->bitmap_changed = 0;
    denial->nxt_changed = 0;
    return;
}


/**
 * Nsecify Denial of Existence data point.
 *
 */
void
denial_nsecify(denial_type* denial, denial_type* nxt, uint32_t* num_added)
{
    ldns_rr* nsec_rr = NULL;
    zone_type* zone = NULL;
    uint32_t ttl = 0;
    ods_log_assert(denial);
    ods_log_assert(nxt);
    zone = (zone_type*) denial->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->signconf);
    if (denial->nxt_changed || denial->bitmap_changed) {
        ttl = zone->default_ttl;
        /* SOA MINIMUM */
        if (zone->signconf->soa_min) {
            ttl = (uint32_t) duration2time(zone->signconf->soa_min);
        }
        /* create new NSEC(3) rr */
        nsec_rr = denial_create_nsec(denial, nxt, ttl, zone->klass,
            zone->signconf->nsec3params);
        if (!nsec_rr) {
            ods_fatal_exit("[%s] unable to nsecify: denial_create_nsec() "
                "failed", denial_str);
        }
        denial_add_rr(denial, nsec_rr);
        if (num_added) {
            (*num_added)++;
        }
    }
    return;
}


/**
 * Print Denial of Existence data point.
 *
 */
void
denial_print(FILE* fd, denial_type* denial, ods_status* status)
{
    if (!denial || !fd) {
        if (status) {
            ods_log_crit("[%s] unable to print denial: denial of fd missing",
                denial_str);
            *status = ODS_STATUS_ASSERT_ERR;
        }
        return;
    }
    if (denial->rrset) {
        rrset_print(fd, denial->rrset, 0, status);
    }
    return;
}


/**
 * Cleanup Denial of Existence data point.
 *
 */
void
denial_cleanup(denial_type* denial)
{
    zone_type* zone = NULL;
    if (!denial) {
        return;
    }
    zone = (zone_type*) denial->zone;
    ldns_rdf_deep_free(denial->dname);
    rrset_cleanup(denial->rrset);
    allocator_deallocate(zone->allocator, (void*) denial);
    return;
}
