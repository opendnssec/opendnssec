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
#include "shared/allocator.h"
#include "shared/log.h"
#include "signer/denial.h"
#include "signer/domain.h"
#include "signer/nsec3params.h"

#include <ldns/ldns.h>

static const char* denial_str = "denial";


/**
 * Create new Denial of Existence data point.
 *
 */
denial_type*
denial_create(ldns_rdf* owner)
{
    allocator_type* allocator = NULL;
    denial_type* denial = NULL;
    char* str = NULL;

    if (!owner) {
        ods_log_error("[%s] unable to create denial of existence data point: "
            "no owner name", denial_str);
        return NULL;
    }
    ods_log_assert(owner);

    allocator = allocator_create(malloc, free);
    if (!allocator) {
        str = ldns_rdf2str(owner);
        ods_log_error("[%s] unable to create denial of existence data point: "
            "%s: create allocator failed", denial_str, str?str:"(null)");
        free((void*)str);
        return NULL;
    }
    ods_log_assert(allocator);

    denial = (denial_type*) allocator_alloc(allocator, sizeof(denial_type));
    if (!denial) {
        str = ldns_rdf2str(denial->owner);
        ods_log_error("[%s] unable to create denial of existence data point: "
            "%s: allocator failed", denial_str, str?str:"(null)");
        free((void*)str);
        allocator_cleanup(allocator);
        return NULL;
    }
    ods_log_assert(denial);

    denial->allocator = allocator;
    denial->owner = ldns_rdf_clone(owner);
    denial->bitmap_changed = 0;
    denial->nxt_changed = 0;
    denial->rrset = NULL;
    denial->domain = NULL;
    return denial;
}


/**
 * Create NSEC(3) bitmap.
 *
 */
static void
denial_create_bitmap(denial_type* denial, ldns_rr_type types[],
    size_t* types_count)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;

    ods_log_assert(denial->domain);

    domain = (domain_type*) denial->domain;
    node = ldns_rbtree_first(domain->rrsets);

    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        types[*types_count] = rrset->rr_type;
        *types_count = *types_count + 1;
        node = ldns_rbtree_next(node);
    }
    return;
}


/**
 * Add NSEC or NSEC3 to the Denial of Existence data point.
 *
 */
ods_status
denial_nsecify(denial_type* denial, denial_type* nxt, uint32_t ttl,
    ldns_rr_class klass)
{
    ldns_rr_type types[1024];
    ldns_rr* nsec_rr = NULL;
    ods_status status = ODS_STATUS_OK;
    size_t types_count = 0;

    if (!denial) {
        ods_log_error("[%s] unable to nsecify: no domain", denial_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(denial);

    if (!nxt) {
        ods_log_error("[%s] unable to nsecify: no next", denial_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(nxt);

    if (denial->nxt_changed || denial->bitmap_changed) {
        /* create types bitmap */
        denial_create_bitmap(denial, types, &types_count);
        types[types_count] = LDNS_RR_TYPE_RRSIG;
        types_count++;
        types[types_count] = LDNS_RR_TYPE_NSEC;
        types_count++;
        /* assert there is a NSEC RRset */
        if (!denial->rrset) {
            denial->rrset = rrset_create(LDNS_RR_TYPE_NSEC);
            if (!denial->rrset) {
                 ods_log_alert("[%s] unable to nsecify: failed to "
                "create NSEC RRset", denial_str);
                return ODS_STATUS_ERR;
            }
        }
        ods_log_assert(denial->rrset);
        /* create new NSEC rr */
        nsec_rr = ldns_rr_new();
        if (!nsec_rr) {
            ods_log_alert("[%s] unable to nsecify: failed to "
                "create NSEC RR", denial_str);
            return ODS_STATUS_ERR;
        }
        ods_log_assert(nsec_rr);
        ldns_rr_set_type(nsec_rr, LDNS_RR_TYPE_NSEC);
        ldns_rr_set_owner(nsec_rr, ldns_rdf_clone(denial->owner));
        ldns_rr_push_rdf(nsec_rr, ldns_rdf_clone(nxt->owner));
        ldns_rr_push_rdf(nsec_rr, ldns_dnssec_create_nsec_bitmap(types,
            types_count, LDNS_RR_TYPE_NSEC));
        ldns_rr_set_ttl(nsec_rr, ttl);
        ldns_rr_set_class(nsec_rr, klass);
        /* delete old NSEC RR(s) */
        status = rrset_wipe_out(denial->rrset);
        if (status != ODS_STATUS_OK) {
            ods_log_alert("[%s] unable to nsecify: failed to "
                "wipe out NSEC RRset", denial_str);
            return status;
        }
       /* add the new one */
        if (!rrset_add_rr(denial->rrset, nsec_rr)) {
            ods_log_alert("[%s] unable to nsecify: failed to "
                "add NSEC to RRset", denial_str);
            return ODS_STATUS_ERR;
        }
        /* commit */
        status = rrset_commit(denial->rrset);
        if (status != ODS_STATUS_OK) {
            ods_log_alert("[%s] unable to nsecify: failed to "
                "commit the NSEC RRset", denial_str);
            return status;
        }
        /* ok */
        denial->bitmap_changed = 0;
        denial->nxt_changed = 0;
    }
    return ODS_STATUS_OK;
}


/**
 * Clean up Denial of Existence data point.
 *
 */
void
denial_cleanup(denial_type* denial)
{
    allocator_type* allocator;

    if (!denial) {
        return;
    }
    allocator = denial->allocator;

    if (denial->owner) {
        ldns_rdf_deep_free(denial->owner);
        denial->owner = NULL;
    }
    if (denial->rrset) {
        rrset_cleanup(denial->rrset);
        denial->rrset = NULL;
    }

    allocator_deallocate(allocator);
    allocator_cleanup(allocator);
    return;

}

