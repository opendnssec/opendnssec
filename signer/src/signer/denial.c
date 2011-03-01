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
#include "signer/denial.h"
#include "signer/domain.h"
#include "signer/nsec3params.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <ldns/ldns.h>

#define SE_MAX_RRTYPE_COUNT 65536

static const char* denial_str = "denial";


/**
 * Create new Denial of Existence data point.
 *
 */
denial_type*
denial_create(ldns_rdf* owner)
{
    denial_type* denial = NULL;
    char* str = NULL;

    if (!owner) {
        se_log_error("[%s] unable to create denial of existence data point: "
            "no owner name", denial_str);
        return NULL;
    }
    se_log_assert(owner);

    denial = (denial_type*) se_malloc(sizeof(denial_type));
    if (!denial) {
        str = ldns_rdf2str(denial->owner);
        se_log_error("[%s] unable to create denial of existence data point: "
            "%s: allocator failed", denial_str, str?str:"(null)");
        free((void*)str);
        free((void*)denial);
        return NULL;
    }
    se_log_assert(denial);

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

    se_log_assert(denial->domain);

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
 * Create NSEC RR.
 *
 */
static ldns_rr*
denial_create_nsec(denial_type* denial, denial_type* nxt, uint32_t ttl,
    ldns_rr_class klass)
{
    ldns_rr* nsec_rr = NULL;
    ldns_rdf* rdf = NULL;
    ldns_rr_type types[SE_MAX_RRTYPE_COUNT];
    size_t types_count = 0;

    se_log_assert(denial);
    se_log_assert(denial->owner);
    se_log_assert(nxt);
    se_log_assert(nxt->owner);

    nsec_rr = ldns_rr_new();
    if (!nsec_rr) {
        se_log_alert("[%s] unable to create NSEC RR: ldns error",
            denial_str);
        return NULL;
    }
    se_log_assert(nsec_rr);

    ldns_rr_set_type(nsec_rr, LDNS_RR_TYPE_NSEC);
    rdf = ldns_rdf_clone(denial->owner);
    if (!rdf) {
        se_log_alert("[%s] unable to create NSEC RR: failed to clone owner",
            denial_str);
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    ldns_rr_set_owner(nsec_rr, rdf);

    rdf = ldns_rdf_clone(nxt->owner);
    if (!rdf) {
        se_log_alert("[%s] unable to create NSEC RR: failed to clone nxt",
            denial_str);
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    ldns_rr_push_rdf(nsec_rr, rdf);

    /* create types bitmap */
    denial_create_bitmap(denial, types, &types_count);
    types[types_count] = LDNS_RR_TYPE_RRSIG;
    types_count++;
    types[types_count] = LDNS_RR_TYPE_NSEC;
    types_count++;

    rdf = ldns_dnssec_create_nsec_bitmap(types,
        types_count, LDNS_RR_TYPE_NSEC);
    if (!rdf) {
        se_log_alert("[%s] unable to create NSEC RR: failed to create bitmap",
            denial_str);
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    ldns_rr_push_rdf(nsec_rr, rdf);
    ldns_rr_set_ttl(nsec_rr, ttl);
    ldns_rr_set_class(nsec_rr, klass);
    return nsec_rr;
}


/**
 * Add NSEC to the Denial of Existence data point.
 *
 */
int
denial_nsecify(denial_type* denial, denial_type* nxt, uint32_t ttl,
    ldns_rr_class klass)
{
    ldns_rr* nsec_rr = NULL;
    int error = 0;

    if (!denial) {
        se_log_error("[%s] unable to nsecify: no data point", denial_str);
        return 1;
    }
    se_log_assert(denial);

    if (!nxt) {
        se_log_error("[%s] unable to nsecify: no next", denial_str);
        return 1;
    }
    se_log_assert(nxt);

    if (denial->nxt_changed || denial->bitmap_changed) {
        /* assert there is a NSEC RRset */
        if (!denial->rrset) {
            denial->rrset = rrset_create(LDNS_RR_TYPE_NSEC);
            if (!denial->rrset) {
                 se_log_alert("[%s] unable to nsecify: failed to "
                "create NSEC RRset", denial_str);
                return 1;
            }
        }
        se_log_assert(denial->rrset);
        /* create new NSEC rr */
        nsec_rr = denial_create_nsec(denial, nxt, ttl, klass);
        if (!nsec_rr) {
            se_log_alert("[%s] unable to nsecify: failed to "
                "create NSEC RR", denial_str);
            return 1;
        }
        /* delete old NSEC RR(s)... */
        error = rrset_del_rrs(denial->rrset);
        if (error) {
            se_log_alert("[%s] unable to nsecify: failed to "
                "wipe out NSEC RRset", denial_str);
            ldns_rr_free(nsec_rr);
            return error;
        }
        /* ...and add the new one */
        error = rrset_add_rr(denial->rrset, nsec_rr);
        if (error) {
            se_log_alert("[%s] unable to nsecify: failed to "
                "add NSEC to RRset", denial_str);
            ldns_rr_free(nsec_rr);
            return error;
        }
        /* commit */
        denial->rrset->initialized = 0; /* hack */
        error = rrset_update(denial->rrset, 0);
        if (error) {
            se_log_alert("[%s] unable to nsecify: failed to "
                "commit the NSEC RRset", denial_str);
            return error;
        }
        /* ok */
        denial->bitmap_changed = 0;
        denial->nxt_changed = 0;
    }
    return 0;
}


/**
 * Create NSEC3 RR.
 *
 */
static ldns_rr*
denial_create_nsec3(denial_type* denial, denial_type* nxt, uint32_t ttl,
    ldns_rr_class klass, nsec3params_type* nsec3params)
{
    ldns_status status = LDNS_STATUS_OK;
    ldns_rr* nsec_rr = NULL;
    ldns_rdf* rdf = NULL;
    ldns_rdf* next_owner_label = NULL;
    ldns_rdf* next_owner_rdf = NULL;
    char* next_owner_string = NULL;
    domain_type* domain = NULL;
    ldns_rr_type types[SE_MAX_RRTYPE_COUNT];
    size_t types_count = 0;
    int i = 0;

    se_log_assert(denial);
    se_log_assert(denial->owner);
    se_log_assert(nxt);
    se_log_assert(nxt->owner);
    se_log_assert(nsec3params);

    nsec_rr = ldns_rr_new();
    if (!nsec_rr) {
        se_log_alert("[%s] unable to create NSEC3 RR: ldns error",
            denial_str);
        return NULL;
    }
    se_log_assert(nsec_rr);

    ldns_rr_set_type(nsec_rr, LDNS_RR_TYPE_NSEC3);
    rdf = ldns_rdf_clone(denial->owner);
    if (!rdf) {
        se_log_alert("[%s] unable to create NSEC3 RR: failed to clone owner",
            denial_str);
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    ldns_rr_set_owner(nsec_rr, rdf);

    /* set all to NULL first, then call nsec3_add_param_rdfs. */
    for (i=0; i < SE_NSEC3_RDATA_NSEC3PARAMS; i++) {
        ldns_rr_push_rdf(nsec_rr, NULL);
    }
    ldns_nsec3_add_param_rdfs(nsec_rr, nsec3params->algorithm,
        nsec3params->flags, nsec3params->iterations,
        nsec3params->salt_len, nsec3params->salt_data);
    /* nxt owner label */
    next_owner_label = ldns_dname_label(nxt->owner, 0);
    if (!next_owner_label) {
        se_log_alert("[%s] unable to create NSEC3 RR: failed to get nxt "
            "owner label", denial_str);
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    next_owner_string = ldns_rdf2str(next_owner_label);
    if (!next_owner_string) {
        se_log_alert("[%s] unable to create NSEC3 RR: failed to get nxt "
            "owner string", denial_str);
        ldns_rdf_deep_free(next_owner_label);
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    if (next_owner_string[strlen(next_owner_string)-1] == '.') {
        next_owner_string[strlen(next_owner_string)-1] = '\0';
    }
    status = ldns_str2rdf_b32_ext(&next_owner_rdf, next_owner_string);
    free((void*)next_owner_string);
    ldns_rdf_deep_free(next_owner_label);
    if (status != LDNS_STATUS_OK) {
        se_log_alert("[%s] unable to create NSEC3 RR: failed to create nxt "
            "owner rdf: %s", denial_str, ldns_get_errorstr_by_id(status));
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    ldns_rr_push_rdf(nsec_rr, next_owner_rdf);

    /* create types bitmap */
    denial_create_bitmap(denial, types, &types_count);
    /* only add RRSIG type if we have authoritative data to sign */
    domain = (domain_type*) denial->domain;
    if (domain_count_rrset(domain) > 0 &&
        (domain->domain_status == DOMAIN_STATUS_APEX ||
         domain->domain_status == DOMAIN_STATUS_AUTH ||
         domain->domain_status == DOMAIN_STATUS_DS)) {
        types[types_count] = LDNS_RR_TYPE_RRSIG;
        types_count++;
    }
    /* and don't add NSEC3 type... */
    rdf = ldns_dnssec_create_nsec_bitmap(types,
        types_count, LDNS_RR_TYPE_NSEC3);
    if (!rdf) {
        se_log_alert("[%s] unable to create NSEC3 RR: failed to create "
            "bitmap", denial_str);
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    ldns_rr_push_rdf(nsec_rr, rdf);
    ldns_rr_set_ttl(nsec_rr, ttl);
    ldns_rr_set_class(nsec_rr, klass);
    return nsec_rr;
}


/**
 * Add NSEC3 to the Denial of Existence data point.
 *
 */
int
denial_nsecify3(denial_type* denial, denial_type* nxt, uint32_t ttl,
    ldns_rr_class klass, nsec3params_type* nsec3params)
{
    ldns_rr* nsec_rr = NULL;
    int error = 0;

    if (!denial) {
        se_log_error("[%s] unable to nsecify3: no data point", denial_str);
        return 1;
    }
    se_log_assert(denial);

    if (!nxt) {
        se_log_error("[%s] unable to nsecify3: no next", denial_str);
        return 1;
    }
    se_log_assert(nxt);

    if (denial->nxt_changed || denial->bitmap_changed) {
        /* assert there is a NSEC RRset */
        if (!denial->rrset) {
            denial->rrset = rrset_create(LDNS_RR_TYPE_NSEC3);
            if (!denial->rrset) {
                 se_log_alert("[%s] unable to nsecify3: failed to "
                "create NSEC3 RRset", denial_str);
                return 1;
            }
        }
        se_log_assert(denial->rrset);
        /* create new NSEC3 rr */
        nsec_rr = denial_create_nsec3(denial, nxt, ttl, klass, nsec3params);
        if (!nsec_rr) {
            se_log_alert("[%s] unable to nsecify3: failed to "
                "create NSEC3 RR", denial_str);
            return 1;
        }
        se_log_assert(nsec_rr);
        /* delete old NSEC RR(s) */
        error = rrset_del_rrs(denial->rrset);
        if (error) {
            se_log_alert("[%s] unable to nsecify3: failed to "
                "wipe out NSEC3 RRset", denial_str);
            return error;
        }
       /* add the new one */
        error = rrset_add_rr(denial->rrset, nsec_rr);
        if (error) {
            se_log_alert("[%s] unable to nsecify3: failed to "
                "add NSEC3 to RRset", denial_str);
            return error;
        }
        /* commit */
        denial->rrset->initialized = 0; /* hack */
        error = rrset_update(denial->rrset, 0);
        if (error) {
            se_log_alert("[%s] unable to nsecify3: failed to "
                "commit the NSEC3 RRset", denial_str);
            return error;
        }
        /* ok */
        denial->bitmap_changed = 0;
        denial->nxt_changed = 0;
    }
    return 0;
}


/**
 * Clean up Denial of Existence data point.
 *
 */
void
denial_cleanup(denial_type* denial)
{
    if (!denial) {
        return;
    }
    if (denial->owner) {
        ldns_rdf_deep_free(denial->owner);
        denial->owner = NULL;
    }
    if (denial->rrset) {
        rrset_cleanup(denial->rrset);
        denial->rrset = NULL;
    }
    free((void*)denial);
    return;

}
