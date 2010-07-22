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
 * Domain.
 *
 */

#include "config.h"
#include "signer/domain.h"
#include "signer/hsm.h"
#include "signer/rrset.h"
#include "util/duration.h"
#include "util/log.h"
#include "util/se_malloc.h"
#include "util/util.h"

#include <ldns/ldns.h> /* ldns_*() */


/**
 * Compare RRsets.
 *
 */
static int
rrset_compare(const void* a, const void* b)
{
    ldns_rr_type* x = (ldns_rr_type*)a;
    ldns_rr_type* y = (ldns_rr_type*)b;
    return (*x)-(*y);
}


/**
 * Create empty domain.
 *
 */
domain_type*
domain_create(ldns_rdf* dname)
{
    domain_type* domain = (domain_type*) se_malloc(sizeof(domain_type));
    se_log_assert(dname);

    domain->name = ldns_rdf_clone(dname);
    domain->parent = NULL;
    domain->nsec3 = NULL;
    domain->rrsets = ldns_rbtree_create(rrset_compare);
    domain->domain_status = DOMAIN_STATUS_NONE;
    domain->inbound_serial = 0;
    domain->outbound_serial = 0;
    /* nsec */
    domain->nsec_rrset = NULL;
    domain->nsec_serial = 0;
    domain->nsec_bitmap_changed = 0;
    domain->nsec_nxt_changed = 0;
    return domain;
}


/**
 * Convert RRset to a tree node.
 *
 */
static ldns_rbnode_t*
rrset2node(rrset_type* rrset)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) se_malloc(sizeof(ldns_rbnode_t));
    node->key = &(rrset->rr_type);
    node->data = rrset;
    return node;
}


/**
 * Lookup RRset within domain.
 *
 */
rrset_type*
domain_lookup_rrset(domain_type* domain, ldns_rr_type type)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;

    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    node = ldns_rbtree_search(domain->rrsets, &(type));
    if (node && node != LDNS_RBTREE_NULL) {
        return (rrset_type*) node->data;
    }
    return NULL;
}


/**
 * Add RRset to domain.
 *
 */
rrset_type*
domain_add_rrset(domain_type* domain, rrset_type* rrset)
{
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;
    char* str = NULL;

    se_log_assert(rrset);
    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    new_node = rrset2node(rrset);
    if (ldns_rbtree_insert(domain->rrsets, new_node) == NULL) {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to add RRset %i to domain %s: already present",
            rrset->rr_type, domain->name);
        se_free((void*)str);
        se_free((void*)new_node);
        return NULL;
    }
    domain->nsec_bitmap_changed = 1;
    return rrset;
}


/**
 * Delete RRset from domain.
 *
 */
rrset_type*
domain_del_rrset(domain_type* domain, rrset_type* rrset)
{
    rrset_type* del_rrset = NULL;
    ldns_rbnode_t* del_node = NULL;
    char* str = NULL;

    se_log_assert(rrset);
    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    del_node = ldns_rbtree_delete(domain->rrsets,
        (const void*)&rrset->rr_type);
    if (del_node) {
        del_rrset = (rrset_type*) del_node->data;
        rrset_cleanup(del_rrset);
        se_free((void*)del_node);
        domain->nsec_bitmap_changed = 1;
        return NULL;
    } else {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to delete RRset %i from domain %s: "
            "not in tree", rrset->rr_type, domain->name);
        se_free((void*)str);
        return rrset;
    }
    return rrset;
}


/**
 * Check if the domain can be opted-out.
 *
 */
int
domain_optout(domain_type* domain)
{
    se_log_assert(domain);
    if (domain->domain_status != DOMAIN_STATUS_APEX &&
        domain_lookup_rrset(domain, LDNS_RR_TYPE_NS) &&
        !domain_lookup_rrset(domain, LDNS_RR_TYPE_DS)) {
        return 1;
    } else if (domain->domain_status == DOMAIN_STATUS_ENT_NS) {
        return 1;
    }
    return 0;
}


/**
 * Return the number of RRsets at this domain.
 *
 */
int domain_count_rrset(domain_type* domain)
{
    se_log_assert(domain);
    if (!domain->rrsets) {
        return 0;
    }
    return domain->rrsets->count;
}


/**
 * Update domain with pending changes.
 *
 */
int
domain_update(domain_type* domain, uint32_t serial)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;

    se_log_assert(serial);
    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    if (DNS_SERIAL_GT(serial, domain->inbound_serial)) {
        if (domain->rrsets->root != LDNS_RBTREE_NULL) {
            node = ldns_rbtree_first(domain->rrsets);
        }
        while (node && node != LDNS_RBTREE_NULL) {
            rrset = (rrset_type*) node->data;
            if (rrset_update(rrset, serial) != 0) {
                se_log_error("failed to update domain to serial %u: failed "
                    "to update RRset", serial);
                return 1;
            }
            node = ldns_rbtree_next(node);
            /* delete memory of RRsets if no RRs exist */
            if (rrset_count_rr(rrset) <= 0) {
                rrset = domain_del_rrset(domain, rrset);
            }
        }
        domain->inbound_serial = serial;
    }
    return 0;
}


/**
 * Update domain status.
 *
 */
void
domain_update_status(domain_type* domain)
{
    domain_type* parent = NULL;

    se_log_assert(domain);
    if (domain->domain_status == DOMAIN_STATUS_APEX) {
        /* apex stays apex */
        return;
    }

    if (domain_count_rrset(domain) <= 0) {
        /* Empty Non-Terminal */
        return; /* we don't care */
    }

    if (domain_lookup_rrset(domain, LDNS_RR_TYPE_NS)) {
        domain->domain_status = DOMAIN_STATUS_NS;
    } else { /* else, it is just an authoritative domain */
        domain->domain_status = DOMAIN_STATUS_AUTH;
    }

    parent = domain->parent;
    while (parent && parent->domain_status != DOMAIN_STATUS_APEX) {
        if (domain_lookup_rrset(parent, LDNS_RR_TYPE_DNAME) ||
            domain_lookup_rrset(parent, LDNS_RR_TYPE_NS)) {
            domain->domain_status = DOMAIN_STATUS_OCCLUDED;
            return;
        }
        parent = parent->parent;
    }
    return;
}


/**
 * Create NSEC bitmap.
 *
 */
static void
domain_nsecify_create_bitmap(domain_type* domain, ldns_rr_type types[],
    size_t* types_count)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;

    if (domain->rrsets && domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        types[*types_count] = rrset->rr_type;
        *types_count = *types_count + 1;
        node = ldns_rbtree_next(node);
    }
    return;
}


/**
 * Add NSEC record to domain.
 *
 */
int
domain_nsecify(domain_type* domain, domain_type* to, uint32_t ttl,
    ldns_rr_class klass)
{
    ldns_rr_type types[1024];
    ldns_rr* nsec_rr = NULL;
    ldns_rdf* old_rdf = NULL;
    size_t types_count = 0;

    se_log_assert(domain);
    se_log_assert(domain->name);
    se_log_assert(to);
    se_log_assert(to->name);

    if (DNS_SERIAL_GT(domain->inbound_serial, domain->outbound_serial)) {
        /* create types bitmap */
        if (!domain->nsec_rrset || domain->nsec_bitmap_changed) {
            domain_nsecify_create_bitmap(domain, types, &types_count);
            types[types_count] = LDNS_RR_TYPE_RRSIG;
            types_count++;
            types[types_count] = LDNS_RR_TYPE_NSEC;
            types_count++;
        }
        /* update the NSEC RRset */
        if (!domain->nsec_rrset) {
            se_log_debug("new nsec");
            nsec_rr = ldns_rr_new();
            if (!nsec_rr) {
                se_log_alert("failed to create NSEC rr");
                return 1;
            }
            ldns_rr_set_type(nsec_rr, LDNS_RR_TYPE_NSEC);
            ldns_rr_set_owner(nsec_rr, ldns_rdf_clone(domain->name));
            ldns_rr_push_rdf(nsec_rr, ldns_rdf_clone(to->name));
            ldns_rr_push_rdf(nsec_rr, ldns_dnssec_create_nsec_bitmap(types,
                types_count, LDNS_RR_TYPE_NSEC));
            ldns_rr_set_ttl(nsec_rr, ttl);
            ldns_rr_set_class(nsec_rr, klass);
            domain->nsec_rrset = rrset_create_frm_rr(nsec_rr);
            if (!domain->nsec_rrset) {
                se_log_alert("failed to create NSEC RRset");
                return 1;
            }
            domain->nsec_nxt_changed = 0;
            domain->nsec_bitmap_changed = 0;
        } else {
            se_log_assert(domain->nsec_rrset);
            se_log_assert(domain->nsec_rrset->rrs);
            se_log_assert(domain->nsec_rrset->rrs->rr);
            nsec_rr = domain->nsec_rrset->rrs->rr;

            if (domain->nsec_nxt_changed) {
                se_log_debug("nsec nxt changed");
                old_rdf = ldns_rr_set_rdf(nsec_rr, ldns_rdf_clone(to->name),
                    SE_NSEC_RDATA_NXT);
                if (!old_rdf) {
                    se_log_alert("failed to update NSEC next owner name");
                    return 1;
                }
                domain->nsec_nxt_changed = 0;
            }
            if (domain->nsec_bitmap_changed) {
                se_log_debug("nsec bitmap changed");
                old_rdf = ldns_rr_set_rdf(nsec_rr,
                    ldns_dnssec_create_nsec_bitmap(types, types_count,
                    LDNS_RR_TYPE_NSEC), SE_NSEC_RDATA_BITMAP);
                if (!old_rdf) {
                    se_log_alert("failed to update NSEC bitmap");
                    return 1;
                }
                domain->nsec_bitmap_changed = 0;
            }
        }
        domain->outbound_serial = domain->inbound_serial;
    }
    domain->nsec_rrset->inbound_serial = domain->inbound_serial;
    return 0;
}


/**
 * Add NSEC3 record to domain.
 *
 */
int
domain_nsecify3(domain_type* domain, domain_type* to, uint32_t ttl,
    ldns_rr_class klass, nsec3params_type* nsec3params)
{
    domain_type* orig_domain = NULL;
    ldns_rr_type types[1024];
    ldns_rr* nsec_rr = NULL;
    ldns_rdf* old_rdf = NULL;
    size_t types_count = 0;
    int i = 0;
    ldns_rdf* next_owner_label = NULL;
    ldns_rdf* next_owner_rdf = NULL;
    char* next_owner_string = NULL;
    ldns_status status = LDNS_STATUS_OK;

    se_log_assert(domain);
    se_log_assert(domain->nsec3);
    se_log_assert(domain->name);
    se_log_assert(to);
    se_log_assert(to->nsec3);
    se_log_assert(to->name);
    se_log_assert(nsec3params);

    orig_domain = domain->nsec3; /* use the back reference */
    if (DNS_SERIAL_GT(orig_domain->inbound_serial,
        orig_domain->outbound_serial))
    {
        /* create types bitmap */
        if (!domain->nsec_rrset || orig_domain->nsec_bitmap_changed) {
            domain_nsecify_create_bitmap(orig_domain, types, &types_count);
            /* only add RRSIG type if we have authoritative data to sign */
            if (orig_domain->domain_status != DOMAIN_STATUS_OCCLUDED &&
                domain_count_rrset(orig_domain) > 0) {
                if (orig_domain->domain_status == DOMAIN_STATUS_APEX ||
                     orig_domain->domain_status == DOMAIN_STATUS_AUTH ||
                     (orig_domain->domain_status == DOMAIN_STATUS_NS &&
                     domain_lookup_rrset(orig_domain, LDNS_RR_TYPE_NS))) {

                     types[types_count] = LDNS_RR_TYPE_RRSIG;
                     types_count++;
                 }
            }
            /* and don't add NSEC3 type... */
        }
        /* create new NSEC3 RR */
        if (!domain->nsec_rrset) {
            nsec_rr = ldns_rr_new();
            if (!nsec_rr) {
                se_log_alert("failed to create NSEC3 rr");
                return 1;
            }
            ldns_rr_set_type(nsec_rr, LDNS_RR_TYPE_NSEC3);
            ldns_rr_set_owner(nsec_rr, ldns_rdf_clone(domain->name));

            /* set all to NULL first, then call nsec3_add_param_rdfs. */
            for (i=0; i < SE_NSEC3_RDATA_NSEC3PARAMS; i++) {
                ldns_rr_push_rdf(nsec_rr, NULL);
            }
            ldns_nsec3_add_param_rdfs(nsec_rr, nsec3params->algorithm,
                nsec3params->flags, nsec3params->iterations,
                nsec3params->salt_len, nsec3params->salt_data);
        }
        /* create next owner name */
        if (!domain->nsec_rrset || domain->nsec_nxt_changed) {
            next_owner_label = ldns_dname_label(to->name, 0);
            next_owner_string = ldns_rdf2str(next_owner_label);
            if (next_owner_string[strlen(next_owner_string)-1] == '.') {
                next_owner_string[strlen(next_owner_string)-1] = '\0';
            }
            status = ldns_str2rdf_b32_ext(&next_owner_rdf, next_owner_string);

            se_free((void*)next_owner_string);
            ldns_rdf_deep_free(next_owner_label);
            if (status != LDNS_STATUS_OK) {
                se_log_error("failed to create NSEC3 next owner name: %s",
                    ldns_get_errorstr_by_id(status));
                ldns_rr_free(nsec_rr);
                return 1;
            }
        }
        /* update the NSEC3 RRset */
        if (!domain->nsec_rrset) {
            ldns_rr_push_rdf(nsec_rr, next_owner_rdf);
            ldns_rr_push_rdf(nsec_rr, ldns_dnssec_create_nsec_bitmap(types,
                types_count, LDNS_RR_TYPE_NSEC3));
            ldns_rr_set_ttl(nsec_rr, ttl);
            ldns_rr_set_class(nsec_rr, klass);
            domain->nsec_rrset = rrset_create_frm_rr(nsec_rr);
            if (!domain->nsec_rrset) {
                se_log_alert("failed to create NSEC3 RRset");
                return 1;
            }
            domain->nsec_nxt_changed = 0;
            orig_domain->nsec_nxt_changed = 0;
            orig_domain->nsec_bitmap_changed = 0;
        } else {
            se_log_assert(domain->nsec_rrset);
            se_log_assert(domain->nsec_rrset->rrs);
            se_log_assert(domain->nsec_rrset->rrs->rr);
            nsec_rr = domain->nsec_rrset->rrs->rr;
            if (domain->nsec_nxt_changed) {
                old_rdf = ldns_rr_set_rdf(nsec_rr, next_owner_rdf,
                    SE_NSEC3_RDATA_NXT);
                if (!old_rdf) {
                    se_log_alert("failed to update NSEC3 next owner name");
                    return 1;
                }
                domain->nsec_nxt_changed = 0;
            }
            if (orig_domain->nsec_bitmap_changed) {
                old_rdf = ldns_rr_set_rdf(nsec_rr,
                    ldns_dnssec_create_nsec_bitmap(types, types_count,
                    LDNS_RR_TYPE_NSEC3), SE_NSEC3_RDATA_BITMAP);
                if (!old_rdf) {
                    se_log_alert("failed to update NSEC3 bitmap");
                    return 1;
                }
                orig_domain->nsec_bitmap_changed = 0;
            }
            orig_domain->nsec_nxt_changed = 0;
        }
        orig_domain->outbound_serial = orig_domain->inbound_serial;
    }
    domain->nsec_rrset->inbound_serial = orig_domain->inbound_serial;
    return 0;
}


/**
 * Sign domain.
 *
 */
int
domain_sign(hsm_ctx_t* ctx, domain_type* domain, ldns_rdf* owner,
    signconf_type* sc, time_t signtime)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    int error = 0;

    se_log_assert(domain);
    se_log_assert(domain->rrsets);
    se_log_assert(owner);
    se_log_assert(sc);
    se_log_assert(signtime);

    if (domain->domain_status == DOMAIN_STATUS_OCCLUDED ||
        domain->domain_status == DOMAIN_STATUS_NONE) {
        return error;
    }

    if (sc->nsec_type == LDNS_RR_TYPE_NSEC3) {
        if (domain->nsec3 && domain->nsec3->nsec_rrset) {
            error = rrset_sign(ctx, domain->nsec3->nsec_rrset, owner, sc,
                signtime);
            if (error) {
                se_log_error("failed to sign NSEC3 RRset");
                return error;
            }
        }
    } else if (domain->nsec_rrset) {
        error = rrset_sign(ctx, domain->nsec_rrset, owner, sc, signtime);
        if (error) {
            se_log_error("failed to sign NSEC RRset");
            return error;
        }
    }

    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;

        /* skip delegation RRsets, except for DS records */
        if (domain->domain_status == DOMAIN_STATUS_NS &&
           rrset->rr_type != LDNS_RR_TYPE_DS) {
           node = ldns_rbtree_next(node);
           continue;
        }

        error = rrset_sign(ctx, rrset, owner, sc, signtime);
        if (error) {
            se_log_error("failed to sign %i RRset", (int) rrset->rr_type);
            return error;
        }
        node = ldns_rbtree_next(node);
    }

    return 0;
}


/**
 * Add RR to domain.
 *
 */
int
domain_add_rr(domain_type* domain, ldns_rr* rr)
{
    rrset_type* rrset = NULL;

    se_log_assert(rr);
    se_log_assert(domain);
    se_log_assert(domain->name);
    se_log_assert(domain->rrsets);
    se_log_assert((ldns_dname_compare(domain->name, ldns_rr_owner(rr)) == 0));

    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (rrset) {
        return rrset_add_rr(rrset, rr);
    }
    /* no RRset with this RRtype yet */
    rrset = rrset_create(ldns_rr_get_type(rr));
    rrset = domain_add_rrset(domain, rrset);
    if (!rrset) {
        se_log_error("unable to add RR to domain: failed to add RRset");
        return 1;
    }
    return rrset_add_rr(rrset, rr);
}


/**
 * Delete RR from domain.
 *
 */
int
domain_del_rr(domain_type* domain, ldns_rr* rr)
{
    rrset_type* rrset = NULL;

    se_log_assert(rr);
    se_log_assert(domain);
    se_log_assert(domain->name);
    se_log_assert(domain->rrsets);
    se_log_assert((ldns_dname_compare(domain->name, ldns_rr_owner(rr)) == 0));

    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (rrset) {
        return rrset_del_rr(rrset, rr);
    }
    /* no RRset with this RRtype yet */
    se_log_warning("unable to delete RR from domain: no such RRset "
        "[rrtype %i]", ldns_rr_get_type(rr));
    return 0; /* well, it is not present in the zone anymore, is it? */
}


/**
 * Delete all RRs from domain.
 *
 */
int
domain_del_rrs(domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;

    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
		if (rrset_del_rrs(rrset) != 0) {
            return 1;
        }
        node = ldns_rbtree_next(node);
    }
    return 0;
}


/**
 * Clean up RRsets at the domain.
 *
 */
static void
domain_cleanup_rrsets(ldns_rbtree_t* rrset_tree)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;

    if (rrset_tree && rrset_tree->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(rrset_tree);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        rrset_cleanup(rrset);
        node = ldns_rbtree_next(node);
    }
    se_rbnode_free(rrset_tree->root);
    ldns_rbtree_free(rrset_tree);
    return;
}


/**
 * Clean up domain.
 *
 */
void
domain_cleanup(domain_type* domain)
{
    if (domain) {
        if (domain->name) {
            ldns_rdf_deep_free(domain->name);
            domain->name = NULL;
        }
        if (domain->rrsets) {
            domain_cleanup_rrsets(domain->rrsets);
            domain->rrsets = NULL;
        }
        if (domain->nsec_rrset) {
            rrset_cleanup(domain->nsec_rrset);
            domain->nsec_rrset = NULL;
        }
        /* don't destroy corresponding parent and nsec3 domain */
        se_free((void*) domain);
    } else {
        se_log_warning("cleanup empty domain");
    }
    return;
}


/**
 * Print domain.
 *
 */
void
domain_print(FILE* fd, domain_type* domain, int internal)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    rrset_type* soa_rrset = NULL;
    char* str = NULL;

    if (internal) {
        se_log_assert(domain->name);
        str = ldns_rdf2str(domain->name);
        fprintf(fd, "; DNAME: %s\n", str);
        se_free((void*)str);
    }

    if (domain->rrsets && domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }

    /* print soa */
    soa_rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_SOA);
    if (soa_rrset && !internal) {
        rrset_print(fd, soa_rrset, 0);
    }

    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        if (rrset->rr_type != LDNS_RR_TYPE_SOA || internal) {
            rrset_print(fd, rrset, 0);
        }
        node = ldns_rbtree_next(node);
    }

    /* print nsec */
    if (domain->nsec_rrset) {
        rrset_print(fd, domain->nsec_rrset, 0);
    } else if (domain->nsec3 && domain->nsec3->nsec_rrset) {
        rrset_print(fd, domain->nsec3->nsec_rrset, 0);
    } else if (internal) {
        fprintf(fd, "; NO NSEC(3)\n");
    }
    return;
}


/**
 * Print NSEC(3)s at this domain.
 *
 */
void
domain_print_nsec(FILE* fd, domain_type* domain)
{
    /* print nsec */
    if (domain->nsec_rrset) {
        rrset_print(fd, domain->nsec_rrset, 1);
    } else if (domain->nsec3 && domain->nsec3->nsec_rrset) {
        rrset_print(fd, domain->nsec3->nsec_rrset, 1);
    }
    return;
}


/**
 * Print RRSIGs at this domain.
 *
 */
void
domain_print_rrsig(FILE* fd, domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    rrset_type* soa_rrset = NULL;

    if (domain->rrsets && domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }

    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        rrset_print_rrsig(fd, rrset);
        node = ldns_rbtree_next(node);
    }

    /* print nsec */
    if (domain->nsec_rrset) {
        rrset_print_rrsig(fd, domain->nsec_rrset);
    } else if (domain->nsec3 && domain->nsec3->nsec_rrset) {
        rrset_print_rrsig(fd, domain->nsec3->nsec_rrset);
    }
    return;
}
