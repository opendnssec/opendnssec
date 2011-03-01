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
#include "signer/backup.h"
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
    domain->denial = NULL;
    domain->rrsets = ldns_rbtree_create(rrset_compare);
    domain->domain_status = DOMAIN_STATUS_NONE;
    domain->internal_serial = 0;
    domain->initialized = 0;
    domain->outbound_serial = 0;
    domain->subdomain_count = 0;
    domain->subdomain_auth = 0;
    return domain;
}


/**
 * Recover domain from backup.
 *
 */
domain_type*
domain_recover_from_backup(FILE* fd)
{
    domain_type* domain = NULL;
    const char* name = NULL;
    uint32_t internal_serial = 0;
    uint32_t outbound_serial = 0;
    int domain_status = DOMAIN_STATUS_NONE;
    size_t subdomain_count = 0;
    size_t subdomain_auth = 0;
    int nsec_bitmap_changed = 0;
    int nsec_nxt_changed = 0;

    se_log_assert(fd);

    if (!backup_read_str(fd, &name) ||
        !backup_read_uint32_t(fd, &internal_serial) ||
        !backup_read_uint32_t(fd, &outbound_serial) ||
        !backup_read_int(fd, &domain_status) ||
        !backup_read_size_t(fd, &subdomain_count) ||
        !backup_read_size_t(fd, &subdomain_auth) ||
        !backup_read_int(fd, &nsec_bitmap_changed) ||
        !backup_read_int(fd, &nsec_nxt_changed)) {
        se_log_error("domain part in backup file is corrupted");
        if (name) {
            se_free((void*)name);
        }
        return NULL;
    }

    domain = (domain_type*) se_malloc(sizeof(domain_type));
    se_log_assert(name);
    domain->name = ldns_dname_new_frm_str(name);
    if (!domain->name) {
        se_log_error("failed to create domain from name");
        se_free((void*)name);
        se_free((void*)domain);
        return NULL;
    }
    domain->parent = NULL;
    domain->denial = NULL;
    domain->rrsets = ldns_rbtree_create(rrset_compare);
    domain->domain_status = domain_status;
    domain->internal_serial = internal_serial;
    domain->initialized = 0;
    domain->outbound_serial = outbound_serial;
    domain->subdomain_count = subdomain_count;
    domain->subdomain_auth = subdomain_auth;
/* RECOVER DENIAL OF EXISTENCE
    domain->nsec_rrset = NULL;
    domain->nsec_bitmap_changed = nsec_bitmap_changed;
    domain->nsec_nxt_changed = nsec_nxt_changed;
*/
    se_log_deeebug("recovered domain %s internal_serial=%u, "
        "outbound_serial=%u, domain_status=%i, nsec_status=(%i, %i)",
        name, domain->internal_serial, domain->outbound_serial,
        domain->domain_status, nsec_bitmap_changed,
        nsec_nxt_changed);

    se_free((void*)name);
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
domain_add_rrset(domain_type* domain, rrset_type* rrset, int recover)
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
            rrset->rr_type, str?str:"(null)");
        se_free((void*)str);
        se_free((void*)new_node);
        return NULL;
    }
    if (!recover && domain->denial) {
        domain->denial->bitmap_changed = 1;
    }
    return rrset;
}


/**
 * Delete RRset from domain.
 *
 */
rrset_type*
domain_del_rrset(domain_type* domain, rrset_type* rrset, int recover)
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
        if (!recover && domain->denial) {
            domain->denial->bitmap_changed = 1;
        }
        return NULL;
    } else {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to delete RRset %i from domain %s: "
            "not in tree", rrset->rr_type, str?str:"(null)");
        se_free((void*)str);
        return rrset;
    }
    return rrset;
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
 * Examine domain and verify if data exists.
 *
 */
int
domain_examine_data_exists(domain_type* domain, ldns_rr_type rrtype,
    int skip_glue)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;

    se_log_assert(domain);

    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        if (rrset_count_RR(rrset) > 0) {
            if (rrtype) {
                /* looking for a specific RRset */
                if (rrset->rr_type == rrtype) {
                    return 0;
                }
            } else if (!skip_glue ||
                (rrset->rr_type != LDNS_RR_TYPE_A &&
                 rrset->rr_type != LDNS_RR_TYPE_AAAA)) {
                /* not glue or not skipping glue */
                return 0;
            }
        }
        node = ldns_rbtree_next(node);
    }
    return 1;
}


/**
 * Examine domain NS RRset and verify its RDATA.
 *
 */
int
domain_examine_ns_rdata(domain_type* domain, ldns_rdf* nsdname)
{
    rrset_type* rrset = NULL;

    se_log_assert(domain);
    if (!nsdname) {
       return 1;
    }

    rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_NS);
    if (rrset && rrset_count_RR(rrset) > 0) {
        /* NS RRset exists after update */
        if (rrset_examine_ns_rdata(rrset, nsdname) == 0) {
            return 0;
        }
    }
    return 1;
}


/**
 * Examine domain and verify if there is no other data next to a RRset.
 *
 */
int
domain_examine_rrset_is_alone(domain_type* domain, ldns_rr_type rrtype)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    ldns_dnssec_rrs* rrs = NULL;
    char* str_name = NULL;
    char* str_type = NULL;

    se_log_assert(domain);
    se_log_assert(rrtype);

    rrset = domain_lookup_rrset(domain, rrtype);
    if (rrset && rrset_count_RR(rrset) > 0) {
        if (domain_count_rrset(domain) < 2) {
            /* one or zero, that's ok */
            return 0;
        }
        /* make sure all other RRsets become empty */
        if (domain->rrsets->root != LDNS_RBTREE_NULL) {
            node = ldns_rbtree_first(domain->rrsets);
        }
        while (node && node != LDNS_RBTREE_NULL) {
            rrset = (rrset_type*) node->data;
            if (rrset->rr_type != rrtype && rrset_count_RR(rrset) > 0) {
                /* found other data next to rrtype */
                str_name = ldns_rdf2str(domain->name);
                str_type = ldns_rr_type2str(rrtype);
                se_log_error("other data next to %s %s", str_name, str_type);
                rrs = rrset->rrs;
                while (rrs) {
                    if (rrs->rr) {
                        log_rr(rrs->rr, "next-to-CNAME: ", 2);
                    }
                    rrs = rrs->next;
                }
                rrs = rrset->add;
                while (rrs) {
                    if (rrs->rr) {
                        log_rr(rrs->rr, "next-to-CNAME: ", 2);
                    }
                    rrs = rrs->next;
                }
                se_free((void*)str_name);
                se_free((void*)str_type);
                return 1;
            }
            node = ldns_rbtree_next(node);
        }
    }
    return 0;
}


/**
 * Examine domain and verify if there is no occluded data next to a delegation.
 *
 */
int
domain_examine_valid_zonecut(domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;

    se_log_assert(domain);

    rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_NS);
    if (rrset && rrset_count_RR(rrset) > 0) {
        /* make sure all other RRsets become empty (except DS, glue) */
        if (domain->rrsets->root != LDNS_RBTREE_NULL) {
            node = ldns_rbtree_first(domain->rrsets);
        }
        while (node && node != LDNS_RBTREE_NULL) {
            rrset = (rrset_type*) node->data;
            if (rrset->rr_type != LDNS_RR_TYPE_DS &&
                rrset->rr_type != LDNS_RR_TYPE_NS &&
                rrset->rr_type != LDNS_RR_TYPE_A &&
                rrset->rr_type != LDNS_RR_TYPE_AAAA &&
                rrset_count_RR(rrset) > 0) {
                /* found occluded data next to delegation */
                se_log_error("occluded glue data at zonecut, RRtype=%u",
                    rrset->rr_type);
                return 1;
            } else if (rrset->rr_type == LDNS_RR_TYPE_A ||
                rrset->rr_type == LDNS_RR_TYPE_AAAA) {
                /* check if glue is allowed at the delegation */
                if (rrset_count_RR(rrset) > 0 &&
                    domain_examine_ns_rdata(domain, domain->name) != 0) {
                    se_log_error("occluded glue data at zonecut, #RR=%u",
                        rrset_count_RR(rrset));
                    return 1;
                }
            }

            node = ldns_rbtree_next(node);
        }
    }
    return 0;
}


/**
 * Examine domain and verify if the RRset is a singleton.
 *
 */
int
domain_examine_rrset_is_singleton(domain_type* domain, ldns_rr_type rrtype)
{
    rrset_type* rrset = NULL;
    char* str_name = NULL;
    char* str_type = NULL;

    se_log_assert(domain);
    se_log_assert(rrtype);

    rrset = domain_lookup_rrset(domain, rrtype);
    if (rrset && rrset_count_RR(rrset) > 1) {
        /* multiple RRs in the RRset for singleton RRtype*/
        str_name = ldns_rdf2str(domain->name);
        str_type = ldns_rr_type2str(rrtype);
        se_log_error("multiple records for singleton type at %s %s",
            str_name, str_type);
        se_free((void*)str_name);
        se_free((void*)str_type);
        return 1;
    }
    return 0;
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

    if (!domain->initialized || DNS_SERIAL_GT(serial, domain->internal_serial)) {
        if (domain->rrsets->root != LDNS_RBTREE_NULL) {
            node = ldns_rbtree_first(domain->rrsets);
        }
        while (node && node != LDNS_RBTREE_NULL) {
            rrset = (rrset_type*) node->data;
            if (rrset->rr_type == LDNS_RR_TYPE_SOA && rrset->rrs &&
                rrset->rrs->rr) {
                rrset->drop_signatures = 1;
            }

            if (rrset_update(rrset, serial) != 0) {
                se_log_error("failed to update domain to serial %u: failed "
                    "to update RRset", serial);
                return 1;
            }
            node = ldns_rbtree_next(node);
            /* delete memory of RRsets if no RRs exist */
            if (rrset_count_rr(rrset) <= 0) {
                rrset = domain_del_rrset(domain, rrset, 0);
                if (rrset) {
                    se_log_error("failed to delete obsoleted RRset");
                }
            }
        }
        domain->internal_serial = serial;
        domain->initialized = 1;
    } else {
        se_log_error("cannot update domain: serial %u should be larger than "
            "domain internal serial %u", serial, domain->internal_serial);
        return 2;
    }
    return 0;
}


/**
 * Cancel update.
 *
 */
void
domain_cancel_update(domain_type* domain)
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
        rrset_cancel_update(rrset);
        node = ldns_rbtree_next(node);
    }
    return;
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
        return;
    }

    if (domain_count_rrset(domain) <= 0) {
        /* Empty Non-Terminal */
        return; /* we don't care */
    }

    if (domain_lookup_rrset(domain, LDNS_RR_TYPE_NS)) {
        if (domain_lookup_rrset(domain, LDNS_RR_TYPE_DS)) {
            domain->domain_status = DOMAIN_STATUS_DS;
        } else {
            domain->domain_status = DOMAIN_STATUS_NS;
        }
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
 * Sign domain.
 *
 */
int
domain_sign(hsm_ctx_t* ctx, domain_type* domain, ldns_rdf* owner,
    signconf_type* sc, time_t signtime, uint32_t serial, stats_type* stats)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rdf* soa_serial = NULL;
    rrset_type* rrset = NULL;
    int error = 0;

    se_log_assert(domain);
    se_log_assert(domain->rrsets);
    se_log_assert(owner);
    se_log_assert(sc);
    se_log_assert(signtime);
    se_log_assert(stats);

    if (domain->domain_status == DOMAIN_STATUS_NONE ||
        domain->domain_status == DOMAIN_STATUS_OCCLUDED) {
        return 0;
    }

    if (domain->denial && domain->denial->rrset) {
        error = rrset_sign(ctx, domain->denial->rrset, owner, sc, signtime, stats);
        if (error) {
            return error;
        }
    }

    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;

        /* skip delegation RRsets */
        if (domain->domain_status != DOMAIN_STATUS_APEX &&
            rrset->rr_type == LDNS_RR_TYPE_NS) {
            node = ldns_rbtree_next(node);
            continue;
        }
        /* skip glue at the delegation */
        if ((domain->domain_status == DOMAIN_STATUS_DS ||
             domain->domain_status == DOMAIN_STATUS_NS) &&
            (rrset->rr_type == LDNS_RR_TYPE_A ||
             rrset->rr_type == LDNS_RR_TYPE_AAAA)) {
            node = ldns_rbtree_next(node);
            continue;
        }

        if (rrset->rr_type == LDNS_RR_TYPE_SOA && rrset->rrs &&
            rrset->rrs->rr) {
            soa_serial = ldns_rr_set_rdf(rrset->rrs->rr,
                ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, serial),
                SE_SOA_RDATA_SERIAL);
            if (soa_serial) {
                if (ldns_rdf2native_int32(soa_serial) != serial) {
                    rrset->drop_signatures = 1;
                }
                ldns_rdf_deep_free(soa_serial);
             } else {
                se_log_error("unable to sign domain: failed to replace "
                    "SOA SERIAL rdata");
                return 1;
            }
        }

        error = rrset_sign(ctx, rrset, owner, sc, signtime, stats);
        if (error) {
            se_log_error("failed to sign RRset[%i]", (int) rrset->rr_type);
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
    rrset = domain_add_rrset(domain, rrset, 0);
    if (!rrset) {
        se_log_error("unable to add RR to domain: failed to add RRset");
        return 1;
    }
    return rrset_add_rr(rrset, rr);
}


/**
 * Recover RR from backup.
 *
 */
int
domain_recover_rr_from_backup(domain_type* domain, ldns_rr* rr)
{
    rrset_type* rrset = NULL;

    se_log_assert(rr);
    se_log_assert(domain);
    se_log_assert(domain->name);
    se_log_assert(domain->rrsets);
    se_log_assert((ldns_dname_compare(domain->name, ldns_rr_owner(rr)) == 0));

    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (rrset) {
        return rrset_recover_rr_from_backup(rrset, rr);
    }
    /* no RRset with this RRtype yet */
    rrset = rrset_create(ldns_rr_get_type(rr));
    rrset = domain_add_rrset(domain, rrset, 1);
    if (!rrset) {
        se_log_error("unable to recover RR to domain: failed to add RRset");
        return 1;
    }
    return rrset_recover_rr_from_backup(rrset, rr);
}


/**
 * Recover RRSIG from backup.
 *
 */
int
domain_recover_rrsig_from_backup(domain_type* domain, ldns_rr* rrsig,
    ldns_rr_type type_covered, const char* locator, uint32_t flags)
{
    rrset_type* rrset = NULL;

    se_log_assert(rrsig);
    se_log_assert(domain);
    se_log_assert(domain->name);
    se_log_assert(domain->rrsets);
    se_log_assert((ldns_dname_compare(domain->name,
        ldns_rr_owner(rrsig)) == 0));

    if (type_covered == LDNS_RR_TYPE_NSEC ||
        type_covered == LDNS_RR_TYPE_NSEC3) {
        if (domain->denial && domain->denial->rrset) {
            return rrset_recover_rrsig_from_backup(domain->denial->rrset,
                rrsig, locator, flags);
        } else if (type_covered == LDNS_RR_TYPE_NSEC) {
            se_log_error("unable to recover RRSIG to domain: no NSEC RRset");
        } else {
            se_log_error("unable to recover RRSIG to domain: no NSEC3 RRset");
        }
    } else {
        rrset = domain_lookup_rrset(domain, type_covered);
        if (rrset) {
            return rrset_recover_rrsig_from_backup(rrset, rrsig,
                locator, flags);
        } else {
            se_log_error("unable to recover RRSIG to domain: no such RRset");
        }
    }
    return 1;
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
    if (rrset_tree && rrset_tree->root != LDNS_RBTREE_NULL) {
        se_rbnode_free(rrset_tree->root);
    }
    if (rrset_tree) {
        ldns_rbtree_free(rrset_tree);
    }
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
domain_print(FILE* fd, domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* parent = NULL;
    int print_glue = 0;
    rrset_type* rrset = NULL;
    rrset_type* soa_rrset = NULL;
    rrset_type* cname_rrset = NULL;

    if (domain->rrsets && domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }

    /* no other data may accompany a CNAME */
    cname_rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_CNAME);
    if (cname_rrset) {
        rrset_print(fd, cname_rrset, 0);
    } else {
        /* if SOA, print soa first */
        soa_rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_SOA);
        if (soa_rrset) {
            rrset_print(fd, soa_rrset, 0);
        }

        /* print other RRsets */
        while (node && node != LDNS_RBTREE_NULL) {
            rrset = (rrset_type*) node->data;
            if (rrset->rr_type != LDNS_RR_TYPE_SOA) {
                if (domain->domain_status == DOMAIN_STATUS_NONE ||
                    domain->domain_status == DOMAIN_STATUS_OCCLUDED) {

                    parent = domain->parent;
                    print_glue = 0;
                    while (parent && parent->domain_status != DOMAIN_STATUS_APEX) {
                        if (domain_lookup_rrset(parent, LDNS_RR_TYPE_NS)) {
                            print_glue = 1;
                            break;
                        }
                        parent = parent->parent;
                    }

                    /* only output glue */
                    if (print_glue && (rrset->rr_type == LDNS_RR_TYPE_A ||
                        rrset->rr_type == LDNS_RR_TYPE_AAAA)) {
                        rrset_print(fd, rrset, 0);
                    }
                } else {
                    rrset_print(fd, rrset, 0);
                }
            }

            node = ldns_rbtree_next(node);
        }
    }

    /* print NSEC(3) */
    if (domain->denial && domain->denial->rrset) {
        rrset_print(fd, domain->denial->rrset, 0);
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
    char* str = NULL;
    int nsec_bitmap_changed = 0;
    int nsec_nxt_changed = 0;

/* PRINT DENIAL OF EXISTENCE */
    str = ldns_rdf2str(domain->name);
    fprintf(fd, ";DNAME %s %u %u %i %i %i %i %i\n", str,
        domain->internal_serial, domain->outbound_serial,
        (int) domain->domain_status,
        (int) domain->subdomain_count, (int) domain->subdomain_auth,
        nsec_bitmap_changed, nsec_nxt_changed);
    se_free((void*) str);

    if (domain->denial && domain->denial->rrset &&
        domain->denial->rrset->rrs && domain->denial->rrset->rrs->rr) {
        fprintf(fd, ";NSEC\n");
        ldns_rr_print(fd, domain->denial->rrset->rrs->rr);
/*
    } else if (domain->nsec3) {
        domain = domain->nsec3;
        str = ldns_rdf2str(domain->name);
        fprintf(fd, ";DNAME3 %s %u %u %i %i %i %i %i\n", str,
            domain->internal_serial, domain->outbound_serial,
            (int) domain->domain_status,
            (int) domain->subdomain_count, (int) domain->subdomain_auth,
            domain->nsec_bitmap_changed, domain->nsec_nxt_changed);
        se_free((void*) str);

        if (domain->nsec_rrset && domain->nsec_rrset->rrs &&
            domain->nsec_rrset->rrs->rr) {
            fprintf(fd, ";NSEC3\n");
            ldns_rr_print(fd, domain->nsec_rrset->rrs->rr);
        }
*/
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

    if (domain->rrsets && domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }

    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        rrset_print_rrsig(fd, rrset);
        node = ldns_rbtree_next(node);
    }

    /* print nsec */
    if (domain->denial && domain->denial->rrset) {
        rrset_print_rrsig(fd, domain->denial->rrset);
    }
    return;
}
