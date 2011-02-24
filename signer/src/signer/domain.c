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
#include "shared/duration.h"
#include "shared/allocator.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/backup.h"
#include "signer/domain.h"
#include "signer/rrset.h"

#include <ldns/ldns.h>

static const char* dname_str = "domain";


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
    allocator_type* allocator = NULL;
    domain_type* domain = NULL;
    char* str = NULL;

    if (!dname) {
        ods_log_error("[%s] unable to create domain: no dname", dname_str);
        return NULL;
    }
    ods_log_assert(dname);

    allocator = allocator_create(malloc, free);
    if (!allocator) {
        str = ldns_rdf2str(dname);
        ods_log_error("[%s] unable to create domain %s: create allocator "
            "failed", dname_str, str?str:"(null)");
        free((void*)str);
        return NULL;
    }
    ods_log_assert(allocator);

    domain = (domain_type*) allocator_alloc(allocator, sizeof(domain_type));
    if (!domain) {
        str = ldns_rdf2str(dname);
        ods_log_error("[%s] unable to create domain %s: allocator failed",
            dname_str, str);
        free(str);
        allocator_cleanup(allocator);
        return NULL;
    }
    ods_log_assert(domain);

    domain->allocator = allocator;
    domain->dname = ldns_rdf_clone(dname);
    domain->dstatus = DOMAIN_STATUS_NONE;
    domain->parent = NULL;
    domain->denial = NULL;
    domain->rrsets = ldns_rbtree_create(rrset_compare);
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
    int domain_status = DOMAIN_STATUS_NONE;

    ods_log_assert(fd);

    if (!backup_read_str(fd, &name) ||
        !backup_read_int(fd, &domain_status)) {
        ods_log_error("[%s] domain part in backup file is corrupted", dname_str);
        if (name) {
            free((void*)name);
        }
        return NULL;
    }

    domain = (domain_type*) malloc(sizeof(domain_type));
    ods_log_assert(name);
    domain->dname = ldns_dname_new_frm_str(name);
    if (!domain->dname) {
        ods_log_error("[%s] failed to create domain from name", dname_str);
        free((void*)name);
        free((void*)domain);
        return NULL;
    }
    domain->parent = NULL;
    domain->rrsets = ldns_rbtree_create(rrset_compare);
    domain->dstatus = domain_status;
    ods_log_deeebug("[%s] recovered domain %s domain_status=%i",
        dname_str, name, domain->dstatus);

    free((void*)name);
    return domain;
}


/**
 * Recover RR from backup.
 *
 */
int
domain_recover_rr_from_backup(domain_type* domain, ldns_rr* rr)
{
    rrset_type* rrset = NULL;

    ods_log_assert(rr);
    ods_log_assert(domain);
    ods_log_assert(domain->dname);
    ods_log_assert(domain->rrsets);
    ods_log_assert((ldns_dname_compare(domain->dname, ldns_rr_owner(rr)) == 0));

    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (rrset) {
        return rrset_recover_rr_from_backup(rrset, rr);
    }
    /* no RRset with this RRtype yet */
    rrset = rrset_create(ldns_rr_get_type(rr));
    rrset = domain_add_rrset(domain, rrset);
    if (!rrset) {
        ods_log_error("[%s] unable to recover RR to domain: failed to add "
            "RRset", dname_str);
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

    ods_log_assert(rrsig);
    ods_log_assert(domain);
    ods_log_assert(domain->dname);
    ods_log_assert(domain->rrsets);
    ods_log_assert((ldns_dname_compare(domain->dname,
        ldns_rr_owner(rrsig)) == 0));

    if (type_covered == LDNS_RR_TYPE_NSEC ||
        type_covered == LDNS_RR_TYPE_NSEC3) {
        if (domain->denial && domain->denial->rrset) {
            return rrset_recover_rrsig_from_backup(domain->denial->rrset, rrsig,
                locator, flags);
        } else if (type_covered == LDNS_RR_TYPE_NSEC) {
            ods_log_error("[%s] unable to recover RRSIG to domain: "
                "no NSEC RRset", dname_str);
        } else {
            ods_log_error("[%s] unable to recover RRSIG to domain: "
                "no NSEC3 RRset", dname_str);
        }
    } else {
        rrset = domain_lookup_rrset(domain, type_covered);
        if (rrset) {
            return rrset_recover_rrsig_from_backup(rrset, rrsig,
                locator, flags);
        } else {
            ods_log_error("[%s] unable to recover RRSIG to domain: "
                "no such RRset", dname_str);
        }
    }
    return 1;
}


/**
 * Convert RRset to a tree node.
 *
 */
static ldns_rbnode_t*
rrset2node(rrset_type* rrset)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) malloc(sizeof(ldns_rbnode_t));
    if (!node) {
        return NULL;
    }
    node->key = (const void*) &(rrset->rr_type);
    node->data = rrset;
    return node;
}


/**
 * Internal lookup RRset function.
 *
 */
static rrset_type*
domain_rrset_search(ldns_rbtree_t* tree, ldns_rr_type rrtype)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;

    if (!tree || !rrtype) {
        return NULL;
    }
    node = ldns_rbtree_search(tree, (const void*) &rrtype);
    if (node && node != LDNS_RBTREE_NULL) {
        return (rrset_type*) node->data;
    }
    return NULL;
}


/**
 * Look up RRset at this domain.
 *
 */
rrset_type*
domain_lookup_rrset(domain_type* domain, ldns_rr_type rrtype)
{
    if (!domain || !rrtype) {
        return NULL;
    }
    return domain_rrset_search(domain->rrsets, rrtype);
}


/**
 * Add RRset to domain.
 *
 */
rrset_type*
domain_add_rrset(domain_type* domain, rrset_type* rrset)
{
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;

    if (!rrset) {
        ods_log_error("[%s] unable to add RRset: no RRset", dname_str);
        return NULL;
    }
    ods_log_assert(rrset);

    if (!domain || !domain->rrsets) {
        ods_log_error("[%s] unable to add RRset: no storage", dname_str);
        return NULL;
    }
    ods_log_assert(domain);
    ods_log_assert(domain->rrsets);

    new_node = rrset2node(rrset);
    if (ldns_rbtree_insert(domain->rrsets, new_node) == NULL) {
        ods_log_error("[%s] unable to add RRset: already present", dname_str);
        free((void*)new_node);
        return NULL;
    }
    return rrset;
}


/**
 * Delete RRset from domain.
 *
 */
rrset_type*
domain_del_rrset(domain_type* domain, rrset_type* rrset)
{
    ldns_rbnode_t* del_node = LDNS_RBTREE_NULL;
    rrset_type* del_rrset = NULL;

    if (!rrset) {
        ods_log_error("[%s] unable to delete RRset: no RRset", dname_str);
        return NULL;
    }
    ods_log_assert(rrset);

    if (!domain || !domain->rrsets) {
        ods_log_error("[%s] unable to delete RRset: no storage", dname_str);
        return rrset;
    }
    ods_log_assert(domain);
    ods_log_assert(domain->rrsets);

    del_node = ldns_rbtree_search(domain->rrsets,
        (const void*) &(rrset->rr_type));
    if (del_node) {
        del_node = ldns_rbtree_delete(domain->rrsets,
            (const void*) &(rrset->rr_type));
        del_rrset = (rrset_type*) del_node->data;
        rrset_cleanup(del_rrset);
        free((void*)del_node);
        return NULL;
    }
    return rrset;
}


/**
 * Count the number of RRsets at this domain.
 *
 */
size_t
domain_count_rrset(domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    size_t count = 0;

    if (!domain || !domain->rrsets) {
        return 0;
    }

    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        if (rrset_count_rr(rrset, COUNT_RR) > 0) {
            count++;
        }
        node = ldns_rbtree_next(node);
    }
    return count;
}


/**
 * Calculate differences at this domain between current and new RRsets.
 *
 */
ods_status
domain_diff(domain_type* domain, keylist_type* kl)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!domain || !domain->rrsets) {
        return status;
    }
    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        /* special cases */
        if (rrset->rr_type == LDNS_RR_TYPE_NSEC3PARAMS) {
            node = ldns_rbtree_next(node);
            continue;
        }
        /* normal cases */
        status = rrset_diff(rrset, kl);
        if (status != ODS_STATUS_OK) {
            return status;
        }
        node = ldns_rbtree_next(node);
    }
    return status;
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

    if (!domain) {
        return 0;
    }
    ods_log_assert(domain);

    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        if (rrset_count_RR(rrset) > 0) {
            if (rrtype) {
                /* looking for a specific RRset */
                if (rrset->rr_type == rrtype) {
                    return 1;
                }
            } else if (!skip_glue ||
                (rrset->rr_type != LDNS_RR_TYPE_A &&
                 rrset->rr_type != LDNS_RR_TYPE_AAAA)) {
                /* not glue or not skipping glue */
                return 1;
            }
        }
        node = ldns_rbtree_next(node);
    }
    return 0;
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

    if (!domain || !rrtype) {
        return 1;
    }
    ods_log_assert(domain);
    ods_log_assert(rrtype);

    rrset = domain_lookup_rrset(domain, rrtype);
    if (rrset && rrset_count_RR(rrset) > 0) {
        if (domain_count_rrset(domain) < 2) {
            /* one or zero, that's ok */
            return 1;
        }
        /* make sure all other RRsets become empty */
        if (domain->rrsets->root != LDNS_RBTREE_NULL) {
            node = ldns_rbtree_first(domain->rrsets);
        }
        while (node && node != LDNS_RBTREE_NULL) {
            rrset = (rrset_type*) node->data;
            if (rrset->rr_type != rrtype && rrset_count_RR(rrset) > 0) {
                /* found other data next to rrtype */
                str_name = ldns_rdf2str(domain->dname);
                str_type = ldns_rr_type2str(rrtype);
                ods_log_error("[%s] other data next to %s %s", dname_str, str_name, str_type);
                rrs = rrset->rrs;
                while (rrs) {
                    if (rrs->rr) {
                        log_rr(rrs->rr, "next-to-CNAME: ", 1);
                    }
                    rrs = rrs->next;
                }
                rrs = rrset->add;
                while (rrs) {
                    if (rrs->rr) {
                        log_rr(rrs->rr, "next-to-CNAME: ", 1);
                    }
                    rrs = rrs->next;
                }
                free((void*)str_name);
                free((void*)str_type);
                return 0;
            }
            node = ldns_rbtree_next(node);
        }
    }
    return 1;
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

    if (!domain) {
        return 1;
    }
    ods_log_assert(domain);

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
                ods_log_error("[%s] occluded glue data at zonecut, RRtype=%u",
                    dname_str, rrset->rr_type);
                return 0;
            } else if (rrset->rr_type == LDNS_RR_TYPE_A ||
                rrset->rr_type == LDNS_RR_TYPE_AAAA) {
                /* check if glue is allowed at the delegation */
/* allow for now (root zone has it)
                if (rrset_count_RR(rrset) > 0 &&
                    !domain_examine_ns_rdata(domain, domain->dname)) {
                    ods_log_error("[%s] occluded glue data at zonecut, #RR=%u",
                        dname_str, rrset_count_RR(rrset));
                    return 0;
                }
*/
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

    if (!domain || !rrtype) {
        return 1;
    }
    ods_log_assert(domain);
    ods_log_assert(rrtype);

    rrset = domain_lookup_rrset(domain, rrtype);
    if (rrset && rrset_count_RR(rrset) > 1) {
        /* multiple RRs in the RRset for singleton RRtype*/
        str_name = ldns_rdf2str(domain->dname);
        str_type = ldns_rr_type2str(rrtype);
        ods_log_error("[%s] multiple records for singleton type at %s %s",
            dname_str, str_name, str_type);
        free((void*)str_name);
        free((void*)str_type);
        return 0;
    }
    return 1;
}


/**
 * Commit updates to domain.
 *
 */
ods_status
domain_commit(domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    ods_status status = ODS_STATUS_OK;
    size_t numadd = 0;
    size_t numdel = 0;
    size_t numrrs = 0;
    size_t numnew = 0;

    if (!domain || !domain->rrsets) {
        return ODS_STATUS_OK;
    }
    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        numrrs = rrset_count_rr(rrset, COUNT_RR);
        numadd = rrset_count_rr(rrset, COUNT_ADD);
        numdel = rrset_count_rr(rrset, COUNT_DEL);

        if (rrset->rr_type == LDNS_RR_TYPE_SOA && rrset->rrs &&
            rrset->rrs->rr) {
            rrset->needs_signing = 1;
        }
        status = rrset_commit(rrset);
        if (status != ODS_STATUS_OK) {
            return status;
        }
        node = ldns_rbtree_next(node);
        numnew = rrset_count_rr(rrset, COUNT_RR);
        if (numrrs > 0 && numnew <= 0) {
            if (domain_del_rrset(domain, rrset) != NULL) {
                ods_log_warning("[%s] unable to commit: failed ",
                    "to delete RRset", dname_str);
                return ODS_STATUS_UNCHANGED;
            }
            if (domain->denial) {
                domain->denial->bitmap_changed = 1;
            }
        } else if (numrrs <= 0 && numnew == numadd) {
            if (domain->denial) {
                domain->denial->bitmap_changed = 1;
            }
        }
    }
    return status;
}


/**
 * Rollback updates from domain.
 *
 */
void
domain_rollback(domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;

    if (!domain || !domain->rrsets) {
        return;
    }
    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        rrset_rollback(rrset);
        node = ldns_rbtree_next(node);
    }
    return;
}


/**
 * Set domain status.
 *
 */
void
domain_dstatus(domain_type* domain)
{
    domain_type* parent = NULL;

    if (!domain) {
        ods_log_error("[%s] unable to set status: no domain", dname_str);
        return;
    }
    if (domain->dstatus == DOMAIN_STATUS_APEX) {
        /* that doesn't change... */
        return;
    }
    if (domain_count_rrset(domain) <= 0) {
        domain->dstatus = DOMAIN_STATUS_ENT;
        return;
    }

    if (domain_lookup_rrset(domain, LDNS_RR_TYPE_NS)) {
        if (domain_lookup_rrset(domain, LDNS_RR_TYPE_DS)) {
            domain->dstatus = DOMAIN_STATUS_DS;
        } else {
            domain->dstatus = DOMAIN_STATUS_NS;
        }
    } else {
        domain->dstatus = DOMAIN_STATUS_AUTH;
    }

    parent = domain->parent;
    while (parent && parent->dstatus != DOMAIN_STATUS_APEX) {
        if (domain_lookup_rrset(parent, LDNS_RR_TYPE_DNAME) ||
            domain_lookup_rrset(parent, LDNS_RR_TYPE_NS)) {
            domain->dstatus = DOMAIN_STATUS_OCCLUDED;
            return;
        }
        parent = parent->parent;
    }
    return;
}


/**
 * Queue all RRsets at this domain.
 *
 */
ods_status
domain_queue(domain_type* domain, fifoq_type* q, worker_type* worker)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!domain || !domain->rrsets) {
        return ODS_STATUS_OK;
    }
    if (domain->dstatus == DOMAIN_STATUS_NONE ||
        domain->dstatus == DOMAIN_STATUS_OCCLUDED) {
        return ODS_STATUS_OK;
    }

    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;

        /* skip delegation RRsets */
        if (domain->dstatus != DOMAIN_STATUS_APEX &&
            rrset->rr_type == LDNS_RR_TYPE_NS) {
            node = ldns_rbtree_next(node);
            continue;
        }
        /* skip glue at the delegation */
        if ((domain->dstatus == DOMAIN_STATUS_DS ||
             domain->dstatus == DOMAIN_STATUS_NS) &&
            (rrset->rr_type == LDNS_RR_TYPE_A ||
             rrset->rr_type == LDNS_RR_TYPE_AAAA)) {
            node = ldns_rbtree_next(node);
            continue;
        }
/*
        if (rrset->rr_type == LDNS_RR_TYPE_SOA && rrset->rrs &&
            rrset->rrs->rr) {
            soa_serial = ldns_rr_set_rdf(rrset->rrs->rr,
                ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, serial),
                SE_SOA_RDATA_SERIAL);
            if (soa_serial) {
                if (ldns_rdf2native_int32(soa_serial) != serial) {
                    rrset->needs_signing = 1;
                }
                ldns_rdf_deep_free(soa_serial);
             } else {
                ods_log_error("[%s] unable to sign domain: failed to replace "
                    "SOA SERIAL rdata", dname_str);
                return 1;
            }
        }
*/
        /* queue RRset for signing */
        status = rrset_queue(rrset, q, worker);
        if (status != ODS_STATUS_OK) {
            return status;
        }
        node = ldns_rbtree_next(node);
    }

    /* queue NSEC(3) RRset for signing */
    if (domain->denial && domain->denial->rrset) {
        status = rrset_queue(domain->denial->rrset, q, worker);
    }
    return status;
}


/**
 * Examine domain NS RRset and verify its RDATA.
 *
 */
int
domain_examine_ns_rdata(domain_type* domain, ldns_rdf* nsdname)
{
    rrset_type* rrset = NULL;

    if (!domain || !nsdname) {
       return 0;
    }
    rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_NS);
    if (rrset && rrset_examine_ns_rdata(rrset, nsdname)) {
        return 1;
    }
    return 0;
}


/**
 * Clean up RRsets at the domain.
 *
 */
static void
rrset_delfunc(ldns_rbnode_t* elem)
{
    rrset_type* rrset;

    if (elem && elem != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) elem->data;
        rrset_delfunc(elem->left);
        rrset_delfunc(elem->right);

        rrset_cleanup(rrset);
        free(elem);
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
    allocator_type* allocator;

    if (!domain) {
        return;
    }
    allocator = domain->allocator;

    if (domain->dname) {
        ldns_rdf_deep_free(domain->dname);
        domain->dname = NULL;
    }
    if (domain->rrsets) {
        rrset_delfunc(domain->rrsets->root);
        ldns_rbtree_free(domain->rrsets);
        domain->rrsets = NULL;
    }
    allocator_deallocate(allocator, (void*) domain);
    allocator_cleanup(allocator);
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
    char* str = NULL;
    int print_glue = 0;
    rrset_type* rrset = NULL;
    rrset_type* soa_rrset = NULL;
    rrset_type* cname_rrset = NULL;

    if (!domain || !fd) {
        return;
    }
    ods_log_assert(fd);
    ods_log_assert(domain);

    str = ldns_rdf2str(domain->dname);

    if (domain->rrsets) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    /* no other data may accompany a CNAME */
    cname_rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_CNAME);
    if (cname_rrset) {
        fprintf(fd, ";; Domain: %s\n", str);
        rrset_print(fd, cname_rrset, 0);
    } else {
        /* if SOA, print soa first */
        if (domain->dstatus == DOMAIN_STATUS_APEX) {
            soa_rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_SOA);
            if (soa_rrset) {
                fprintf(fd, ";; Zone: %s\n", str);
                rrset_print(fd, soa_rrset, 0);
            }
        } else if (domain->dstatus == DOMAIN_STATUS_ENT) {
            /* empty non-terminal */
            fprintf(fd, ";; Empty non-terminal: %s\n", str);
        } else if (domain->dstatus == DOMAIN_STATUS_OCCLUDED) {
            /* occluded or glue */
            fprintf(fd, ";; Occluded (glue): %s\n", str);
        } else if (domain->dstatus == DOMAIN_STATUS_NS ||
                   domain->dstatus == DOMAIN_STATUS_DS) {
            /* delegation */
            fprintf(fd, ";; Delegation: %s\n", str);
        } else if (domain->dstatus == DOMAIN_STATUS_NONE) {
            /* non-existent */
            fprintf(fd, ";; Non-existent: %s\n", str);
        } else {
            fprintf(fd, ";; Domain: %s\n", str);
        }

        /* print other RRsets */
        while (node && node != LDNS_RBTREE_NULL) {
            rrset = (rrset_type*) node->data;
            /* skip SOA RRset */
            if (rrset->rr_type != LDNS_RR_TYPE_SOA) {
                if (domain->dstatus == DOMAIN_STATUS_OCCLUDED) {
                    /* glue?  */
                    print_glue = 1;
/*
                    parent = domain->parent;
                    while (parent && parent->dstatus != DOMAIN_STATUS_APEX) {
                        if (domain_examine_ns_rdata(parent, domain->dname)) {
                            print_glue = 1;
                            break;
                        }
                        parent = parent->parent;
                    }
*/
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
    free((void*)str);

    /* denial of existence */
    if (domain->denial) {
        rrset_print(fd, domain->denial->rrset, 0);
    }

    fprintf(fd, ";\n");
    return;
}
