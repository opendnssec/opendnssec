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
 * Zone data.
 *
 */

#include "config.h"
#include "adapter/adapter.h"
#include "shared/allocator.h"
#include "shared/log.h"
#include "shared/util.h"
#include "signer/backup.h"
#include "signer/domain.h"
#include "signer/nsec3params.h"
#include "signer/zonedata.h"

#include <ldns/ldns.h> /* ldns_dname_*(), ldns_rbtree_*() */

static const char* zd_str = "data";


/**
 * Compare domains.
 *
 */
static int
domain_compare(const void* a, const void* b)
{
    ldns_rdf* x = (ldns_rdf*)a;
    ldns_rdf* y = (ldns_rdf*)b;
    return ldns_dname_compare(x, y);
}


/**
 * Create empty zone data..
 *
 */
zonedata_type*
zonedata_create(allocator_type* allocator)
{
    zonedata_type* zd = NULL;

    if (!allocator) {
        ods_log_error("[%s] cannot create zonedata: no allocator", zd_str);
        return NULL;
    }
    ods_log_assert(allocator);

    zd = (zonedata_type*) allocator_alloc(allocator, sizeof(zonedata_type));
    if (!zd) {
        ods_log_error("[%s] cannot create zonedata: allocator failed", zd_str);
        return NULL;
    }
    ods_log_assert(zd);

    zd->domains = ldns_rbtree_create(domain_compare);
    zd->denial_chain = ldns_rbtree_create(domain_compare);
    zd->initialized = 0;
    zd->inbound_serial = 0;
    zd->internal_serial = 0;
    zd->outbound_serial = 0;
    zd->default_ttl = 3600; /* configure --default-ttl option? */
    return zd;
}


static ldns_rbnode_t* domain2node(domain_type* domain);

/**
 * Recover zone data from backup.
 *
 */
int
zonedata_recover_from_backup(zonedata_type* zd, FILE* fd)
{
    int corrupted = 0;
    const char* token = NULL;
    domain_type* current_domain = NULL;
    ldns_rdf* parent_rdf = NULL;
    ldns_rr* rr = NULL;
    ldns_status status = LDNS_STATUS_OK;
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;

    ods_log_assert(zd);
    ods_log_assert(fd);

    if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC)) {
        corrupted = 1;
    }

/*

    while (!corrupted) {
        if (backup_read_str(fd, &token)) {
            if (ods_strcmp(token, ";DNAME") == 0) {
                current_domain = domain_recover_from_backup(fd);
                if (!current_domain) {
                    ods_log_error("[%s] error reading domain from backup file", zd_str);
                    corrupted = 1;
                } else {
                    parent_rdf = ldns_dname_left_chop(current_domain->dname);
                    if (!parent_rdf) {
                        ods_log_error("[%s] unable to create parent domain name (rdf)",
                            zd_str);
                        corrupted = 1;
                    } else {
                        current_domain->parent =
                            zonedata_lookup_domain(zd, parent_rdf);
                        ldns_rdf_deep_free(parent_rdf);
                        ods_log_assert(current_domain->parent ||
                            current_domain->dstatus == DOMAIN_STATUS_APEX);

                        new_node = domain2node(current_domain);
                        if (!zd->domains) {
                            zd->domains = ldns_rbtree_create(domain_compare);
                        }
                        if (ldns_rbtree_insert(zd->domains, new_node) == NULL) {
                            ods_log_error("[%s] error adding domain from backup file",
                                zd_str);
                            free((void*)new_node);
                            corrupted = 1;
                        }
                        new_node = NULL;
                    }
                }
            } else if (ods_strcmp(token, ";DNAME3") == 0) {
                ods_log_assert(current_domain);
                current_domain->nsec3 = domain_recover_from_backup(fd);
                if (!current_domain->nsec3) {
                    ods_log_error("[%s] error reading nsec3 domain from backup file",
                        zd_str);
                    corrupted = 1;
                } else {
                    current_domain->nsec3->nsec3 = current_domain;
                    new_node = domain2node(current_domain->nsec3);
                    if (!zd->nsec3_domains) {
                        zd->nsec3_domains = ldns_rbtree_create(domain_compare);
                    }

                    if (ldns_rbtree_insert(zd->nsec3_domains, new_node) == NULL) {
                        ods_log_error("[%s] error adding nsec3 domain from backup file",
                            zd_str);
                        free((void*)new_node);
                        corrupted = 1;
                    }
                    new_node = NULL;
                }
            } else if (ods_strcmp(token, ";NSEC") == 0) {
                status = ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL);
                if (status != LDNS_STATUS_OK) {
                    ods_log_error("[%s] error reading NSEC RR from backup file", zd_str);
                    if (rr) {
                        ldns_rr_free(rr);
                    }
                    corrupted = 1;
                } else {
                    ods_log_assert(current_domain);
                    current_domain->nsec_rrset = rrset_create_frm_rr(rr);
                    if (!current_domain->nsec_rrset) {
                        ods_log_error("[%s] error adding NSEC RR from backup file", zd_str);
                        corrupted = 1;
                    }
                }
                rr = NULL;
                status = LDNS_STATUS_OK;
            } else if (ods_strcmp(token, ";NSEC3") == 0) {
                status = ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL);
                if (status != LDNS_STATUS_OK) {
                    ods_log_error("[%s] error reading NSEC3 RR from backup file", zd_str);
                    if (rr) {
                        ldns_rr_free(rr);
                    }
                    corrupted = 1;
                } else {
                    ods_log_assert(current_domain);
                    ods_log_assert(current_domain->nsec3);
                    current_domain->nsec3->nsec_rrset = rrset_create_frm_rr(rr);
                    if (!current_domain->nsec3->nsec_rrset) {
                        ods_log_error("[%s] error adding NSEC3 RR from backup file", zd_str);
                        corrupted = 1;
                    }
                }
                rr = NULL;
                status = LDNS_STATUS_OK;
            } else if (ods_strcmp(token, ODS_SE_FILE_MAGIC) == 0) {
                free((void*)token);
                token = NULL;
                break;
            } else {
                corrupted = 1;
            }
            free((void*)token);
            token = NULL;
        } else {
            corrupted = 1;
        }
    }
*/
    return corrupted;
}


/**
 * Recover RR from backup.
 *
 */
int
zonedata_recover_rr_from_backup(zonedata_type* zd, ldns_rr* rr)
{
    domain_type* domain = NULL;

    ods_log_assert(zd);
    ods_log_assert(zd->domains);
    ods_log_assert(rr);

    domain = zonedata_lookup_domain(zd, ldns_rr_owner(rr));
    if (domain) {
        return domain_recover_rr_from_backup(domain, rr);
    }

    ods_log_error("[%s] unable to recover RR to zonedata: domain does not exist",
        zd_str);
    return 1;
}


/**
 * Recover RRSIG from backup.
 *
 */
int
zonedata_recover_rrsig_from_backup(zonedata_type* zd, ldns_rr* rrsig,
    const char* locator, uint32_t flags)
{
    domain_type* domain = NULL;
    ldns_rr_type type_covered;

    ods_log_assert(zd);
    ods_log_assert(zd->domains);
    ods_log_assert(rrsig);

    type_covered = ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rrsig));
    domain = zonedata_lookup_domain(zd, ldns_rr_owner(rrsig));
    if (domain) {
        return domain_recover_rrsig_from_backup(domain, rrsig, type_covered,
            locator, flags);
    }
    ods_log_error("[%s] unable to recover RRSIG to zonedata: domain does not exist",
        zd_str);
    return 1;
}


/**
 * Convert a domain to a tree node.
 *
 */
static ldns_rbnode_t*
domain2node(domain_type* domain)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) malloc(sizeof(ldns_rbnode_t));
    if (!node) {
        return NULL;
    }
    node->key = domain->dname;
    node->data = domain;
    return node;
}


/**
 * Internal lookup domain function.
 *
 */
static domain_type*
zonedata_domain_search(ldns_rbtree_t* tree, ldns_rdf* dname)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;

    if (!tree || !dname) {
        return NULL;
    }
    node = ldns_rbtree_search(tree, dname);
    if (node && node != LDNS_RBTREE_NULL) {
        return (domain_type*) node->data;
    }
    return NULL;
}


/**
 * Lookup domain.
 *
 */
domain_type*
zonedata_lookup_domain(zonedata_type* zd, ldns_rdf* dname)
{
    if (!zd || !zd->domains | !dname) {
        return NULL;
    }
    return zonedata_domain_search(zd->domains, dname);
}


/**
 * Add a domain to the zone data.
 *
 */
domain_type*
zonedata_add_domain(zonedata_type* zd, domain_type* domain)
{
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;
    char* str = NULL;

    if (!domain) {
        ods_log_error("[%s] unable to add domain: no domain", zd_str);
        return NULL;
    }
    ods_log_assert(domain);

    if (!zd || !zd->domains) {
        str = ldns_rdf2str(domain->dname);
        ods_log_error("[%s] unable to add domain %s: no storage", zd_str,
            str?str:"(null)");
        free((void*)str);
        return NULL;
    }
    ods_log_assert(zd);
    ods_log_assert(zd->domains);

    new_node = domain2node(domain);
    if (ldns_rbtree_insert(zd->domains, new_node) == NULL) {
        str = ldns_rdf2str(domain->dname);
        ods_log_error("[%s] unable to add domain %s: already present", zd_str,
            str?str:"(null)");
        free((void*)str);
        free((void*)new_node);
        return NULL;
    }
    str = ldns_rdf2str(domain->dname);
    ods_log_deeebug("+DD %s", str?str:"(null)");
    free((void*) str);
    return domain;
}


/**
 * Internal delete domain function.
 *
 */
static domain_type*
zonedata_del_domain_fixup(ldns_rbtree_t* tree, domain_type* domain)
{
    domain_type* del_domain = NULL;
    ldns_rbnode_t* del_node = LDNS_RBTREE_NULL;
    char* str = NULL;

    ods_log_assert(tree);
    ods_log_assert(domain);
    ods_log_assert(domain->dname);

    del_node = ldns_rbtree_search(tree, (const void*)domain->dname);
    if (del_node) {
        del_node = ldns_rbtree_delete(tree, (const void*)domain->dname);
        del_domain = (domain_type*) del_node->data;
        domain_cleanup(del_domain);
        free((void*)del_node);
        return NULL;
    } else {
        str = ldns_rdf2str(domain->dname);
        ods_log_error("[%s] unable to del domain %s: not found", zd_str,
            str?str:"(null)");
        free((void*)str);
    }
    return domain;
}


/**
 * Delete domain from the zone data.
 *
 */
domain_type*
zonedata_del_domain(zonedata_type* zd, domain_type* domain)
{
    char* str = NULL;

    if (!domain) {
        ods_log_error("[%s] unable to delete domain: no domain", zd_str);
        return NULL;
    }
    ods_log_assert(domain);
    ods_log_assert(domain->dname);

    if (!zd || !zd->domains) {
        str = ldns_rdf2str(domain->dname);
        ods_log_error("[%s] unable to delete domain %s: no zonedata",
            zd_str, str?str:"(null)");
        free((void*)str);
        return domain;
    }
    ods_log_assert(zd);
    ods_log_assert(zd->domains);

    str = ldns_rdf2str(domain->dname);
    ods_log_deeebug("-DD %s", str?str:"(null)");
    if (domain->denial && zonedata_del_denial(zd, domain->denial) != NULL) {
        str = ldns_rdf2str(domain->dname);
        ods_log_error("[%s] unable to delete domain %s: failed to delete "
            "denial of existence data point", zd_str, str?str:"(null)");
        free((void*)str);
        return domain;
    }
    free((void*) str);
    return zonedata_del_domain_fixup(zd->domains, domain);
}


/**
 * Convert a denial of existence data point to a tree node.
 *
 */
static ldns_rbnode_t*
denial2node(denial_type* denial)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) malloc(sizeof(ldns_rbnode_t));
    if (!node) {
        return NULL;
    }
    node->key = denial->owner;
    node->data = denial;
    return node;
}


/**
 * Internal function to lookup denial of existence data point.
 *
 */
static denial_type*
zonedata_denial_search(ldns_rbtree_t* tree, ldns_rdf* dname)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;

    if (!tree || !dname) {
        return NULL;
    }
    node = ldns_rbtree_search(tree, dname);
    if (node && node != LDNS_RBTREE_NULL) {
        return (denial_type*) node->data;
    }
    return NULL;
}


/**
 * Lookup denial of existence data point.
 *
 */
denial_type*
zonedata_lookup_denial(zonedata_type* zd, ldns_rdf* dname)
{
    if (!zd || !zd->denial_chain | !dname) {
        return NULL;
    }
    return zonedata_denial_search(zd->denial_chain, dname);
}


/**
 * Provide domain with NSEC3 hashed domain.
 *
 */
static ldns_rdf*
dname_hash(ldns_rdf* dname, ldns_rdf* apex, nsec3params_type* nsec3params)
{
    ldns_rdf* hashed_ownername = NULL;
    ldns_rdf* hashed_label = NULL;
    char* str = NULL;

    ods_log_assert(dname);
    ods_log_assert(apex);
    ods_log_assert(nsec3params);

    /**
     * The owner name of the NSEC3 RR is the hash of the original owner
     * name, prepended as a single label to the zone name.
     */
    hashed_label = ldns_nsec3_hash_name(dname, nsec3params->algorithm,
        nsec3params->iterations, nsec3params->salt_len,
        nsec3params->salt_data);
    if (!hashed_label) {
        str = ldns_rdf2str(dname);
        ods_log_error("[%s] unable to hash dname %s: hash failed", zd_str,
            str?str:"(null)");
        free((void*)str);
        return NULL;
    }
    hashed_ownername = ldns_dname_cat_clone((const ldns_rdf*) hashed_label,
        (const ldns_rdf*) apex);
    if (!hashed_ownername) {
        str = ldns_rdf2str(dname);
        ods_log_error("[%s] unable to hash dname %s: concat apex failed",
            zd_str, str?str:"(null)");
        free((void*)str);
        return NULL;
    }
    ldns_rdf_deep_free(hashed_label);
    return hashed_ownername;
}


/**
 * Add denial of existence data point to the zone data.
 *
 */
ods_status
zonedata_add_denial(zonedata_type* zd, domain_type* domain, ldns_rdf* apex,
    nsec3params_type* nsec3params)
{
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* prev_node = LDNS_RBTREE_NULL;
    ldns_rdf* owner = NULL;
    denial_type* denial = NULL;
    denial_type* prev_denial = NULL;
    char* str = NULL;

    if (!domain) {
        ods_log_error("[%s] unable to add denial of existence data point: "
            "no domain", zd_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(domain);

    if (!zd || !zd->denial_chain) {
        str = ldns_rdf2str(domain->dname);
        ods_log_error("[%s] unable to add denial of existence data point "
            "for domain %s: no denial chain", zd_str, str?str:"(null)");
        free((void*)str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zd);
    ods_log_assert(zd->denial_chain);

    if (!apex) {
        str = ldns_rdf2str(domain->dname);
        ods_log_error("[%s] unable to add denial of existence data point "
            "for domain %s: apex unknown", zd_str, str?str:"(null)");
        free((void*)str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(apex);

    /* nsec or nsec3 */
    if (nsec3params) {
        owner = dname_hash(domain->dname, apex, nsec3params);
        if (!owner) {
            str = ldns_rdf2str(domain->dname);
            ods_log_error("[%s] unable to add denial of existence data point "
                "for domain %s: dname hash failed", zd_str, str?str:"(null)");
            free((void*)str);
            return ODS_STATUS_ERR;
        }
    } else {
        owner = ldns_rdf_clone(domain->dname);
    }
    /* lookup */
    if (zonedata_lookup_denial(zd, owner) != NULL) {
        str = ldns_rdf2str(domain->dname);
        ods_log_error("[%s] unable to add denial of existence for %s: "
            "data point exists", zd_str, str?str:"(null)");
        free((void*)str);
        return ODS_STATUS_CONFLICT_ERR;
    }
    /* create */
    denial = denial_create(owner);
    new_node = denial2node(denial);
    ldns_rdf_deep_free(owner);
    /* insert */
    if (!ldns_rbtree_insert(zd->denial_chain, new_node)) {
        str = ldns_rdf2str(domain->dname);
        ods_log_error("[%s] unable to add denial of existence for %s: "
            "insert failed", zd_str, str?str:"(null)");
        free((void*)str);
        free((void*)new_node);
        denial_cleanup(denial);
        return ODS_STATUS_ERR;
    }
    /* denial of existence data point added */
    denial->bitmap_changed = 1;
    denial->nxt_changed = 1;
    prev_node = ldns_rbtree_previous(new_node);
    if (!prev_node || prev_node == LDNS_RBTREE_NULL) {
        prev_node = ldns_rbtree_last(zd->denial_chain);
    }
    ods_log_assert(prev_node);
    prev_denial = (denial_type*) prev_node->data;
    ods_log_assert(prev_denial);
    prev_denial->nxt_changed = 1;
    domain->denial = denial;
    domain->denial->domain = domain; /* back reference */
    return ODS_STATUS_OK;
}


/**
 * Internal delete denial function.
 *
 */
static denial_type*
zonedata_del_denial_fixup(ldns_rbtree_t* tree, denial_type* denial)
{
    denial_type* del_denial = NULL;
    denial_type* prev_denial = NULL;
    ldns_rbnode_t* prev_node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* del_node = LDNS_RBTREE_NULL;
    ods_status status = ODS_STATUS_OK;
    char* str = NULL;

    ods_log_assert(tree);
    ods_log_assert(denial);
    ods_log_assert(denial->owner);

    del_node = ldns_rbtree_search(tree, (const void*)denial->owner);
    if (del_node) {
        /**
         * [CALC] if domain removed, mark previous domain NSEC(3) nxt changed.
         *
         */
        prev_node = ldns_rbtree_previous(del_node);
        if (!prev_node || prev_node == LDNS_RBTREE_NULL) {
            prev_node = ldns_rbtree_last(tree);
        }
        ods_log_assert(prev_node);
        ods_log_assert(prev_node->data);
        prev_denial = (denial_type*) prev_node->data;
        prev_denial->nxt_changed = 1;

        /* delete old NSEC RR(s) */
        if (denial->rrset) {
            status = rrset_wipe_out(denial->rrset);
            if (status != ODS_STATUS_OK) {
                ods_log_alert("[%s] unable to del denial of existence data "
                    "point: failed to wipe out NSEC RRset", zd_str);
                return denial;
            }
            rrset_commit(denial->rrset);
            if (status != ODS_STATUS_OK) {
                ods_log_alert("[%s] unable to del denial of existence data "
                    "point: failed to commit NSEC RRset", zd_str);
                return denial;
            }
        }

        del_node = ldns_rbtree_delete(tree, (const void*)denial->owner);
        del_denial = (denial_type*) del_node->data;
        denial_cleanup(del_denial);
        free((void*)del_node);
        return NULL;
    } else {
        str = ldns_rdf2str(denial->owner);
        ods_log_error("[%s] unable to del denial of existence data point %s: "
            "not found", zd_str, str?str:"(null)");
        free((void*)str);
    }
    return denial;
}


/**
 * Delete denial of existence data point from the zone data.
 *
 */
denial_type*
zonedata_del_denial(zonedata_type* zd, denial_type* denial)
{
    char* str = NULL;

    if (!denial) {
        ods_log_error("[%s] unable to delete denial of existence data point: "
            "no data point", zd_str);
        return NULL;
    }
    ods_log_assert(denial);

    if (!zd || !zd->denial_chain) {
        str = ldns_rdf2str(denial->owner);
        ods_log_error("[%s] unable to delete denial of existence data point "
            "%s: no zone data", zd_str, str?str:"(null)");
        free((void*)str);
        return denial;
    }
    ods_log_assert(zd);
    ods_log_assert(zd->denial_chain);

    return zonedata_del_denial_fixup(zd->denial_chain, denial);
}


/**
 * Calculate differences at the zonedata between current and new RRsets.
 *
 */
ods_status
zonedata_diff(zonedata_type* zd, keylist_type* kl)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!zd || !zd->domains) {
        return status;
    }
    if (zd->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zd->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        status = domain_diff(domain, kl);
        if (status != ODS_STATUS_OK) {
            return status;
        }
        node = ldns_rbtree_next(node);
    }
    return status;
}


/**
 * Commit updates to zone data.
 *
 */
ods_status
zonedata_commit(zonedata_type* zd)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* nxtnode = LDNS_RBTREE_NULL;
    ldns_rbnode_t* tmpnode = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    domain_type* nxtdomain = NULL;
    ods_status status = ODS_STATUS_OK;
    size_t oldnum = 0;

    if (!zd || !zd->domains) {
        return ODS_STATUS_OK;
    }
    if (zd->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_last(zd->domains);
    }

    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        oldnum = domain_count_rrset(domain);
        status = domain_commit(domain);
        if (status != ODS_STATUS_OK) {
            return status;
        }
        tmpnode = node;
        node = ldns_rbtree_previous(node);

        /* delete memory if empty leaf domain */
        if (domain_count_rrset(domain) <= 0) {
            /* empty domain */
            nxtnode = ldns_rbtree_next(tmpnode);
            nxtdomain = NULL;
            if (nxtnode && nxtnode != LDNS_RBTREE_NULL) {
                nxtdomain = (domain_type*) nxtnode->data;
            }
            if (!nxtdomain ||
                !ldns_dname_is_subdomain(nxtdomain->dname, domain->dname)) {
                /* leaf domain */
                if (zonedata_del_domain(zd, domain) != NULL) {
                    ods_log_warning("[%s] unable to delete obsoleted "
                        "domain", zd_str);
                    return ODS_STATUS_ERR;
                }
            }
        } /* if (domain_count_rrset(domain) <= 0) */
    }
    return status;
}


/**
 * Rollback updates from zone data.
 *
 */
void
zonedata_rollback(zonedata_type* zd)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    if (!zd || !zd->domains) {
        return;
    }
    if (zd->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zd->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_rollback(domain);
        node = ldns_rbtree_next(node);
    }
    return;
}


/**
 * See if the domain is an empty non-terminal to glue.
 *
 */
static int
domain_ent2glue(ldns_rbnode_t* node)
{
    ldns_rbnode_t* nextnode = LDNS_RBTREE_NULL;
    domain_type* nextdomain = NULL;
    domain_type* domain = NULL;
    ods_log_assert(node && node != LDNS_RBTREE_NULL);
    domain = (domain_type*) node->data;
    if (domain->dstatus == DOMAIN_STATUS_ENT) {
        ods_log_assert(domain_count_rrset(domain) == 0);
        nextnode = ldns_rbtree_next(node);
        while (nextnode && nextnode != LDNS_RBTREE_NULL) {
            nextdomain = (domain_type*) nextnode->data;
            if (!ldns_dname_is_subdomain(nextdomain->dname, domain->dname)) {
                /* we are done, no non-glue found */
                return 1;
            }
            if (nextdomain->dstatus != DOMAIN_STATUS_OCCLUDED &&
                nextdomain->dstatus != DOMAIN_STATUS_ENT &&
                nextdomain->dstatus != DOMAIN_STATUS_NONE) {
                /* found non-glue */
                return 0;
            }
            nextnode = ldns_rbtree_next(nextnode);
        }
    } else {
        /* no empty non-terminal */
        ods_log_assert(domain_count_rrset(domain) != 0);
        return 0;
    }
    /* no non-glue found */
    return 1;
}


/**
 * See if the domain is an empty non-terminal to unsigned data.
 *
 */
static int
domain_ent2unsigned(ldns_rbnode_t* node)
{
    ldns_rbnode_t* nextnode = LDNS_RBTREE_NULL;
    domain_type* nextdomain = NULL;
    domain_type* domain = NULL;
    ods_log_assert(node && node != LDNS_RBTREE_NULL);
    domain = (domain_type*) node->data;
    if (domain->dstatus == DOMAIN_STATUS_ENT) {
        ods_log_assert(domain_count_rrset(domain) == 0);
        nextnode = ldns_rbtree_next(node);
        while (nextnode && nextnode != LDNS_RBTREE_NULL) {
            nextdomain = (domain_type*) nextnode->data;
            if (!ldns_dname_is_subdomain(nextdomain->dname, domain->dname)) {
                /* we are done, no unsigned delegation found */
                return 1;
            }
            if (nextdomain->dstatus != DOMAIN_STATUS_OCCLUDED &&
                nextdomain->dstatus != DOMAIN_STATUS_ENT &&
                nextdomain->dstatus != DOMAIN_STATUS_NS &&
                nextdomain->dstatus != DOMAIN_STATUS_NONE) {
                /* found data that has to be signed */
                return 0;
            }
            nextnode = ldns_rbtree_next(nextnode);
        }
    } else {
        /* no empty non-terminal */
        ods_log_assert(domain_count_rrset(domain) != 0);
        return 0;
    }
    /* no unsigned delegation found */
    return 1;
}


/**
 * Add empty non-terminals to zone data from this domain up.
 *
 */
static ods_status
domain_entize(zonedata_type* zd, domain_type* domain, ldns_rdf* apex)
{
    ldns_rdf* parent_rdf = NULL;
    domain_type* parent_domain = NULL;
    char* str = NULL;

    ods_log_assert(apex);
    ods_log_assert(domain);
    ods_log_assert(domain->dname);
    ods_log_assert(zd);
    ods_log_assert(zd->domains);

    if (domain->parent) {
        /* domain already has parent */
        return ODS_STATUS_OK;
    }

    while (domain && ldns_dname_is_subdomain(domain->dname, apex) &&
           ldns_dname_compare(domain->dname, apex) != 0) {

        str = ldns_rdf2str(domain->dname);

        /**
         * RFC5155:
         * 4. If the difference in number of labels between the apex and
         *    the original owner name is greater than 1, additional NSEC3
         *    RRs need to be added for every empty non-terminal between
         *     the apex and the original owner name.
         */
        parent_rdf = ldns_dname_left_chop(domain->dname);
        if (!parent_rdf) {
            ods_log_error("[%s] unable to entize domain %s: left chop failed",
                zd_str, str);
            free((void*)str);
            return ODS_STATUS_ERR;
        }
        ods_log_assert(parent_rdf);

        parent_domain = zonedata_lookup_domain(zd, parent_rdf);
        if (!parent_domain) {
            parent_domain = domain_create(parent_rdf);
            ldns_rdf_deep_free(parent_rdf);
            if (!parent_domain) {
                ods_log_error("[%s] unable to entize domain %s: create parent "
                    "failed", zd_str, str);
                free((void*)str);
                return ODS_STATUS_ERR;
            }
            ods_log_assert(parent_domain);
            if (zonedata_add_domain(zd, parent_domain) == NULL) {
                ods_log_error("[%s] unable to entize domain %s: add parent "
                    "failed", zd_str, str);
                domain_cleanup(parent_domain);
                free((void*)str);
                return ODS_STATUS_ERR;
            }
            parent_domain->dstatus = DOMAIN_STATUS_ENT;
            domain->parent = parent_domain;
            /* continue with the parent domain */
            domain = parent_domain;
        } else {
            ldns_rdf_deep_free(parent_rdf);
            domain->parent = parent_domain;
            /* we are done with this domain */
            domain = NULL;
        }
        free((void*)str);
    }
    return ODS_STATUS_OK;
}


/**
 * Add empty non-terminals to zone data.
 *
 */
ods_status
zonedata_entize(zonedata_type* zd, ldns_rdf* apex)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;

    if (!zd || !zd->domains) {
        ods_log_error("[%s] unable to entize zone data: no zone data",
            zd_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zd);
    ods_log_assert(zd->domains);

    if (!apex) {
        ods_log_error("[%s] unable to entize zone data: no zone apex",
            zd_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(apex);

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        status = domain_entize(zd, domain, apex);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to entize zone data: entize domain "
                "failed", zd_str);
            return status;
        }
        domain_dstatus(domain);
        node = ldns_rbtree_next(node);
    }
    return ODS_STATUS_OK;
}


/**
 * Add NSEC records to zonedata.
 *
 */
ods_status
zonedata_nsecify(zonedata_type* zd, ldns_rr_class klass, uint32_t ttl)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* nxt_node = LDNS_RBTREE_NULL;
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;
    domain_type* apex = NULL;
    denial_type* denial = NULL;
    denial_type* nxt = NULL;
    char* str = NULL;

    if (!zd || !zd->domains) {
        return ODS_STATUS_OK;
    }
    ods_log_assert(zd);
    ods_log_assert(zd->domains);

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain->dstatus == DOMAIN_STATUS_APEX) {
            apex = domain;
        }
        /* don't do glue-only or empty domains */
        if (domain->dstatus == DOMAIN_STATUS_NONE ||
            domain->dstatus == DOMAIN_STATUS_ENT ||
            domain->dstatus == DOMAIN_STATUS_OCCLUDED ||
            domain_count_rrset(domain) <= 0) {
            str = ldns_rdf2str(domain->dname);
            ods_log_deeebug("[%s] nsecify3: don't do %s domain %s", zd_str,
                domain_count_rrset(domain)?"glue":"emtpy", str?str:"(null)");
            free((void*) str);
            if (domain->denial) {
                if (zonedata_del_denial(zd, domain->denial) != NULL) {
                    ods_log_warning("[%s] unable to nsecify: failed to "
                        "delete denial of existence data point", zd_str);
                    return ODS_STATUS_ERR;
                }
            }
            node = ldns_rbtree_next(node);
            continue;
        }
        if (!apex) {
            ods_log_alert("[%s] unable to nsecify: apex unknown", zd_str);
            return ODS_STATUS_ASSERT_ERR;
        }

        /* add the denial of existence */
        if (!domain->denial) {
            status = zonedata_add_denial(zd, domain, apex->dname, NULL);
            if (status != ODS_STATUS_OK) {
                str = ldns_rdf2str(domain->dname);
                ods_log_alert("[%s] unable to nsecify: failed to add denial "
                    "of existence for domain %s", zd_str, str?str:"(null)");
                free((void*) str);
                return status;
            }
        }
        node = ldns_rbtree_next(node);
    }

    /** Now we have the complete denial of existence chain */
    node = ldns_rbtree_first(zd->denial_chain);
    while (node && node != LDNS_RBTREE_NULL) {
        denial = (denial_type*) node->data;
        nxt_node = ldns_rbtree_next(node);
        if (!nxt_node || nxt_node == LDNS_RBTREE_NULL) {
             nxt_node = ldns_rbtree_first(zd->denial_chain);
        }
        nxt = (denial_type*) nxt_node->data;

        status = denial_nsecify(denial, nxt, ttl, klass);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to nsecify: failed to add NSEC record",
                zd_str);
            return status;
        }
        node = ldns_rbtree_next(node);
    }
    return ODS_STATUS_OK;
}


/**
 * Add NSEC3 records to zonedata.
 *
 */
ods_status
zonedata_nsecify3(zonedata_type* zd, ldns_rr_class klass,
    uint32_t ttl, nsec3params_type* nsec3params)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* nxt_node = LDNS_RBTREE_NULL;
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;
    domain_type* apex = NULL;
    denial_type* denial = NULL;
    denial_type* nxt = NULL;
    char* str = NULL;

    if (!zd || !zd->domains) {
        return ODS_STATUS_OK;
    }
    ods_log_assert(zd);
    ods_log_assert(zd->domains);

    if (!nsec3params) {
        ods_log_error("[%s] unable to nsecify3: no nsec3 paramaters", zd_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(nsec3params);

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain->dstatus == DOMAIN_STATUS_APEX) {
            apex = domain;
        }

        /* don't do glue-only domains */
        if (domain->dstatus == DOMAIN_STATUS_NONE ||
            domain->dstatus == DOMAIN_STATUS_OCCLUDED ||
            domain_ent2glue(node)) {
            str = ldns_rdf2str(domain->dname);
            ods_log_deeebug("[%s] nsecify3: don't do glue domain %s", zd_str,
                str?str:"(null)");
            free((void*) str);
            if (domain->denial) {
                if (zonedata_del_denial(zd, domain->denial) != NULL) {
                    ods_log_error("[%s] unable to nsecify3: failed to "
                        "delete denial of existence data point", zd_str);
                    return ODS_STATUS_ERR;
                }
            }
            node = ldns_rbtree_next(node);
            continue;
        }
        /* Opt-Out? */
        if (nsec3params->flags) {
            /* If Opt-Out is being used, owner names of unsigned delegations
               MAY be excluded. */
            if (domain->dstatus == DOMAIN_STATUS_NS ||
                domain_ent2unsigned(node)) {
                str = ldns_rdf2str(domain->dname);
                ods_log_debug("[%s] nsecify3: opt-out %s (%s)", zd_str,
                    str?str:"(null)",
                    domain->dstatus == DOMAIN_STATUS_NS ?
                    "unsigned delegation" : "empty non-terminal (to unsigned "
                    "delegation)");
                free((void*) str);
                if (domain->denial) {
                    if (zonedata_del_denial(zd, domain->denial) != NULL) {
                        ods_log_error("[%s] unable to nsecify3: failed to "
                            "delete denial of existence data point", zd_str);
                        return ODS_STATUS_ERR;
                    }
                }
                node = ldns_rbtree_next(node);
                continue;
            }
        }
        if (!apex) {
            ods_log_alert("[%s] unable to nsecify3: apex unknown", zd_str);
            return ODS_STATUS_ASSERT_ERR;
        }

        /* add the denial of existence */
        if (!domain->denial) {
            status = zonedata_add_denial(zd, domain, apex->dname, nsec3params);
            if (status != ODS_STATUS_OK) {
                str = ldns_rdf2str(domain->dname);
                ods_log_alert("[%s] unable to nsecify3: failed to add denial "
                    "of existence for domain %s", zd_str, str?str:"(null)");
                free((void*) str);
                return status;
            }
        }
        node = ldns_rbtree_next(node);

        /* The Next Hashed Owner Name field is left blank for the moment. */

        /**
         * Additionally, for collision detection purposes, optionally
         * create an additional NSEC3 RR corresponding to the original
         * owner name with the asterisk label prepended (i.e., as if a
         * wildcard existed as a child of this owner name) and keep track
         * of this original owner name. Mark this NSEC3 RR as temporary.
        **/
        /* [TODO] */
        /**
         * pseudo:
         * wildcard_name = *.domain->dname;
         * hashed_ownername = ldns_nsec3_hash_name(domain->dname,
               nsec3params->algorithm, nsec3params->iterations,
               nsec3params->salt_len, nsec3params->salt);
         * domain->nsec3_wildcard = denial_create(hashed_ownername);
        **/

    }

    /** Now we have the complete denial of existence chain */
    node = ldns_rbtree_first(zd->denial_chain);
    while (node && node != LDNS_RBTREE_NULL) {
        denial = (denial_type*) node->data;
        nxt_node = ldns_rbtree_next(node);
        if (!nxt_node || nxt_node == LDNS_RBTREE_NULL) {
             nxt_node = ldns_rbtree_first(zd->denial_chain);
        }
        nxt = (denial_type*) nxt_node->data;

        status = denial_nsecify3(denial, nxt, ttl, klass, nsec3params);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to nsecify3: failed to add NSEC3 "
                "record", zd_str);
            return status;
        }
        node = ldns_rbtree_next(node);
    }
    return ODS_STATUS_OK;
}


/**
 * Update the serial.
 *
 */
static int
zonedata_update_serial(zonedata_type* zd, signconf_type* sc)
{
    uint32_t soa = 0;
    uint32_t prev = 0;
    uint32_t update = 0;

    ods_log_assert(zd);
    ods_log_assert(sc);

    prev = zd->internal_serial;
    if (!zd->initialized) {
        prev = zd->inbound_serial;
    }
    ods_log_debug("[%s] update serial: in=%u internal=%u out=%u now=%u",
        zd_str, zd->inbound_serial, zd->internal_serial, zd->outbound_serial,
        (uint32_t) time_now());

    if (!sc->soa_serial) {
        ods_log_error("[%s] no serial type given", zd_str);
        return 1;
    }

    if (ods_strcmp(sc->soa_serial, "unixtime") == 0) {
        soa = (uint32_t) time_now();
        if (!DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
    } else if (strncmp(sc->soa_serial, "counter", 7) == 0) {
        soa = prev + 1;
    } else if (strncmp(sc->soa_serial, "datecounter", 11) == 0) {
        soa = (uint32_t) time_datestamp(0, "%Y%m%d", NULL) * 100;
        if (!DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
    } else if (strncmp(sc->soa_serial, "keep", 4) == 0) {
        soa = zd->inbound_serial;
        if (zd->initialized && !DNS_SERIAL_GT(soa, prev)) {
            ods_log_error("[%s] cannot keep SOA SERIAL from input zone "
                " (%u): output SOA SERIAL is %u", zd_str, soa, prev);
            return 1;
        }
    } else {
        ods_log_error("[%s] unknown serial type %s", zd_str, sc->soa_serial);
        return 1;
    }

    /* serial is stored in 32 bits */
    update = soa - prev;
    if (update > 0x7FFFFFFF) {
        update = 0x7FFFFFFF;
    }

    if (!zd->initialized) {
        zd->internal_serial = soa;
        zd->initialized = 1;
    } else {
        zd->internal_serial += update; /* automatically does % 2^32 */
    }
    ods_log_debug("[%s] update serial: %u + %u = %u", zd_str, prev, update,
        zd->internal_serial);
    return 0;
}


/**
 * Add RRSIG records to zonedata.
 *
 */
int
zonedata_sign(zonedata_type* zd, ldns_rdf* owner, signconf_type* sc,
    stats_type* stats)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    time_t now = 0;
    hsm_ctx_t* ctx = NULL;
    int error = 0;

    ods_log_assert(sc);
    ods_log_assert(zd);
    ods_log_assert(zd->domains);

    error = zonedata_update_serial(zd, sc);
    if (error) {
        ods_log_error("[%s] unable to sign zone data: failed to update serial",
            zd_str);
        return 1;
    }

    now = time_now();
    ctx = hsm_create_context();
    if (!ctx) {
        ods_log_error("[%s] error creating libhsm context", zd_str);
        return 2;
    }

    ods_log_debug("[%s] rrsig timers: offset=%u jitter=%u validity=%u", zd_str,
        duration2time(sc->sig_inception_offset),
        duration2time(sc->sig_jitter),
        duration2time(sc->sig_validity_denial));

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain_sign(ctx, domain, owner, sc, now, zd->internal_serial,
            stats) != 0) {
            ods_log_error("[%s] unable to sign zone data: failed to sign domain",
                zd_str);
            hsm_destroy_context(ctx);
            return 1;
        }
        node = ldns_rbtree_next(node);
    }
    hsm_destroy_context(ctx);
    return 0;
}


/**
 * Examine domain for occluded data.
 *
 */
static int
zonedata_examine_domain_is_occluded(zonedata_type* zd, domain_type* domain,
    ldns_rdf* apex)
{
    ldns_rdf* parent_rdf = NULL;
    ldns_rdf* next_rdf = NULL;
    domain_type* parent_domain = NULL;
    char* str_name = NULL;
    char* str_parent = NULL;

    ods_log_assert(apex);
    ods_log_assert(domain);
    ods_log_assert(domain->dname);
    ods_log_assert(zd);
    ods_log_assert(zd->domains);

    if (ldns_dname_compare(domain->dname, apex) == 0) {
        return 0;
    }

    if (domain_examine_valid_zonecut(domain) != 0) {
        str_name = ldns_rdf2str(domain->dname);
        ods_log_warning("[%s] occluded (non-glue non-DS) data at %s NS",
            zd_str, str_name);
        free((void*)str_name);
        return 1;
    }

    parent_rdf = ldns_dname_left_chop(domain->dname);
    while (parent_rdf && ldns_dname_is_subdomain(parent_rdf, apex) &&
           ldns_dname_compare(parent_rdf, apex) != 0) {

        parent_domain = zonedata_lookup_domain(zd, parent_rdf);
        next_rdf = ldns_dname_left_chop(parent_rdf);
        ldns_rdf_deep_free(parent_rdf);

        if (parent_domain) {
            /* check for DNAME or NS */
            if (domain_examine_data_exists(parent_domain, LDNS_RR_TYPE_DNAME,
                0) && domain_examine_data_exists(domain, 0, 0)) {
                /* data below DNAME */
                str_name = ldns_rdf2str(domain->dname);
                str_parent = ldns_rdf2str(parent_domain->dname);
                ods_log_warning("[%s] occluded data at %s (below %s DNAME)",
                    zd_str, str_name, str_parent);
                free((void*)str_name);
                free((void*)str_parent);
                return 1;
            } else if (domain_examine_data_exists(parent_domain,
                LDNS_RR_TYPE_NS, 0) &&
                domain_examine_data_exists(domain, 0, 1)) {
                /* data (non-glue) below NS */
                str_name = ldns_rdf2str(domain->dname);
                str_parent = ldns_rdf2str(parent_domain->dname);
                ods_log_warning("[%s] occluded (non-glue) data at %s (below "
                    "%s NS)", zd_str, str_name, str_parent);
                free((void*)str_name);
                free((void*)str_parent);
                return 1;
/* allow for now (root zone has it)
            } else if (domain_examine_data_exists(parent_domain,
                LDNS_RR_TYPE_NS, 0) &&
                domain_examine_data_exists(domain, 0, 0) &&
                !domain_examine_ns_rdata(parent_domain, domain->dname)) {
                str_name = ldns_rdf2str(domain->dname);
                str_parent = ldns_rdf2str(parent_domain->dname);
                ods_log_warning("[%s] occluded data at %s (below %s NS)",
                    zd_str, str_name, str_parent);
                free((void*)str_name);
                free((void*)str_parent);
                return 1;
*/
            }
        }
        parent_rdf = next_rdf;
    }
    if (parent_rdf) {
        ldns_rdf_deep_free(parent_rdf);
    }
    return 0;
}


/**
 * Examine updates to zone data.
 *
 */
ods_status
zonedata_examine(zonedata_type* zd, ldns_rdf* apex, adapter_mode mode)
{
    int result = 0;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!zd || !zd->domains) {
       /* no zone data, no error */
       return ODS_STATUS_OK;
    }
    ods_log_assert(zd);
    ods_log_assert(zd->domains);

    if (zd->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zd->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        result =
        /* Thou shall not have other data next to CNAME */
        domain_examine_rrset_is_alone(domain, LDNS_RR_TYPE_CNAME) &&
        /* Thou shall have at most one CNAME per name */
        domain_examine_rrset_is_singleton(domain, LDNS_RR_TYPE_CNAME) &&
        /* Thou shall have at most one DNAME per name */
        domain_examine_rrset_is_singleton(domain, LDNS_RR_TYPE_DNAME);
        if (!result) {
            status = ODS_STATUS_ERR;
        }

        if (mode == ADAPTER_FILE) {
            result =
            /* Thou shall not have occluded data in your zone file */
            zonedata_examine_domain_is_occluded(zd, domain, apex);
            if (result) {
                ; /* just warn if there is occluded data */
            }
        }
        node = ldns_rbtree_next(node);
    }
    return status;
}


/**
 * Wipe out all NSEC RRsets.
 *
 */
void
zonedata_wipe_denial(zonedata_type* zd)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    denial_type* denial = NULL;

    if (zd && zd->denial_chain) {
        node = ldns_rbtree_first(zd->denial_chain);
        while (node && node != LDNS_RBTREE_NULL) {
            denial = (denial_type*) node->data;
            if (denial->rrset) {
                /* [TODO] IXFR delete NSEC */
                rrset_cleanup(denial->rrset);
                denial->rrset = NULL;
            }
            node = ldns_rbtree_next(node);
        }
    }
    return;
}


/**
 * Clean up domains in zone data.
 *
 */
static void
domain_delfunc(ldns_rbnode_t* elem)
{
    domain_type* domain;

    if (elem && elem != LDNS_RBTREE_NULL) {
        domain = (domain_type*) elem->data;
        domain_delfunc(elem->left);
        domain_delfunc(elem->right);

        domain_cleanup(domain);
        free((void*)elem);
    }
    return;
}


/**
 * Clean up denial of existence data points from zone data.
 *
 */
static void
denial_delfunc(ldns_rbnode_t* elem)
{
    denial_type* denial;

    if (elem && elem != LDNS_RBTREE_NULL) {
        denial = (denial_type*) elem->data;
        denial_delfunc(elem->left);
        denial_delfunc(elem->right);

        denial_cleanup(denial);
        free((void*)elem);
    }
    return;
}


/**
 * Clean up zone data.
 *
 */
void
zonedata_cleanup(zonedata_type* zd)
{
    if (zd) {
        if (zd->domains) {
            domain_delfunc(zd->domains->root);
            ldns_rbtree_free(zd->domains);
            zd->domains = NULL;
        }
        if (zd->denial_chain) {
            denial_delfunc(zd->denial_chain->root);
            ldns_rbtree_free(zd->denial_chain);
            zd->denial_chain = NULL;
        }
    }
    return;
}


/**
 * Print zone data.
 *
 */
ods_status
zonedata_print(FILE* fd, zonedata_type* zd)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    if (!fd) {
        ods_log_error("[%s] unable to print zone data: no file descriptor",
            zd_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(fd);

    if (!zd || !zd->domains) {
        ods_log_error("[%s] unable to print zone data: no zone data",
            zd_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zd);
    ods_log_assert(zd->domains);

    node = ldns_rbtree_first(zd->domains);
    if (!node || node == LDNS_RBTREE_NULL) {
        fprintf(fd, "; empty zone\n");
        return ODS_STATUS_OK;
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_print(fd, domain);
        node = ldns_rbtree_next(node);
    }
    return ODS_STATUS_OK;
}
