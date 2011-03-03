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
#include "signer/backup.h"
#include "signer/denial.h"
#include "signer/domain.h"
#include "signer/nsec3params.h"
#include "signer/zonedata.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"
#include "util/util.h"

#include <ldns/ldns.h> /* ldns_dname_*(), ldns_rbtree_*() */


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
zonedata_create(void)
{
    zonedata_type* zd = (zonedata_type*) se_malloc(sizeof(zonedata_type));
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
static ldns_rbnode_t* denial2node(denial_type* denial);

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
    int current_nxt = 0;
    int current_bm = 0;

    se_log_assert(zd);
    se_log_assert(fd);

    if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC)) {
        corrupted = 1;
    }

    while (!corrupted) {
        if (backup_read_str(fd, &token)) {
            if (se_strcmp(token, ";DNAME") == 0) {
                current_domain = domain_recover_from_backup(fd, &current_nxt,
                    &current_bm);
                if (!current_domain) {
                    se_log_error("error reading domain from backup file");
                    corrupted = 1;
                } else {
                    parent_rdf = ldns_dname_left_chop(current_domain->name);
                    if (!parent_rdf) {
                        se_log_error("unable to create parent domain name (rdf)");
                        corrupted = 1;
                    } else {
                        current_domain->parent =
                            zonedata_lookup_domain(zd, parent_rdf);
                        ldns_rdf_deep_free(parent_rdf);
                        se_log_assert(current_domain->parent ||
                            current_domain->domain_status == DOMAIN_STATUS_APEX);

                        new_node = domain2node(current_domain);
                        if (!zd->domains) {
                            zd->domains = ldns_rbtree_create(domain_compare);
                        }
                        if (ldns_rbtree_insert(zd->domains, new_node) == NULL) {
                            se_log_error("error adding domain from backup file");
                            se_free((void*)new_node);
                            corrupted = 1;
                        }
                        new_node = NULL;
                    }
                }
            } else if (se_strcmp(token, ";DNAME3") == 0) {
                se_log_assert(current_domain);
                current_domain->denial = denial_recover_from_backup(fd);
                if (!current_domain->denial) {
                    se_log_error("error reading nsec3 domain from backup file");
                    corrupted = 1;
                } else {
                    current_domain->denial->domain = current_domain;
                    new_node = denial2node(current_domain->denial);
                    if (!zd->denial_chain) {
                        zd->denial_chain = ldns_rbtree_create(domain_compare);
                    }

                    if (ldns_rbtree_insert(zd->denial_chain, new_node) == NULL) {
                        se_log_error("error adding nsec3 domain from backup file");
                        se_free((void*)new_node);
                        corrupted = 1;
                    }
                    new_node = NULL;
                }
            } else if (se_strcmp(token, ";NSEC") == 0) {
                status = ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL);
                if (status != LDNS_STATUS_OK) {
                    se_log_error("error reading NSEC RR from backup file");
                    if (rr) {
                        ldns_rr_free(rr);
                    }
                    corrupted = 1;
                } else {
                    se_log_assert(current_domain);
                    current_domain->denial = denial_create(current_domain->name);
                    if (!current_domain->denial) {
                        se_log_error("error reading nsec domain from backup file");
                        corrupted = 1;
                    } else {
                        current_domain->denial->domain = current_domain;
                        current_domain->denial->nxt_changed = current_nxt;
                        current_domain->denial->bitmap_changed = current_bm;
                        new_node = denial2node(current_domain->denial);
                        if (!zd->denial_chain) {
                            zd->denial_chain = ldns_rbtree_create(domain_compare);
                        }
                        if (ldns_rbtree_insert(zd->denial_chain, new_node) == NULL) {
                            se_log_error("error adding nsec domain from backup file");
                            se_free((void*)new_node);
                            corrupted = 1;
                        }
                        new_node = NULL;

                        current_domain->denial->rrset = rrset_create_frm_rr(rr);
                        if (!current_domain->denial->rrset) {
                            se_log_error("error adding NSEC RR from backup file");
                            corrupted = 1;
                        }
                    }
                }

                rr = NULL;
                status = LDNS_STATUS_OK;
            } else if (se_strcmp(token, ";NSEC3") == 0) {
                status = ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL);
                if (status != LDNS_STATUS_OK) {
                    se_log_error("error reading NSEC3 RR from backup file");
                    if (rr) {
                        ldns_rr_free(rr);
                    }
                    corrupted = 1;
                } else {
                    se_log_assert(current_domain);
                    se_log_assert(current_domain->denial);
                    current_domain->denial->rrset = rrset_create_frm_rr(rr);
                    if (!current_domain->denial->rrset) {
                        se_log_error("error adding NSEC3 RR from backup file");
                        corrupted = 1;
                    }
                }
                rr = NULL;
                status = LDNS_STATUS_OK;
            } else if (se_strcmp(token, ODS_SE_FILE_MAGIC) == 0) {
                se_free((void*)token);
                token = NULL;
                break;
            } else {
                corrupted = 1;
            }
            se_free((void*)token);
            token = NULL;
        } else {
            corrupted = 1;
        }
    }

    return corrupted;
}


/**
 * Convert a domain to a tree node.
 *
 */
static ldns_rbnode_t*
domain2node(domain_type* domain)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) se_malloc(sizeof(ldns_rbnode_t));
    if (!node) {
        return NULL;
    }
    node->key = domain->name;
    node->data = domain;
    return node;
}


/**
 * Internal lookup domain function.
 *
 */
static domain_type*
zonedata_domain_search(ldns_rbtree_t* tree, ldns_rdf* name)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;

    if (!tree || !name) {
        return NULL;
    }
    node = ldns_rbtree_search(tree, name);
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
zonedata_lookup_domain(zonedata_type* zd, ldns_rdf* name)
{
    if (!zd || !zd->domains | !name) {
        return NULL;
    }
    return zonedata_domain_search(zd->domains, name);
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
        se_log_error("unable to add domain: no domain");
        return NULL;
    }
    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    if (!zd || !zd->domains) {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to add domain %s: no storage",
            str?str:"(null)");
        free((void*)str);
        return NULL;
    }
    se_log_assert(zd);
    se_log_assert(zd->domains);

    new_node = domain2node(domain);
    if (ldns_rbtree_insert(zd->domains, new_node) == NULL) {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to add domain %s: already present",
            str?str:"(null)");
        se_free((void*)str);
        se_free((void*)new_node);
        return NULL;
    }
    str = ldns_rdf2str(domain->name);
    se_log_debug("+DD %s", str?str:"(null)");
    se_free((void*) str);
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

    se_log_assert(tree);
    se_log_assert(domain);
    se_log_assert(domain->name);

    del_node = ldns_rbtree_search(tree, (const void*)domain->name);
    if (del_node) {
        del_node = ldns_rbtree_delete(tree, (const void*)domain->name);
        del_domain = (domain_type*) del_node->data;
        domain_cleanup(del_domain);
        free((void*)del_node);
        return NULL;
    } else {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to del domain %s: not found",
            str?str:"(null)");
        free((void*)str);
    }
    return domain;
}


/**
 * Delete a domain from the zone data.
 *
 */
domain_type*
zonedata_del_domain(zonedata_type* zd, domain_type* domain)
{
    char* str = NULL;

    if (!domain) {
        se_log_error("unable to delete domain: no domain");
        return NULL;
    }
    se_log_assert(domain);
    se_log_assert(domain->name);

    if (!zd || !zd->domains) {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to delete domain %s: no zonedata",
            str?str:"(null)");
        free((void*)str);
        return domain;
    }
    se_log_assert(zd);
    se_log_assert(zd->domains);

    str = ldns_rdf2str(domain->name);
    se_log_deeebug("-DD %s", str?str:"(null)");
    if (domain->denial && zonedata_del_denial(zd, domain->denial) != NULL) {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to delete domain %s: failed to delete "
            "denial of existence data point", str?str:"(null)");
        free((void*)str);
        return domain;
    }
    domain->denial = NULL;
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

    se_log_assert(dname);
    se_log_assert(apex);
    se_log_assert(nsec3params);

    /**
     * The owner name of the NSEC3 RR is the hash of the original owner
     * name, prepended as a single label to the zone name.
     */
    hashed_label = ldns_nsec3_hash_name(dname, nsec3params->algorithm,
        nsec3params->iterations, nsec3params->salt_len,
        nsec3params->salt_data);
    if (!hashed_label) {
        str = ldns_rdf2str(dname);
        se_log_error("unable to hash dname %s: hash failed",
            str?str:"(null)");
        free((void*)str);
        return NULL;
    }
    hashed_ownername = ldns_dname_cat_clone((const ldns_rdf*) hashed_label,
        (const ldns_rdf*) apex);
    if (!hashed_ownername) {
        str = ldns_rdf2str(dname);
        se_log_error("unable to hash dname %s: concat apex failed",
            str?str:"(null)");
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
int
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
        se_log_error("unable to add denial of existence data point: "
            "no domain");
        return 1;
    }
    se_log_assert(domain);

    if (!zd || !zd->denial_chain) {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to add denial of existence data point "
            "for domain %s: no denial chain", str?str:"(null)");
        free((void*)str);
        return 1;
    }
    se_log_assert(zd);
    se_log_assert(zd->denial_chain);

    if (!apex) {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to add denial of existence data point "
            "for domain %s: apex unknown", str?str:"(null)");
        free((void*)str);
        return 1;
    }
    se_log_assert(apex);

    /* nsec or nsec3 */
    if (nsec3params) {
        owner = dname_hash(domain->name, apex, nsec3params);
        if (!owner) {
            str = ldns_rdf2str(domain->name);
            se_log_error("unable to add denial of existence data point "
                "for domain %s: dname hash failed", str?str:"(null)");
            free((void*)str);
            return 1;
        }
    } else {
        owner = ldns_rdf_clone(domain->name);
    }
    /* lookup */
    if (zonedata_lookup_denial(zd, owner) != NULL) {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to add denial of existence for %s: "
            "data point exists", str?str:"(null)");
        free((void*)str);
        return 1;
    }
    /* create */
    denial = denial_create(owner);
    new_node = denial2node(denial);
    ldns_rdf_deep_free(owner);
    /* insert */
    if (!ldns_rbtree_insert(zd->denial_chain, new_node)) {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to add denial of existence for %s: "
            "insert failed", str?str:"(null)");
        free((void*)str);
        free((void*)new_node);
        denial_cleanup(denial);
        return 1;
    }
    /* denial of existence data point added */
    denial->bitmap_changed = 1;
    denial->nxt_changed = 1;
    prev_node = ldns_rbtree_previous(new_node);
    if (!prev_node || prev_node == LDNS_RBTREE_NULL) {
        prev_node = ldns_rbtree_last(zd->denial_chain);
    }
    se_log_assert(prev_node);
    prev_denial = (denial_type*) prev_node->data;
    se_log_assert(prev_denial);
    prev_denial->nxt_changed = 1;
    domain->denial = denial;
    domain->denial->domain = domain; /* back reference */
    return 0;
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
    int error = 0;
    char* str = NULL;

    se_log_assert(tree);
    se_log_assert(denial);
    se_log_assert(denial->owner);

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
        se_log_assert(prev_node);
        se_log_assert(prev_node->data);
        prev_denial = (denial_type*) prev_node->data;
        prev_denial->nxt_changed = 1;

        /* delete old NSEC RR(s) */
        if (denial->rrset) {
            error = rrset_del_rrs(denial->rrset);
            if (error) {
                se_log_alert("unable to del denial of existence data "
                    "point: failed to wipe out NSEC RRset");
                return denial;
            }
            denial->rrset->initialized = 0; /* hack */
            error = rrset_update(denial->rrset, 0);
            if (error) {
                se_log_alert("unable to del denial of existence data "
                    "point: failed to commit NSEC RRset");
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
        se_log_error("unable to del denial of existence data point %s: "
            "not found", str?str:"(null)");
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
        se_log_error("unable to delete denial of existence data point: "
            "no data point");
        return NULL;
    }
    se_log_assert(denial);

    if (!zd || !zd->denial_chain) {
        str = ldns_rdf2str(denial->owner);
        se_log_error("unable to delete denial of existence data point "
            "%s: no zone data", str?str:"(null)");
        free((void*)str);
        return denial;
    }
    se_log_assert(zd);
    se_log_assert(zd->denial_chain);

    return zonedata_del_denial_fixup(zd->denial_chain, denial);
}


/**
 * Add empty non-terminals to a domain in the zone data.
 *
 */
static int
zonedata_domain_entize(zonedata_type* zd, domain_type* domain, ldns_rdf* apex)
{
    int ent2unsigned_deleg = 0;
    ldns_rdf* parent_rdf = NULL;
    domain_type* parent_domain = NULL;
    char* str = NULL;

    se_log_assert(apex);
    se_log_assert(domain);
    se_log_assert(domain->name);
    se_log_assert(zd);
    se_log_assert(zd->domains);

    if (domain->parent) {
        /* domain already has parent */
        return 0;
    }

    if (domain_lookup_rrset(domain, LDNS_RR_TYPE_NS) &&
        !domain_lookup_rrset(domain, LDNS_RR_TYPE_DS)) {
        /* empty non-terminal to unsigned delegation */
        ent2unsigned_deleg = 1;
    }

    while (domain && ldns_dname_is_subdomain(domain->name, apex) &&
           ldns_dname_compare(domain->name, apex) != 0) {

        str = ldns_rdf2str(domain->name);

        /**
         * RFC5155:
         * 4. If the difference in number of labels between the apex and
         *    the original owner name is greater than 1, additional NSEC3
         *    RRs need to be added for every empty non-terminal between
         *     the apex and the original owner name.
         */
        parent_rdf = ldns_dname_left_chop(domain->name);
        if (!parent_rdf) {
            se_log_error("entize: unable to create parent rdf for %s", str);
            se_free((void*)str);
            return 1;
        }

        parent_domain = zonedata_lookup_domain(zd, parent_rdf);
        if (!parent_domain) {
            se_log_deeebug("create parent domain for %s", str);
            parent_domain = domain_create(parent_rdf);
            ldns_rdf_deep_free(parent_rdf);
            se_log_deeebug("add parent domain to %s", str);
            parent_domain = zonedata_add_domain(zd, parent_domain);
            if (!parent_domain) {
                se_log_error("unable to add parent domain to %s", str);
                se_free((void*)str);
                return 1;
            }
            parent_domain->domain_status =
                (ent2unsigned_deleg?DOMAIN_STATUS_ENT_NS:
                                    DOMAIN_STATUS_ENT_AUTH);
            parent_domain->subdomain_count = 1;
            if (!ent2unsigned_deleg) {
                parent_domain->subdomain_auth = 1;
            }
            parent_domain->internal_serial = domain->internal_serial;
            domain->parent = parent_domain;
            /* continue with the parent domain */
            domain = parent_domain;
        } else {
            se_log_deeebug("entize domain %s", str);
            ldns_rdf_deep_free(parent_rdf);
            parent_domain->internal_serial = domain->internal_serial;
            parent_domain->subdomain_count += 1;
            if (!ent2unsigned_deleg) {
                parent_domain->subdomain_auth += 1;
            }
            domain->parent = parent_domain;
            if (domain_count_rrset(parent_domain) <= 0 &&
                parent_domain->domain_status != DOMAIN_STATUS_ENT_AUTH) {
                parent_domain->domain_status =
                    (ent2unsigned_deleg?DOMAIN_STATUS_ENT_NS:
                                        DOMAIN_STATUS_ENT_AUTH);
            }
            /* done */
            domain = NULL;
        }
        se_free((void*)str);
    }
    return 0;
}


/**
 * Revise the empty non-terminals domain status.
 *
 */
static void
zonedata_domain_entize_revised(domain_type* domain, int status)
{
    domain_type* parent = NULL;
    if (!domain) {
        return;
    }
    parent = domain->parent;
    while (parent) {
        if (parent->domain_status == DOMAIN_STATUS_ENT_AUTH ||
            parent->domain_status == DOMAIN_STATUS_ENT_GLUE ||
            parent->domain_status == DOMAIN_STATUS_ENT_NS) {
            parent->domain_status = status;
        } else {
           break;
        }
        parent = parent->parent;
    }
    return;
}


/**
 * Add empty non-terminals to zone data.
 *
 */
int
zonedata_entize(zonedata_type* zd, ldns_rdf* apex)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    int prev_status = DOMAIN_STATUS_NONE;

    se_log_assert(apex);
    se_log_assert(zd);
    se_log_assert(zd->domains);

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (zonedata_domain_entize(zd, domain, apex) != 0) {
            se_log_error("error adding enmpty non-terminals to domain");
            return 1;
        }
        /* domain has parent now, check for glue */
        prev_status = domain->domain_status;
        domain_update_status(domain);
        if (domain->domain_status == DOMAIN_STATUS_OCCLUDED &&
            prev_status != DOMAIN_STATUS_OCCLUDED) {
            zonedata_domain_entize_revised(domain, DOMAIN_STATUS_ENT_GLUE);
        }
        node = ldns_rbtree_next(node);
    }
    return 0;
}

/**
 * Add NSEC records to zonedata.
 *
 */
int
zonedata_nsecify(zonedata_type* zd, ldns_rr_class klass, stats_type* stats)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* nxt_node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    domain_type* apex = NULL;
    denial_type* denial = NULL;
    denial_type* nxt = NULL;
    size_t nsec_added = 0;
    int error = 0;

    if (!zd || !zd->domains) {
        return 0;
    }
    se_log_assert(zd);
    se_log_assert(zd->domains);

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain->domain_status == DOMAIN_STATUS_APEX) {
            apex = domain;
        }
        /* don't do glue-only or empty domains */
        if (domain->domain_status == DOMAIN_STATUS_NONE ||
            domain->domain_status == DOMAIN_STATUS_OCCLUDED ||
            domain_count_rrset(domain) <= 0) {
            if (domain->denial) {
                if (zonedata_del_denial(zd, domain->denial) != NULL) {
                    se_log_warning("unable to nsecify: failed to "
                        "delete denial of existence data point");
                    return 1;
                }
                domain->denial = NULL;
            }
            node = ldns_rbtree_next(node);
            continue;
        }
        if (!apex) {
            se_log_alert("unable to nsecify: apex unknown");
            return 1;
        }

        /* add the denial of existence */
        if (!domain->denial) {
            error = zonedata_add_denial(zd, domain, apex->name, NULL);
            if (error) {
                se_log_alert("unable to nsecify: failed to add denial "
                    "of existence for domain");
                return error;
            }
            nsec_added++;
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

        error = denial_nsecify(denial, nxt, zd->default_ttl, klass);
        if (error) {
            se_log_error("unable to nsecify: failed to add NSEC record");
            return error;
        }
        node = ldns_rbtree_next(node);
    }
    if (stats) {
        stats->nsec_count = nsec_added;
    }
    return 0;
}


/**
 * Add NSEC3 records to zonedata.
 *
 */
int
zonedata_nsecify3(zonedata_type* zd, ldns_rr_class klass,
    nsec3params_type* nsec3params, stats_type* stats)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* nxt_node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    domain_type* apex = NULL;
    denial_type* denial = NULL;
    denial_type* nxt = NULL;
    char* str = NULL;
    size_t nsec3_added = 0;
    int error = 0;

    if (!zd || !zd->domains) {
        return 0;
    }
    se_log_assert(zd);
    se_log_assert(zd->domains);

    if (!nsec3params) {
        se_log_error("unable to nsecify3: no nsec3 paramaters");
        return 1;
    }
    se_log_assert(nsec3params);

    if (!zd->denial_chain) {
        se_log_debug("create new nsec3 domain tree");
        zd->denial_chain = ldns_rbtree_create(domain_compare);
    }

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain->domain_status == DOMAIN_STATUS_APEX) {
            apex = domain;
        }

        /* don't do glue-only domains */
        if (domain->domain_status == DOMAIN_STATUS_NONE ||
            domain->domain_status == DOMAIN_STATUS_OCCLUDED ||
            domain->domain_status == DOMAIN_STATUS_ENT_GLUE) {
            str = ldns_rdf2str(domain->name);
            se_log_debug("nsecify3: skip glue domain %s", str?str:"(null)");
            se_free((void*) str);
            if (domain->denial) {
                if (zonedata_del_denial(zd, domain->denial) != NULL) {
                    se_log_error("unable to nsecify3: failed to "
                        "delete denial of existence data point");
                    return 1;
                }
                domain->denial = NULL;
            }
            node = ldns_rbtree_next(node);
            continue;
        }
        /* Opt-Out? */
        if (nsec3params->flags) {
            /* If Opt-Out is being used, owner names of unsigned delegations
               MAY be excluded. */
            if (domain->domain_status == DOMAIN_STATUS_NS ||
                domain->domain_status == DOMAIN_STATUS_ENT_NS) {
                str = ldns_rdf2str(domain->name);
                se_log_debug("opt-out %s: %s", str?str:"(null)",
                    domain->domain_status == DOMAIN_STATUS_NS ?
                    "unsigned delegation" : "empty non-terminal (to unsigned "
                    "delegation)");
                se_free((void*) str);
                if (domain->denial) {
                    if (zonedata_del_denial(zd, domain->denial) != NULL) {
                        se_log_error("unable to nsecify3: failed to "
                            "delete denial of existence data point");
                        return 1;
                    }
                    domain->denial = NULL;
                }
                node = ldns_rbtree_next(node);
                continue;
            }
        }

        if (!apex) {
            se_log_alert("apex undefined!, aborting nsecify3");
            return 1;
        }

        /* add the denial of existence */
        if (!domain->denial) {
            error = zonedata_add_denial(zd, domain, apex->name, nsec3params);
            if (error) {
                str = ldns_rdf2str(domain->name);
                se_log_alert("unable to nsecify3: failed to add denial "
                    "of existence for domain %s", str?str:"(null)");
                free((void*) str);
                return error;
            }
            nsec3_added++;
        }

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
         * wildcard_name = *.domain->name;
         * hashed_ownername = ldns_nsec3_hash_name(domain->name,
               nsec3params->algorithm, nsec3params->iterations,
               nsec3params->salt_len, nsec3params->salt);
         * domain->nsec3_wildcard = denial_create(hashed_ownername);
        **/

        node = ldns_rbtree_next(node);
    }

    /* Now we have the complete NSEC3 tree */

    /**
     * In each NSEC3 RR, insert the next hashed owner name by using the
     * value of the next NSEC3 RR in hash order.  The next hashed owner
     * name of the last NSEC3 RR in the zone contains the value of the
     * hashed owner name of the first NSEC3 RR in the hash order.
    **/
    node = ldns_rbtree_first(zd->denial_chain);
    while (node && node != LDNS_RBTREE_NULL) {
        denial = (denial_type*) node->data;
        nxt_node = ldns_rbtree_next(node);
        if (!nxt_node || nxt_node == LDNS_RBTREE_NULL) {
             nxt_node = ldns_rbtree_first(zd->denial_chain);
        }
        nxt = (denial_type*) nxt_node->data;

        error = denial_nsecify3(denial, nxt, zd->default_ttl, klass,
            nsec3params);
        if (error) {
            se_log_error("unable to nsecify3: failed to add NSEC3 "
                "record");
            return error;
        }
        node = ldns_rbtree_next(node);
    }
    if (stats) {
        stats->nsec_count = nsec3_added;
    }
    return 0;
}


static int
se_max(uint32_t a, uint32_t b)
{
    return (a>b?a:b);
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

    se_log_assert(zd);
    se_log_assert(sc);

    prev = zd->internal_serial;
    se_log_debug("update serial: inbound=%u internal=%u outbound=%u now=%u",
        zd->inbound_serial, zd->internal_serial, zd->outbound_serial,
        (uint32_t) time_now());

    if (!sc->soa_serial) {
        se_log_error("no serial type given");
        return 1;
    }

    if (se_strcmp(sc->soa_serial, "unixtime") == 0) {
        soa = se_max(zd->inbound_serial, (uint32_t) time_now());
        if (!DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
        update = soa - prev;
    } else if (strncmp(sc->soa_serial, "counter", 7) == 0) {
        soa = se_max(zd->inbound_serial, prev);
        if (!zd->initialized) {
            zd->internal_serial = soa + 1;
            zd->initialized = 1;
            return 0;
        }
        if (!DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
        update = soa - prev;
    } else if (strncmp(sc->soa_serial, "datecounter", 11) == 0) {
        soa = (uint32_t) time_datestamp(0, "%Y%m%d", NULL) * 100;
        soa = se_max(zd->inbound_serial, soa);
        if (!DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
        update = soa - prev;
    } else if (strncmp(sc->soa_serial, "keep", 4) == 0) {
        soa = zd->inbound_serial;
        if (zd->initialized && !DNS_SERIAL_GT(soa, prev)) {
            se_log_error("cannot keep SOA SERIAL from input zone "
                " (%u): output SOA SERIAL is %u", soa, prev);
            return 1;
        }
        prev = soa;
        update = 0;
    } else {
        se_log_error("unknown serial type %s", sc->soa_serial);
        return 1;
    }

    if (!zd->initialized) {
        zd->initialized = 1;
    }

    /* serial is stored in 32 bits */
    if (update > 0x7FFFFFFF) {
        update = 0x7FFFFFFF;
    }
    zd->internal_serial = (prev + update); /* automatically does % 2^32 */
    se_log_debug("update serial: previous=%u update=%u new=%u",
        prev, update, zd->internal_serial);
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

    se_log_assert(sc);
    se_log_assert(zd);
    se_log_assert(zd->domains);

    if (!DNS_SERIAL_GT(zd->internal_serial, zd->outbound_serial)) {
        error = zonedata_update_serial(zd, sc);
    }
    if (error || !zd->internal_serial) {
        se_log_error("unable to sign zone data: failed to update serial");
        return 1;
    }

    now = time_now();
    ctx = hsm_create_context();
    if (!ctx) {
        se_log_error("error creating libhsm context");
        return 2;
    }

    se_log_debug("rrsig timers: offset=%u jitter=%u validity=%u",
        duration2time(sc->sig_inception_offset),
        duration2time(sc->sig_jitter),
        duration2time(sc->sig_validity_denial));

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain_sign(ctx, domain, owner, sc, now, zd->internal_serial,
            stats) != 0) {
            se_log_error("unable to sign zone data: failed to sign domain");
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

    se_log_assert(apex);
    se_log_assert(domain);
    se_log_assert(domain->name);
    se_log_assert(zd);
    se_log_assert(zd->domains);

    if (ldns_dname_compare(domain->name, apex) == 0) {
        return 0;
    }

    if (domain_examine_valid_zonecut(domain) != 0) {
        str_name = ldns_rdf2str(domain->name);
        se_log_error("occluded (non-glue non-DS) data at %s NS", str_name);
        se_free((void*)str_name);
        return 1;
    }

    parent_rdf = ldns_dname_left_chop(domain->name);
    while (parent_rdf && ldns_dname_is_subdomain(parent_rdf, apex) &&
           ldns_dname_compare(parent_rdf, apex) != 0) {

        parent_domain = zonedata_lookup_domain(zd, parent_rdf);
        next_rdf = ldns_dname_left_chop(parent_rdf);
        ldns_rdf_deep_free(parent_rdf);

        if (parent_domain) {
            /* check for DNAME or NS */
            if (domain_examine_data_exists(parent_domain, LDNS_RR_TYPE_DNAME,
                0) == 0 && domain_examine_data_exists(domain, 0, 0) == 0) {
                /* data below DNAME */
                str_name = ldns_rdf2str(domain->name);
                str_parent = ldns_rdf2str(parent_domain->name);
                se_log_error("occluded data at %s (below %s DNAME)", str_name,
                    str_parent);
                se_free((void*)str_name);
                se_free((void*)str_parent);
                return 1;
            } else if (domain_examine_data_exists(parent_domain,
                LDNS_RR_TYPE_NS, 0) == 0 &&
                domain_examine_data_exists(domain, 0, 1) == 0) {
                /* data (non-glue) below NS */
                str_name = ldns_rdf2str(domain->name);
                str_parent = ldns_rdf2str(parent_domain->name);
                se_log_error("occluded (non-glue) data at %s (below %s NS)",
                    str_name, str_parent);
                se_free((void*)str_name);
                se_free((void*)str_parent);
                return 1;
            } else if (domain_examine_data_exists(parent_domain,
                LDNS_RR_TYPE_NS, 0) == 0 &&
                domain_examine_data_exists(domain, 0, 0) == 0 &&
                domain_examine_ns_rdata(parent_domain, domain->name) != 0) {
                /* glue data not signalled by NS RDATA */
                str_name = ldns_rdf2str(domain->name);
                str_parent = ldns_rdf2str(parent_domain->name);
                se_log_error("occluded data at %s (below %s NS)",
                    str_name, str_parent);
                se_free((void*)str_name);
                se_free((void*)str_parent);
                return 1;
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
 * Examine zone data.
 *
 */
int
zonedata_examine(zonedata_type* zd, ldns_rdf* apex, int is_file)
{
    int error = 0;
    int result = 0;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);

    if (zd->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zd->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        error =
        /* Thou shall not have other data next to CNAME */
        domain_examine_rrset_is_alone(domain, LDNS_RR_TYPE_CNAME) ||
        /* Thou shall have at most one CNAME per name */
        domain_examine_rrset_is_singleton(domain, LDNS_RR_TYPE_CNAME) ||
        /* Thou shall have at most one DNAME per name */
        domain_examine_rrset_is_singleton(domain, LDNS_RR_TYPE_DNAME);
        if (error) {
            result = error;
        }

        if (is_file) {
            error =
            /* Thou shall not have occluded data in your zone file */
            zonedata_examine_domain_is_occluded(zd, domain, apex);
            if (error) {
                result = error;
            }
        }

        node = ldns_rbtree_next(node);
    }

    return result;
}


/**
 * Update zone data with pending changes.
 *
 */
int
zonedata_update(zonedata_type* zd, signconf_type* sc)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    domain_type* parent = NULL;
    int error = 0;

    se_log_assert(sc);
    se_log_assert(zd);
    se_log_assert(zd->domains);

    error = zonedata_update_serial(zd, sc);
    if (error || !zd->internal_serial) {
        se_log_error("unable to update zonedata: failed to update serial");
        zonedata_cancel_update(zd);
        return 1;
    }

    if (zd->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zd->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        error = domain_update(domain, zd->internal_serial);
        if (error != 0) {
            if (error == 1) {
                se_log_crit("unable to update zonedata to serial %u: rr "
                    "compare function failed", zd->internal_serial);
                /* If this happens, the zone is partially updated. */
            } else {
                se_log_error("unable to update zonedata to serial %u: "
                    "serial too small", zd->internal_serial);
                zonedata_cancel_update(zd);
                return 1;
            }
            return 1;
        }
        node = ldns_rbtree_next(node);

        /* delete memory of domain if no RRsets exists */
        /* if this domain is now an empty non-terminal, don't delete */

        if (domain_count_rrset(domain) <= 0 &&
            (domain->domain_status != DOMAIN_STATUS_ENT_AUTH &&
             domain->domain_status != DOMAIN_STATUS_ENT_NS &&
             domain->domain_status != DOMAIN_STATUS_ENT_GLUE)) {

            parent = domain->parent;
            if (domain->subdomain_count <= 0) {
                se_log_deeebug("obsoleted domain: #rrset=%i, status=%i",
                    domain_count_rrset(domain), domain->domain_status);
                domain = zonedata_del_domain(zd, domain);
            }
            if (domain) {
                se_log_error("failed to delete obsoleted domain");
            }
            while (parent && domain_count_rrset(parent) <= 0) {
                domain = parent;
                parent = domain->parent;
                if (domain->subdomain_count <= 0) {
                    domain = zonedata_del_domain(zd, domain);
                    if (domain) {
                        se_log_error("failed to delete obsoleted domain");
                    }
                }
            }
        }
    }
    return 0;
}


/**
 * Cancel update.
 *
 */
void
zonedata_cancel_update(zonedata_type* zd)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);

    if (zd->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zd->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_cancel_update(domain);
        node = ldns_rbtree_next(node);
    }
    return;
}


/**
 * Add RR to the zone data.
 *
 */
int
zonedata_add_rr(zonedata_type* zd, ldns_rr* rr, int at_apex)
{
    domain_type* domain = NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);
    se_log_assert(rr);

    domain = zonedata_lookup_domain(zd, ldns_rr_owner(rr));
    if (domain) {
        return domain_add_rr(domain, rr);
    }
    /* no domain with this name yet */
    domain = domain_create(ldns_rr_owner(rr));
    domain = zonedata_add_domain(zd, domain);
    if (!domain) {
        se_log_error("unable to add RR to zonedata: failed to add domain");
        return 1;
    }
    if (at_apex) {
        domain->domain_status = DOMAIN_STATUS_APEX;
    }
    return domain_add_rr(domain, rr);
}


/**
 * Recover RR from backup.
 *
 */
int
zonedata_recover_rr_from_backup(zonedata_type* zd, ldns_rr* rr)
{
    domain_type* domain = NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);
    se_log_assert(rr);

    domain = zonedata_lookup_domain(zd, ldns_rr_owner(rr));
    if (domain) {
        return domain_recover_rr_from_backup(domain, rr);
    }

    se_log_error("unable to recover RR to zonedata: domain does not exist");
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
    denial_type* denial = NULL;
    ldns_rr_type type_covered;

    se_log_assert(zd);
    se_log_assert(zd->domains);
    se_log_assert(rrsig);

    type_covered = ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rrsig));
    if (type_covered == LDNS_RR_TYPE_NSEC3 ||
        type_covered == LDNS_RR_TYPE_NSEC) {
        denial = zonedata_lookup_denial(zd, ldns_rr_owner(rrsig));
        if (denial) {
            return denial_recover_rrsig_from_backup(denial, rrsig, type_covered,
                locator, flags);
        }
    } else {
        domain = zonedata_lookup_domain(zd, ldns_rr_owner(rrsig));
        if (domain) {
            return domain_recover_rrsig_from_backup(domain, rrsig, type_covered,
                locator, flags);
        }
    }
    se_log_error("unable to recover RRSIG to zonedata: domain does not exist");
    return 1;
}


/**
 * Delete RR from the zone data.
 *
 */
int
zonedata_del_rr(zonedata_type* zd, ldns_rr* rr)
{
    domain_type* domain = NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);
    se_log_assert(rr);

    domain = zonedata_lookup_domain(zd, ldns_rr_owner(rr));
    if (domain) {
        return domain_del_rr(domain, rr);
    }
    /* no domain with this name yet */
    se_log_warning("unable to delete RR from zonedata: no such domain");
    return 0;
}


/**
 * Delete all current RRs from the zone data.
 *
 */
int
zonedata_del_rrs(zonedata_type* zd)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);

    if (zd->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zd->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain_del_rrs(domain) != 0) {
            return 1;
        }
        node = ldns_rbtree_next(node);
    }
    return 0;
}


/**
 * Clean up domains in zone data.
 *
 */
void
zonedata_cleanup_domains(ldns_rbtree_t* domain_tree)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    if (domain_tree && domain_tree->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain_tree);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_cleanup(domain);
        node = ldns_rbtree_next(node);
    }
    if (domain_tree && domain_tree->root != LDNS_RBTREE_NULL) {
        se_rbnode_free(domain_tree->root);
    }
    if (domain_tree) {
        ldns_rbtree_free(domain_tree);
    }
    return;
}


/**
 * Clean up denial of existence in zone data.
 *
 */
void
zonedata_cleanup_denials(ldns_rbtree_t* denial_tree)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    denial_type* denial = NULL;

    if (denial_tree && denial_tree->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(denial_tree);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        denial = (denial_type*) node->data;
        denial_cleanup(denial);
        node = ldns_rbtree_next(node);
    }
    if (denial_tree && denial_tree->root != LDNS_RBTREE_NULL) {
        se_rbnode_free(denial_tree->root);
    }
    if (denial_tree) {
        ldns_rbtree_free(denial_tree);
    }
    return;
}


/**
 * Clean up zone data.
 *
 */
void
zonedata_cleanup(zonedata_type* zonedata)
{
    /* destroy domains */
    if (zonedata) {
        if (zonedata->domains) {
            zonedata_cleanup_domains(zonedata->domains);
            zonedata->domains = NULL;
        }
        if (zonedata->denial_chain) {
            zonedata_cleanup_denials(zonedata->denial_chain);
            zonedata->denial_chain = NULL;
        }
        se_free((void*) zonedata);
    } else {
        se_log_warning("cleanup empty zone data");
    }
    return;
}


/**
 * Print zone data.
 *
 */
void
zonedata_print(FILE* fd, zonedata_type* zd)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    se_log_assert(fd);
    se_log_assert(zd);
    se_log_assert(zd->domains);

    node = ldns_rbtree_first(zd->domains);
    if (!node || node == LDNS_RBTREE_NULL) {
        fprintf(fd, "; zone empty\n");
        return;
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_print(fd, domain);
        node = ldns_rbtree_next(node);
    }

    return;
}


/**
 * Print NSEC(3)s in zone data.
 *
 */
void
zonedata_print_nsec(FILE* fd, zonedata_type* zd)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    se_log_assert(fd);
    se_log_assert(zd);
    se_log_assert(zd->domains);

    node = ldns_rbtree_first(zd->domains);
    if (!node || node == LDNS_RBTREE_NULL) {
        fprintf(fd, "; zone empty\n");
        return;
    }

    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_print_nsec(fd, domain);
        node = ldns_rbtree_next(node);
    }
    return;
}


/**
 * Print RRSIGs zone data.
 *
 */
void
zonedata_print_rrsig(FILE* fd, zonedata_type* zd)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    se_log_assert(fd);
    se_log_assert(zd);
    se_log_assert(zd->domains);

    node = ldns_rbtree_first(zd->domains);
    if (!node || node == LDNS_RBTREE_NULL) {
        fprintf(fd, "; zone empty\n");
        return;
    }

    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_print_rrsig(fd, domain);
        node = ldns_rbtree_next(node);
    }
    return;
}
