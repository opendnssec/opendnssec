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
 * Zone.
 *
 */

#include "adapter/adapi.h"
#include "adapter/adapter.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "shared/allocator.h"
#include "shared/backup.h"
#include "shared/file.h"
#include "shared/hsm.h"
#include "shared/locks.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/journal.h"
#include "signer/nsec3params.h"
#include "signer/signconf.h"
#include "signer/zone.h"

#include <ldns/ldns.h>

static const char* zone_str = "zone";


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
 * Create a new zone.
 *
 */
zone_type*
zone_create(char* name, ldns_rr_class klass)
{
    allocator_type* allocator = NULL;
    zone_type* zone = NULL;

    if (!name || !klass) {
        ods_log_error("[%s] unable to create zone: no name or class",
            zone_str);
        return NULL;
    }
    allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to create zone %s: create allocator "
            "failed", zone_str, name);
        return NULL;
    }
    ods_log_assert(allocator);

    zone = (zone_type*) allocator_alloc(allocator, sizeof(zone_type));
    if (!zone) {
        ods_log_error("[%s] unable to create zone %s: allocator failed",
            zone_str, name);
        allocator_cleanup(allocator);
        return NULL;
    }
    ods_log_assert(zone);

    zone->allocator = allocator;
    /* [start] PS 9218653: Drop trailing dot in domain name */
    if (strlen(name) > 1 && name[strlen(name)-1] == '.') {
        name[strlen(name)-1] = '\0';
    }
    /* [end] PS 9218653 */

    zone->origin = ldns_dname_new_frm_str(name);
    ldns_dname2canonical(zone->origin);
    zone->klass = klass;
    zone->default_ttl = DEFAULT_TTL;

    zone->notify_ns = NULL;
    zone->fetch = 0;

    zone->name = allocator_strdup(allocator, name);
    zone->policy_name = NULL;
    zone->signconf_filename = NULL;
    zone->just_added = 0;
    zone->just_updated = 0;
    zone->tobe_removed = 0;

    zone->adinbound = NULL;
    zone->adoutbound = NULL;

    zone->signconf = signconf_create();
    if (!zone->signconf) {
        ods_log_error("[%s] unable to create zone %s: create signconf "
            "failed", zone_str, name);
        zone_cleanup(zone);
        return NULL;
    }
    zone->nsec3params = NULL;

    zone->journal_entry = entry_create(zone->allocator);
    if (!zone->journal_entry) {
        ods_log_error("[%s] unable to create zone %s: create journal entry "
            "failed", zone_str, name);
        zone_cleanup(zone);
        return NULL;
    }

    /** zone data */
    zone_init_domains(zone);
    if (!zone->domains) {
        ods_log_error("[%s] unable to create zone %s: initialize domains "
            "failed", zone_str, name);
        zone_cleanup(zone);
        return NULL;
    }

    zone_init_denials(zone);
    if (!zone->denials) {
        ods_log_error("[%s] unable to create zone %s: initialize denial of "
            "existence failed", zone_str, name);
        zone_cleanup(zone);
        return NULL;
    }

    /* serial management */
    zone->inbound_serial = 0;
    zone->internal_serial = 0;
    zone->outbound_serial = 0;
    zone->initialized = 0;

    /* worker variables */
    zone->task = NULL;
    zone->processed = 0;

    /** statistics */
    zone->stats = stats_create();

    lock_basic_init(&zone->zone_lock);
    return zone;
}


/**
 * Initialize domains.
 *
 */
void
zone_init_domains(zone_type* zone)
{
    if (zone) {
        zone->domains = ldns_rbtree_create(domain_compare);
    }
    return;
}


/**
 * Initialize denial of existence chain.
 *
 */
void
zone_init_denials(zone_type* zone)
{
    if (zone) {
        zone->denials = ldns_rbtree_create(domain_compare);
    }
    return;
}


/**
 * Internal lookup domain function.
 *
 */
static domain_type*
zone_domain_search(ldns_rbtree_t* tree, ldns_rdf* dname)
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
zone_lookup_domain(zone_type* zone, ldns_rdf* dname)
{
    if (!zone) return NULL;
    return zone_domain_search(zone->domains, dname);
}


/**
 * Add a domain to zone.
 *
 */
domain_type*
zone_add_domain(zone_type* zone, domain_type* domain)
{
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;

    if (!domain) {
        ods_log_error("[%s] unable to add domain: no domain", zone_str);
        return NULL;
    }
    ods_log_assert(domain);

    if (!zone || !zone->domains) {
        log_rdf(domain->dname, "unable to add domain: no storage", 1);
        return NULL;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->domains);

    new_node = domain2node(domain);
    if (ldns_rbtree_insert(zone->domains, new_node) == NULL) {
        log_rdf(domain->dname, "unable to add domain: already present", 1);
        free((void*)new_node);
        return NULL;
    }
    domain->zone = (void*) zone;
    log_rdf(domain->dname, "+DD", 6);
    return domain;
}


/**
 * Internal delete domain function.
 *
 */
static domain_type*
zone_del_domain_fixup(ldns_rbtree_t* tree, domain_type* domain)
{
    domain_type* del_domain = NULL;
    ldns_rbnode_t* del_node = LDNS_RBTREE_NULL;

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
        log_rdf(domain->dname, "unable to del domain: not found", 1);
    }
    return domain;
}


/**
 * Delete domain from zone.
 *
 */
domain_type*
zone_del_domain(zone_type* zone, domain_type* domain)
{
    if (!domain) {
        ods_log_error("[%s] unable to delete domain: no domain", zone_str);
        return NULL;
    }
    ods_log_assert(domain);
    ods_log_assert(domain->dname);

    if (!zone || !zone->domains) {
        log_rdf(domain->dname, "unable to delete domain: no zonedata", 1);
        return domain;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->domains);

    if (domain->denial &&
        zone_del_denial(zone, domain->denial) != NULL) {
        log_rdf(domain->dname, "unable to delete domain: failed to delete "
            "denial of existence data point", 1);
        return domain;
    }
    log_rdf(domain->dname, "-DD", 6);
    return zone_del_domain_fixup(zone->domains, domain);
}


/**
 * Internal function to lookup denial of existence data point.
 *
 */
static denial_type*
zone_denial_search(ldns_rbtree_t* tree, ldns_rdf* dname)
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
zone_lookup_denial(zone_type* zone, ldns_rdf* dname)
{
    if (!zone) return NULL;
    return zone_denial_search(zone->denials, dname);
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
        log_rdf(dname, "unable to hash dname: hash failed", 1);
        return NULL;
    }
    hashed_ownername = ldns_dname_cat_clone((const ldns_rdf*) hashed_label,
        (const ldns_rdf*) apex);
    if (!hashed_ownername) {
        log_rdf(dname, "unable to hash dname: concat apex failed", 1);
        return NULL;
    }
    ldns_rdf_deep_free(hashed_label);
    return hashed_ownername;
}


/**
 * Add denial of existence data point to zone.
 *
 */
ods_status
zone_add_denial(zone_type* zone, domain_type* domain)
{
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* prev_node = LDNS_RBTREE_NULL;
    ldns_rdf* owner = NULL;
    denial_type* denial = NULL;
    denial_type* prev_denial = NULL;

    if (!domain) {
        ods_log_error("[%s] unable to add denial of existence data point: "
            "no domain", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(domain);

    if (!zone || !zone->denials) {
        log_rdf(domain->dname, "unable to add denial of existence data "
            "point for domain: no denial chain", 1);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->denials);

    if (!zone->origin) {
        log_rdf(domain->dname, "unable to add denial of existence data "
            "point for domain: apex unknown", 1);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->origin);

    /* nsec or nsec3 */
    if (zone->nsec3params) {
        owner = dname_hash(domain->dname, zone->origin, zone->nsec3params);
        if (!owner) {
            log_rdf(domain->dname, "unable to add denial of existence data "
                "point for domain: dname hash failed", 1);
            return ODS_STATUS_ERR;
        }
    } else {
        owner = ldns_rdf_clone(domain->dname);
    }
    /* lookup */
    if (zone_lookup_denial(zone, owner) != NULL) {
        log_rdf(domain->dname, "unable to add denial of existence for "
            "domain: data point exists", 1);
        return ODS_STATUS_CONFLICT_ERR;
    }
    /* create */
    denial = denial_create(zone->allocator, owner, (void*) zone);
    new_node = denial2node(denial);
    ldns_rdf_deep_free(owner);
    /* insert */
    if (!ldns_rbtree_insert(zone->denials, new_node)) {
        log_rdf(domain->dname, "unable to add denial of existence for "
            "domain: insert failed", 1);
        free((void*)new_node);
        denial_cleanup(denial);
        return ODS_STATUS_ERR;
    }
    /* denial of existence data point added */
    denial->zone = (void*) zone;
    denial->bitmap_changed = 1;
    denial->nxt_changed = 1;
    prev_node = ldns_rbtree_previous(new_node);
    if (!prev_node || prev_node == LDNS_RBTREE_NULL) {
        prev_node = ldns_rbtree_last(zone->denials);
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
zone_del_denial_fixup(ldns_rbtree_t* tree, denial_type* denial)
{
    denial_type* del_denial = NULL;
    denial_type* prev_denial = NULL;
    ldns_rbnode_t* prev_node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* del_node = LDNS_RBTREE_NULL;
    ods_status status = ODS_STATUS_OK;

    ods_log_assert(tree);
    ods_log_assert(denial);
    ods_log_assert(denial->owner);

    del_node = ldns_rbtree_search(tree, (const void*)denial->owner);
    if (del_node) {
        /**
         * [CALC] if domain removed, mark prev domain NSEC(3) nxt changed.
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
                    "point: failed to wipe out NSEC RRset", zone_str);
                return denial;
            }
            status = rrset_commit(denial->rrset);
            if (status != ODS_STATUS_OK) {
                ods_log_alert("[%s] unable to del denial of existence data "
                    "point: failed to commit NSEC RRset", zone_str);
                return denial;
            }
        }

        del_node = ldns_rbtree_delete(tree, (const void*)denial->owner);
        del_denial = (denial_type*) del_node->data;
        denial_cleanup(del_denial);
        free((void*)del_node);
        return NULL;
    } else {
        log_rdf(denial->owner, "unable to del denial of existence data "
            "point: not found", 1);
    }
    return denial;
}


/**
 * Delete denial of existence data point from zone.
 *
 */
denial_type*
zone_del_denial(zone_type* zone, denial_type* denial)
{
    if (!denial) {
        ods_log_error("[%s] unable to delete denial of existence data "
            "point: no data point", zone_str);
        return NULL;
    }
    ods_log_assert(denial);

    if (!zone || !zone->denials) {
        log_rdf(denial->owner, "unable to delete denial of existence data "
            "point: no zone data", 1);
        return denial;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->denials);

    return zone_del_denial_fixup(zone->denials, denial);
}


/**
 * Add RR.
 *
 */
ods_status
zone_add_rr(zone_type* zone, ldns_rr* rr, int do_stats)
{
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;
    ldns_rdf* soa_min = NULL;
    ldns_rr_type type = LDNS_RR_TYPE_FIRST;
    uint32_t rrset_ttl = 0;
    uint32_t tmp = 0;

    if (!rr) {
        ods_log_error("[%s] unable to add RR: no RR", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rr);

    if (!zone || !zone->domains) {
        ods_log_error("[%s] unable to add RR: no storage", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->domains);

    if (!zone->signconf) {
        ods_log_error("[%s] unable to add RR: no signconf", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf);

    /* in-zone? */
    if (ldns_dname_compare(zone->origin, ldns_rr_owner(rr)) != 0 &&
        !ldns_dname_is_subdomain(ldns_rr_owner(rr), zone->origin)) {
        ods_log_warning("[%s] zone %s contains out-of-zone data, skipping",
            zone_str, zone->name?zone->name:"(null)");
        /* ok, just filter */
        return ODS_STATUS_OK;
    }

    /* set defaults */
    rrset_ttl = zone->default_ttl;
    type = ldns_rr_get_type(rr);

    /* type specific configuration */
    if (type == LDNS_RR_TYPE_DNSKEY && zone->signconf->dnskey_ttl) {
        rrset_ttl = (uint32_t) duration2time(zone->signconf->dnskey_ttl);
        ods_log_verbose("[%s] zone %s set DNSKEY TTL to %u",
            zone_str, zone->name?zone->name:"(null)", rrset_ttl);
        ldns_rr_set_ttl(rr, rrset_ttl);
    }
    if (type == LDNS_RR_TYPE_SOA) {
        if (zone->signconf->soa_ttl) {
            rrset_ttl = (uint32_t) duration2time(zone->signconf->soa_ttl);
            ods_log_verbose("[%s] zone %s set SOA TTL to %u",
                zone_str, zone->name?zone->name:"(null)", rrset_ttl);
            ldns_rr_set_ttl(rr, rrset_ttl);
        }
        if (zone->signconf->soa_min) {
            tmp = (uint32_t) duration2time(zone->signconf->soa_min);
            ods_log_verbose("[%s] zone %s set SOA MINIMUM to %u",
                zone_str, zone->name?zone->name:"(null)", tmp);
            soa_min = ldns_rr_set_rdf(rr,
                ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, tmp),
                SE_SOA_RDATA_MINIMUM);
            if (soa_min) {
                ldns_rdf_deep_free(soa_min);
            } else {
                ods_log_error("[%s] zone %s failed to replace SOA MINIMUM "
                    "rdata", zone_str, zone->name?zone->name:"(null)");
                return ODS_STATUS_ASSERT_ERR;
            }
        }
    }

    /* lookup domain */
    domain = zone_lookup_domain(zone, ldns_rr_owner(rr));
    if (!domain) {
        /* add domain */
        domain = domain_create(zone->allocator, ldns_rr_owner(rr),
            (void*) zone);
        if (!domain) {
            ods_log_error("[%s] unable to add RR: create domain failed",
                zone_str);
            return ODS_STATUS_ERR;
        }
        if (zone_add_domain(zone, domain) == NULL) {
            ods_log_error("[%s] unable to add RR: add domain failed",
                zone_str);
            return ODS_STATUS_ERR;
        }
        if (ldns_dname_compare(domain->dname, zone->origin) == 0) {
            domain->dstatus = DOMAIN_STATUS_APEX;
        }
    }
    ods_log_assert(domain);

    /* lookup RRset */
    rrset = domain_lookup_rrset(domain, type);
    if (!rrset) {
        /* add RRset */
        rrset = rrset_create(domain->dname, zone->default_ttl, type,
            (void*) zone);
        if (!rrset) {
            ods_log_error("[%s] unable to add RR: create RRset failed",
                zone_str);
            return ODS_STATUS_ERR;
        }
        if (domain_add_rrset(domain, rrset) == NULL) {
            ods_log_error("[%s] unable to add RR: add RRset failed",
                zone_str);
            return ODS_STATUS_ERR;
        }
    }
    ods_log_assert(rrset);

    /* add RR */
    status = rrset_add_rr(rrset, rr);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to add RR: pend RR failed", zone_str);
        return status;
    }

    /* update stats */
    if (zone->stats && do_stats) {
        zone->stats->sort_count += 1;
    }
    return ODS_STATUS_OK;
}


/**
 * Delete RR.
 *
 */
ods_status
zone_del_rr(zone_type* zone, ldns_rr* rr, int do_stats)
{
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;

    if (!rr) {
        ods_log_error("[%s] unable to del RR: no RR", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rr);

    if (!zone || !zone->domains) {
        ods_log_error("[%s] unable to del RR: no storage", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->domains);

    /* lookup domain */
    domain = zone_lookup_domain(zone, ldns_rr_owner(rr));
    if (!domain) {
        /* no domain, no del */
        ods_log_warning("[%s] unable to del RR: no such domain", zone_str);
        return ODS_STATUS_UNCHANGED;
    }
    ods_log_assert(domain);

    /* lookup RRset */
    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (!rrset) {
        /* no RRset, no del */
        ods_log_warning("[%s] unable to del RR: no such RRset", zone_str);
        return ODS_STATUS_UNCHANGED;
    }
    ods_log_assert(rrset);

    /* del RR */
    status = rrset_del_rr(rrset, rr,
        (ldns_rr_get_type(rr) == LDNS_RR_TYPE_DNSKEY));
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to del RR: pend RR failed", zone_str);
        return status;
    }

    /* update stats */
    if (do_stats && zone->stats) {
        zone->stats->sort_count -= 1;
    }
    return ODS_STATUS_OK;
}


/**
 * Calculate zone differences between current and new RRsets.
 *
 */
ods_status
zonedata_diff(zone_type* zone, keylist_type* kl)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!zone || !zone->domains) {
        return status;
    }
    if (zone->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zone->domains);
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
zonedata_commit(zone_type* zone)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* nxtnode = LDNS_RBTREE_NULL;
    ldns_rbnode_t* tmpnode = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    domain_type* nxtdomain = NULL;
    ods_status status = ODS_STATUS_OK;
    size_t oldnum = 0;

    if (!zone || !zone->domains) {
        return ODS_STATUS_OK;
    }
    if (zone->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_last(zone->domains);
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
                if (zone_del_domain(zone, domain) != NULL) {
                    ods_log_warning("[%s] unable to delete obsoleted domain",
                        zone_str);
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
zonedata_rollback(zone_type* zone)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    if (!zone || !zone->domains) {
        return;
    }
    if (zone->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zone->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_rollback(domain);
        node = ldns_rbtree_next(node);
    }

    entry_clear(zone->journal_entry);
    return;
}


/**
 * Queue all RRsets.
 *
 */
ods_status
zonedata_queue(zone_type* zone, fifoq_type* q, worker_type* worker)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!zone || !zone->domains) {
        return ODS_STATUS_OK;
    }
    if (zone->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zone->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        status = domain_queue(domain, q, worker);
        if (status != ODS_STATUS_OK) {
            return status;
        }
        node = ldns_rbtree_next(node);
    }
    return status;
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
domain_entize(zone_type* zone, domain_type* domain)
{
    ldns_rdf* parent_rdf = NULL;
    domain_type* parent_domain = NULL;

    ods_log_assert(zone);
    ods_log_assert(zone->domains);
    ods_log_assert(zone->origin);
    ods_log_assert(domain);
    ods_log_assert(domain->dname);

    if (domain->parent) {
        /* domain already has parent */
        return ODS_STATUS_OK;
    }

    while (domain && ldns_dname_is_subdomain(domain->dname, zone->origin) &&
           ldns_dname_compare(domain->dname, zone->origin) != 0) {

        /**
         * RFC5155:
         * 4. If the difference in number of labels between the apex and
         *    the original owner name is greater than 1, additional NSEC3
         *    RRs need to be added for every empty non-terminal between
         *     the apex and the original owner name.
         */
        parent_rdf = ldns_dname_left_chop(domain->dname);
        if (!parent_rdf) {
            log_rdf(domain->dname, "unable to entize domain: left chop "
                "failed", 1);
            return ODS_STATUS_ERR;
        }
        ods_log_assert(parent_rdf);

        parent_domain = zone_lookup_domain(zone, parent_rdf);
        if (!parent_domain) {
            parent_domain = domain_create(zone->allocator, parent_rdf,
                (void*) zone);
            ldns_rdf_deep_free(parent_rdf);
            if (!parent_domain) {
                log_rdf(domain->dname, "unable to entize domain: create "
                    "parent failed", 1);
                return ODS_STATUS_ERR;
            }
            ods_log_assert(parent_domain);
            if (zone_add_domain(zone, parent_domain) == NULL) {
                log_rdf(domain->dname, "unable to entize domain: add parent "
                    "failed", 1);
                domain_cleanup(parent_domain);
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
    }
    return ODS_STATUS_OK;
}


/**
 * Add empty non-terminals to zone.
 *
 */
ods_status
zone_entize(zone_type* zone)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;

    if (!zone || !zone->domains) {
        ods_log_error("[%s] unable to entize zone: no domains", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->domains);
    if (!zone->origin) {
        ods_log_error("[%s] unable to entize zone data: no apex", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->origin);

    node = ldns_rbtree_first(zone->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        status = domain_entize(zone, domain);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to entize zone data: entize domain "
                "failed", zone_str);
            return status;
        }
        domain_dstatus(domain);
        node = ldns_rbtree_next(node);
    }
    return ODS_STATUS_OK;
}


/**
 * Withdraw DNSKEYs.
 *
 */
static ods_status
dnskey_withdraw(zone_type* zone, ldns_rr_list* del)
{
    ods_status status = ODS_STATUS_OK;
    size_t i = 0;

    for (i=0; i < ldns_rr_list_rr_count(del); i++) {
        status = zone_del_rr(zone, ldns_rr_list_rr(del, i), 0);
        if (status != ODS_STATUS_OK) {
            return status;
        }
    }
    return status;
}


/**
 * Load signer configuration for zone.
 *
 */
ods_status
zone_load_signconf(zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    signconf_type* signconf = NULL;
    ldns_rr_list* del = NULL;
    char* datestamp = NULL;
    uint32_t ustamp = 0;
    task_id denial_what;
    task_id keys_what;
    task_id what;

    if (!zone) {
        ods_log_error("[%s] unable to load signconf: no zone", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    if (!zone->signconf_filename) {
        ods_log_warning("[%s] zone %s has no signconf filename, treat as "
            "insecure?", zone_str, zone->name);
        return ODS_STATUS_INSECURE;
    }
    ods_log_assert(zone->signconf_filename);

    status = signconf_update(&signconf, zone->signconf_filename,
        zone->signconf->last_modified);
    if (status == ODS_STATUS_OK) {
        if (!signconf) {
            /* this is unexpected */
            ods_log_error("[%s] unable to load signconf: zone %s signconf "
                "%s: storage empty", zone_str, zone->name,
                zone->signconf_filename);
            return ODS_STATUS_ASSERT_ERR;
        }
        ustamp = time_datestamp(signconf->last_modified, "%Y-%m-%d %T",
            &datestamp);
        ods_log_verbose("[%s] zone %s signconf file %s is modified since %s",
            zone_str, zone->name, zone->signconf_filename,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);

        /* do stuff */
        del = ldns_rr_list_new();
        if (!del) {
            ods_log_error("[%s] unable to load signconf: zone %s "
                "signconf %s: ldns_rr_list_new() failed",
                zone_str, zone->name, zone->signconf_filename);
            return ODS_STATUS_MALLOC_ERR;
        }
        denial_what = signconf_compare_denial(zone->signconf, signconf);
        keys_what = signconf_compare_keys(zone->signconf, signconf, del);

        /* Key Rollover? */
        if (keys_what == TASK_READ) {
            status = dnskey_withdraw(zone, del);
        }
        ldns_rr_list_free(del);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to load signconf: zone %s "
                "signconf %s: failed to delete DNSKEY from RRset",
                zone_str, zone->name, zone->signconf_filename);
            zonedata_rollback(zone);
            return status;
        }

        /* Denial of Existence Rollover? */
        if (denial_what == TASK_NSECIFY) {
            /* or NSEC -> NSEC3, or NSEC3 -> NSEC, or NSEC3PARAM changed */
            nsec3params_cleanup(zone->nsec3params);
            zone->nsec3params = NULL;
            /* all NSEC(3)s become invalid */
            zone_wipe_denials(zone);
            zone_cleanup_denials(zone);
            zone_init_denials(zone);
        }

        /* all ok, switch to new signconf */
        if (keys_what != TASK_NONE) {
            what = keys_what;
        } else {
            what = denial_what;
        }
        if (what == TASK_NONE) { /* no major changes, continue signing */
            what = TASK_SIGN;
        }
/*
        *tbs = what;
*/
        signconf_cleanup(zone->signconf);
        ods_log_debug("[%s] zone %s switch to new signconf", zone_str,
            zone->name);
        zone->signconf = signconf;
        signconf_log(zone->signconf, zone->name);
        zone->default_ttl =
            (uint32_t) duration2time(zone->signconf->soa_min);
    } else if (status == ODS_STATUS_UNCHANGED) {
/*
        *tbs = TASK_READ;
*/
        ustamp = time_datestamp(zone->signconf->last_modified,
            "%Y-%m-%d %T", &datestamp);
        ods_log_verbose("[%s] zone %s signconf file %s is unchanged since "
            "%s", zone_str, zone->name, zone->signconf_filename,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);
    } else {
        ods_log_error("[%s] unable to load signconf: zone %s signconf %s: "
            "%s", zone_str, zone->name, zone->signconf_filename,
            ods_status2str(status));
    }
    return status;
}


/**
 * Publish DNSKEYs.
 *
 */
ods_status
zone_publish_dnskeys(zone_type* zone, int recover)
{
    hsm_ctx_t* ctx = NULL;
    key_type* key = NULL;
    uint32_t ttl = 0;
    size_t count = 0;
    ods_status status = ODS_STATUS_OK;
    ldns_rr* dnskey = NULL;
    int do_publish = 0;

    if (!zone) {
        ods_log_error("[%s] unable to publish dnskeys: no zone", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);

    if (!zone->signconf) {
        ods_log_error("[%s] unable to publish dnskeys zone %s: no signconf",
            zone_str, zone->name);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf);

    if (!zone->signconf->keys) {
        ods_log_error("[%s] unable to publish dnskeys zone %s: no keys",
            zone_str, zone->name);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf->keys);

    if (!zone->domains) {
        ods_log_error("[%s] unable to publish dnskeys zone %s: no domains",
            zone_str, zone->name);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->domains);

    ttl = zone->default_ttl;
    if (zone->signconf->dnskey_ttl) {
        ttl = (uint32_t) duration2time(zone->signconf->dnskey_ttl);
    }

    ctx = hsm_create_context();
    if (ctx == NULL) {
        ods_log_error("[%s] unable to publish dnskeys for zone %s: error "
            "creating libhsm context", zone_str, zone->name);
        return ODS_STATUS_HSM_ERR;
    }

    key = zone->signconf->keys->first_key;
    for (count=0; count < zone->signconf->keys->count; count++) {
        if (key->publish) {
            do_publish = 0;
            if (!key->dnskey) {
                do_publish = 1;
            }

            status = lhsm_get_key(ctx, zone->origin, key);
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to publish dnskeys zone %s: "
                    "error creating DNSKEY for key %s", zone_str,
                    zone->name, key->locator?key->locator:"(null)");
                break;
            }
            ods_log_assert(key->dnskey);

            ldns_rr2canonical(key->dnskey);
            if (recover || do_publish) {
                status = zone_add_rr(zone, key->dnskey, 0);
            } else {
                status = ODS_STATUS_OK;
            }

            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to publish dnskeys zone %s: "
                    "error adding DNSKEY[%u] for key %s", zone_str,
                    zone->name, ldns_calc_keytag(dnskey),
                    key->locator?key->locator:"(null)");
                break;
            }
        }
        key = key->next;
    }

    if (status != ODS_STATUS_OK) {
        zonedata_rollback(zone);
    }
    hsm_destroy_context(ctx);
    ctx = NULL;
    return status;
}


/**
 * Prepare for NSEC3.
 *
 */
ods_status
zone_prepare_nsec3(zone_type* zone, int recover)
{
    ldns_rr* nsec3params_rr = NULL;
    domain_type* apex = NULL;
    rrset_type* rrset = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!zone) {
        ods_log_error("[%s] unable to prepare NSEC3: no zone", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);

    if (!zone->signconf) {
        ods_log_error("[%s] unable to prepare NSEC3: no signconf", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf);

    if (zone->signconf->nsec_type != LDNS_RR_TYPE_NSEC3) {
        /* no preparations needed */
        return ODS_STATUS_OK;
    }

    if (!zone->nsec3params) {
        ods_log_debug("[%s] prepare NSEC3 for zone %s", zone_str, zone->name);

        zone->nsec3params = nsec3params_create(
            (uint8_t) zone->signconf->nsec3_algo,
            (uint8_t) zone->signconf->nsec3_optout,
            (uint16_t) zone->signconf->nsec3_iterations,
            zone->signconf->nsec3_salt);
    }
    if (!zone->nsec3params) {
        ods_log_error("[%s] unable to prepare zone %s for NSEC3: failed "
            "to create NSEC3 parameters", zone_str, zone->name);
        return ODS_STATUS_MALLOC_ERR;
    }
    ods_log_assert(zone->nsec3params);

    if (!recover) {
        nsec3params_rr = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3PARAMS);
        if (!nsec3params_rr) {
            ods_log_error("[%s] unable to prepare zone %s for NSEC3: failed "
                "to create NSEC3PARAM RR", zone_str, zone->name);
            nsec3params_cleanup(zone->nsec3params);
            return ODS_STATUS_MALLOC_ERR;
        }
        ods_log_assert(nsec3params_rr);

        ldns_rr_set_class(nsec3params_rr, zone->klass);
        ldns_rr_set_ttl(nsec3params_rr, zone->default_ttl);
        ldns_rr_set_owner(nsec3params_rr, ldns_rdf_clone(zone->origin));
        ldns_nsec3_add_param_rdfs(nsec3params_rr,
            zone->nsec3params->algorithm, 0,
            zone->nsec3params->iterations,
            zone->nsec3params->salt_len,
            zone->nsec3params->salt_data);
        /**
         * Always set bit 7 of the flags to zero,
         * according to rfc5155 section 11
         */
        ldns_set_bit(ldns_rdf_data(ldns_rr_rdf(nsec3params_rr, 1)), 7, 0);
        ldns_rr2canonical(nsec3params_rr);

        zone->nsec3params->rr = nsec3params_rr;
    }
    ods_log_assert(zone->nsec3params->rr);

    status = zone_add_rr(zone, zone->nsec3params->rr, 0);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to add NSEC3PARAM RR to zone %s",
            zone_str, zone->name);
        nsec3params_cleanup(zone->nsec3params);
        zone->nsec3params = NULL;
    } else if (!recover) {
        /* add ok, wipe out previous nsec3params */
        apex = zone_lookup_domain(zone, zone->origin);
        if (!apex) {
            ods_log_crit("[%s] unable to delete previous NSEC3PARAM RR "
            "from zone %s: apex undefined", zone_str, zone->name);
            nsec3params_cleanup(zone->nsec3params);
            zone->nsec3params = NULL;
            zonedata_rollback(zone);
            return ODS_STATUS_ASSERT_ERR;
        }
        ods_log_assert(apex);

        rrset = domain_lookup_rrset(apex, LDNS_RR_TYPE_NSEC3PARAMS);
        if (rrset) {
            status = rrset_wipe_out(rrset);
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to wipe out previous "
                    "NSEC3PARAM RR from zone %s", zone_str, zone->name);
                nsec3params_cleanup(zone->nsec3params);
                zone->nsec3params = NULL;
                rrset_rollback(rrset);
                return status;
            }
        }
    }
    return status;
}


/**
 * Add NSEC records to zone.
 *
 */
ods_status
zone_nsecify(zone_type* zone, uint32_t* num_added)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* nxt_node = LDNS_RBTREE_NULL;
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;
    domain_type* apex = NULL;
    denial_type* denial = NULL;
    denial_type* nxt = NULL;
    size_t nsec_added = 0;
    uint32_t ttl = 0;

    if (!zone || !zone->domains) {
        return ODS_STATUS_OK;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->domains);

    node = ldns_rbtree_first(zone->domains);
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
            if (domain_count_rrset(domain)) {
                log_rdf(domain->dname, "nsecify: don't do glue domain", 6);
            } else {
                log_rdf(domain->dname, "nsecify: don't do empty domain", 6);
            }
            if (domain->denial) {
                if (zone_del_denial(zone, domain->denial) != NULL) {
                    ods_log_warning("[%s] unable to nsecify: failed to "
                        "delete denial of existence data point", zone_str);
                    return ODS_STATUS_ERR;
                }
            }
            node = ldns_rbtree_next(node);
            continue;
        }
        if (!apex) {
            ods_log_alert("[%s] unable to nsecify: apex unknown", zone_str);
            return ODS_STATUS_ASSERT_ERR;
        }

        /* add the denial of existence */
        if (!domain->denial) {
            status = zone_add_denial(zone, domain);
            if (status != ODS_STATUS_OK) {
                log_rdf(domain->dname, "unable to nsecify: failed to add "
                    "denial of existence for domain", 1);
                return status;
            }
            nsec_added++;
        }
        node = ldns_rbtree_next(node);
    }

    /** Now we have the complete denial of existence chain */
    node = ldns_rbtree_first(zone->denials);
    ttl = zone->default_ttl;
    if (zone->signconf->soa_min) {
        ttl = (uint32_t) duration2time(zone->signconf->soa_min);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        denial = (denial_type*) node->data;
        nxt_node = ldns_rbtree_next(node);
        if (!nxt_node || nxt_node == LDNS_RBTREE_NULL) {
             nxt_node = ldns_rbtree_first(zone->denials);
        }
        nxt = (denial_type*) nxt_node->data;

        status = denial_nsecify(denial, nxt, ttl, zone->klass);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to nsecify: failed to add NSEC record",
                zone_str);
            return status;
        }
        node = ldns_rbtree_next(node);
    }
    if (num_added) {
        *num_added = nsec_added;
    }
    return ODS_STATUS_OK;
}


/**
 * Add NSEC3 records to zone.
 *
 */
ods_status
zone_nsecify3(zone_type* zone, uint32_t* num_added)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* nxt_node = LDNS_RBTREE_NULL;
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;
    domain_type* apex = NULL;
    denial_type* denial = NULL;
    denial_type* nxt = NULL;
    size_t nsec3_added = 0;
    uint32_t ttl = 0;

    if (!zone || !zone->domains) {
        ods_log_error("[%s] unable to nsecify3: no domains", zone_str);
        return ODS_STATUS_OK;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->domains);

    if (!zone->nsec3params) {
        ods_log_error("[%s] unable to nsecify3: no nsec3params", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->nsec3params);

    node = ldns_rbtree_first(zone->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain->dstatus == DOMAIN_STATUS_APEX) {
            apex = domain;
        }
        /* don't do glue-only domains */
        if (domain->dstatus == DOMAIN_STATUS_NONE ||
            domain->dstatus == DOMAIN_STATUS_OCCLUDED ||
            domain_ent2glue(node)) {
            log_rdf(domain->dname, "nsecify3: don't do glue domain" , 6);
            if (domain->denial) {
                if (zone_del_denial(zone, domain->denial) != NULL) {
                    ods_log_error("[%s] unable to nsecify3: failed to "
                        "delete denial of existence data point", zone_str);
                    return ODS_STATUS_ERR;
                }
            }
            node = ldns_rbtree_next(node);
            continue;
        }
        /* Opt-Out? */
        if (zone->nsec3params->flags) {
            /* If Opt-Out is being used, owner names of unsigned delegations
               MAY be excluded. */
            if (domain->dstatus == DOMAIN_STATUS_NS ||
                domain_ent2unsigned(node)) {
                if (domain->dstatus == DOMAIN_STATUS_NS) {
                    log_rdf(domain->dname, "nsecify3: opt-out (unsigned "
                        "delegation)", 5);
                } else {
                    log_rdf(domain->dname, "nsecify3: opt-out (empty "
                        "non-terminal (to unsigned delegation))", 5);
                }
                if (domain->denial) {
                    if (zone_del_denial(zone, domain->denial) != NULL) {
                        ods_log_error("[%s] unable to nsecify3: failed to "
                            "delete denial of existence data point", zone_str);
                        return ODS_STATUS_ERR;
                    }
                }
                node = ldns_rbtree_next(node);
                continue;
            }
        }
        if (!apex) {
            ods_log_alert("[%s] unable to nsecify3: apex unknown", zone_str);
            return ODS_STATUS_ASSERT_ERR;
        }
        /* add the denial of existence */
        if (!domain->denial) {
            status = zone_add_denial(zone, domain);
            if (status != ODS_STATUS_OK) {
                log_rdf(domain->dname, "unable to nsecify3: failed to add "
                    "denial of existence for domain", 1);
                return status;
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
         * wildcard_name = *.domain->dname;
         * hashed_ownername = ldns_nsec3_hash_name(domain->dname,
               nsec3params->algorithm, nsec3params->iterations,
               nsec3params->salt_len, nsec3params->salt);
         * domain->nsec3_wildcard = denial_create(hashed_ownername);
        **/

        node = ldns_rbtree_next(node);
    }

    /** Now we have the complete denial of existence chain */
    node = ldns_rbtree_first(zone->denials);
    ttl = zone->default_ttl;
    if (zone->signconf->soa_min) {
        ttl = (uint32_t) duration2time(zone->signconf->soa_min);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        denial = (denial_type*) node->data;
        nxt_node = ldns_rbtree_next(node);
        if (!nxt_node || nxt_node == LDNS_RBTREE_NULL) {
             nxt_node = ldns_rbtree_first(zone->denials);
        }
        nxt = (denial_type*) nxt_node->data;

        status = denial_nsecify3(denial, nxt,
            zone->default_ttl, zone->klass, zone->nsec3params);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to nsecify3: failed to add NSEC3 "
                "record", zone_str);
            return status;
        }
        node = ldns_rbtree_next(node);
    }
    if (num_added) {
        *num_added = nsec3_added;
    }
    return ODS_STATUS_OK;
}


/**
 * Merge zones.
 *
 */
void
zone_merge(zone_type* z1, zone_type* z2)
{
    const char* str;
    adapter_type* adtmp = NULL;

    if (!z1 || !z2) {
        return;
    }

    /* policy name */
    if (ods_strcmp(z2->policy_name, z1->policy_name) != 0) {
        if (z2->policy_name) {
            str = strdup(z2->policy_name);
            if (!str) {
                ods_log_error("[%s] failed to merge policy %s name to zone "
                    "%s", zone_str, z2->policy_name, z1->name);
            } else {
                free((void*)z1->policy_name);
                z1->policy_name = str;
                z1->just_updated = 1;
            }
        } else {
            free((void*)z1->policy_name);
            z1->policy_name = NULL;
            z1->just_updated = 1;
        }
    }

    /* signconf filename */
    if (ods_strcmp(z2->signconf_filename, z1->signconf_filename) != 0) {
        if (z2->signconf_filename) {
            str = strdup(z2->signconf_filename);
            if (!str) {
                ods_log_error("[%s] failed to merge signconf filename %s to "
                    "zone %s", zone_str, z2->policy_name, z1->name);
            } else {
                free((void*)z1->signconf_filename);
                z1->signconf_filename = str;
                z1->just_updated = 1;
            }
        } else {
            free((void*)z1->signconf_filename);
            z1->signconf_filename = NULL;
            z1->just_updated = 1;
        }
    }

    /* adapters */
    if (adapter_compare(z2->adinbound, z1->adinbound) != 0) {
        adtmp = z2->adinbound;
        z2->adinbound = z1->adinbound;
        z1->adinbound = adtmp;
        adtmp = NULL;
    }
    if (adapter_compare(z2->adoutbound, z1->adoutbound) != 0) {
        adtmp = z2->adoutbound;
        z2->adoutbound = z1->adoutbound;
        z1->adoutbound = adtmp;
        adtmp = NULL;
    }
    return;
}


/**
 * Internal update serial function.
 *
 */
static ods_status
zonedata_update_serial(zone_type* zone)
{
    uint32_t soa = 0;
    uint32_t prev = 0;
    uint32_t update = 0;

    ods_log_assert(zone);
    ods_log_assert(zone->signconf);

    prev = zone->outbound_serial;
    if (!zone->initialized) {
        prev = zone->inbound_serial;
    }
    ods_log_debug("[%s] update serial: in=%u internal=%u out=%u now=%u",
        zone_str, zone->inbound_serial, zone->internal_serial, zone->outbound_serial,
        (uint32_t) time_now());

    if (!zone->signconf->soa_serial) {
        ods_log_error("[%s] no serial type given", zone_str);
        return ODS_STATUS_ERR;
    }

    if (ods_strcmp(zone->signconf->soa_serial, "unixtime") == 0) {
        soa = (uint32_t) time_now();
        if (!DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
    } else if (strncmp(zone->signconf->soa_serial, "counter", 7) == 0) {
        soa = zone->inbound_serial;
        if (zone->initialized && !DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
    } else if (strncmp(zone->signconf->soa_serial, "datecounter", 11) == 0) {
        soa = (uint32_t) time_datestamp(0, "%Y%m%d", NULL) * 100;
        if (!DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
    } else if (strncmp(zone->signconf->soa_serial, "keep", 4) == 0) {
        soa = zone->inbound_serial;
        if (zone->initialized && !DNS_SERIAL_GT(soa, prev)) {
            ods_log_error("[%s] cannot keep SOA SERIAL from input zone "
                " (%u): output SOA SERIAL is %u", zone_str, soa, prev);
            return ODS_STATUS_CONFLICT_ERR;
        }
    } else {
        ods_log_error("[%s] unknown serial type %s", zone_str,
            zone->signconf->soa_serial);
        return ODS_STATUS_ERR;
    }

    /* serial is stored in 32 bits */
    update = soa - prev;
    if (update > 0x7FFFFFFF) {
        update = 0x7FFFFFFF;
    }

    if (!zone->initialized) {
        zone->internal_serial = soa;
    } else {
        zone->internal_serial += update; /* automatically does % 2^32 */
    }
    ods_log_debug("[%s] update serial: %u + %u = %u", zone_str, prev, update,
        zone->internal_serial);
    return ODS_STATUS_OK;
}


/**
 * Update serial.
 *
 */
ods_status
zone_update_serial(zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;
    ldns_rdf* serial = NULL;

    if (!zone) {
        ods_log_error("[%s] unable to update serial: no zone", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);

    if (!zone->signconf) {
        ods_log_error("[%s] unable to update serial: no signconf", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf);

    if (!zone->domains) {
        ods_log_error("[%s] unable to update serial: no domains", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->domains);

    status = zonedata_update_serial(zone);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to update serial: failed to increment",
            zone_str);
        return status;
    }

    /* lookup domain */
    domain = zone_lookup_domain(zone, zone->origin);
    if (!domain) {
        ods_log_error("[%s] unable to update serial: apex not found",
            zone_str);
        return ODS_STATUS_ERR;
    }
    ods_log_assert(domain);

    /* lookup RRset */
    rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_SOA);
    if (!rrset) {
        ods_log_error("[%s] unable to update serial: SOA RRset not found",
            zone_str);
        return ODS_STATUS_ERR;
    }
    ods_log_assert(rrset);
    ods_log_assert(rrset->rr_type == LDNS_RR_TYPE_SOA);

    if (rrset->rrs && rrset->rrs->rr) {
        serial = ods_rr_set_rdf(rrset->rrs->rr,
            ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, zone->internal_serial),
            SE_SOA_RDATA_SERIAL);
        if (serial) {
            if (ldns_rdf2native_int32(serial) != zone->internal_serial) {
                rrset->needs_signing = 1;
            }
            ldns_rdf_deep_free(serial);
         } else {
            ods_log_error("[%s] unable to update serial: failed to replace "
                "SOA SERIAL rdata", zone_str);
            return ODS_STATUS_ERR;
        }
    }
    return ODS_STATUS_OK;
}


/**
 * Examine domain for occluded data.
 *
 */
static int
zonedata_examine_domain_is_occluded(zone_type* zone, domain_type* domain)
{
    ldns_rdf* parent_rdf = NULL;
    ldns_rdf* next_rdf = NULL;
    domain_type* parent_domain = NULL;
    char* str_name = NULL;
    char* str_parent = NULL;

    ods_log_assert(zone);
    ods_log_assert(zone->domains);
    ods_log_assert(zone->origin);
    ods_log_assert(domain);
    ods_log_assert(domain->dname);

    if (ldns_dname_compare(domain->dname, zone->origin) == 0) {
        return 0;
    }

    if (domain_examine_valid_zonecut(domain) != 0) {
        log_rdf(domain->dname, "occluded (non-glue non-DS) data at NS", 2);
        return 1;
    }

    parent_rdf = ldns_dname_left_chop(domain->dname);
    while (parent_rdf && ldns_dname_is_subdomain(parent_rdf, zone->origin) &&
           ldns_dname_compare(parent_rdf, zone->origin) != 0) {

        parent_domain = zone_lookup_domain(zone, parent_rdf);
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
                    zone_str, str_name, str_parent);
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
                    "%s NS)", zone_str, str_name, str_parent);
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
                    zone_str, str_name, str_parent);
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
 * Examine zone.
 *
 */
ods_status
zone_examine(zone_type* zone)
{
    int result = 0;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!zone || !zone->domains) {
       /* no zone data, no error */
       return ODS_STATUS_OK;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->domains);

    if (zone->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zone->domains);
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

        if (zone->adinbound->type == ADAPTER_FILE) {
            result =
            /* Thou shall not have occluded data in your zone file */
            zonedata_examine_domain_is_occluded(zone, domain);
            if (result) {
                ; /* just warn if there is occluded data */
            }
        }
        node = ldns_rbtree_next(node);
    }
    return status;
}


/**
 * Print zone.
 *
 */
ods_status
zone_print(FILE* fd, zone_type* zone)
{
ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    if (!fd) {
        ods_log_error("[%s] unable to print zone: no file descriptor",
            zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(fd);

    if (!zone || !zone->domains) {
        ods_log_error("[%s] unable to print zone: no domains", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->domains);

    node = ldns_rbtree_first(zone->domains);
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


/**
 * Wipe out all NSEC RRsets.
 *
 */
void
zone_wipe_denials(zone_type* zone)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    denial_type* denial = NULL;

    if (zone && zone->denials) {
        node = ldns_rbtree_first(zone->denials);
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
 * Clean up domains.
 *
 */
static void
domain_delfunc(ldns_rbnode_t* elem)
{
    domain_type* domain = NULL;

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
 * Clean up denial of existence data points.
 *
 */
static void
denial_delfunc(ldns_rbnode_t* elem)
{
    denial_type* denial = NULL;
    domain_type* domain = NULL;


    if (elem && elem != LDNS_RBTREE_NULL) {
        denial = (denial_type*) elem->data;
        denial_delfunc(elem->left);
        denial_delfunc(elem->right);

        domain = denial->domain;
        if (domain) {
            domain->denial = NULL;
        }
        denial_cleanup(denial);

        free((void*)elem);
    }
    return;
}


/**
 * Clean up domains.
 *
 */
void
zone_cleanup_domains(zone_type* zone)
{
    if (zone && zone->domains) {
        domain_delfunc(zone->domains->root);
        ldns_rbtree_free(zone->domains);
        zone->domains = NULL;
    }
    return;
}


/**
 * Clean up denial of existence chain.
 *
 */
void
zone_cleanup_denials(zone_type* zone)
{
    if (zone && zone->denials) {
        denial_delfunc(zone->denials->root);
        ldns_rbtree_free(zone->denials);
        zone->denials = NULL;
    }
    return;
}


/**
 * Clean up zone.
 *
 */
void
zone_cleanup(zone_type* zone)
{
    allocator_type* allocator;
    lock_basic_type zone_lock;

    if (!zone) {
        return;
    }
    allocator = zone->allocator;
    zone_lock = zone->zone_lock;

    ldns_rdf_deep_free(zone->origin);
    adapter_cleanup(zone->adinbound);
    adapter_cleanup(zone->adoutbound);
    zone_cleanup_denials(zone);
    zone_cleanup_domains(zone);
    entry_cleanup(allocator, zone->journal_entry);
    signconf_cleanup(zone->signconf);
    nsec3params_cleanup(zone->nsec3params);
    stats_cleanup(zone->stats);
    allocator_deallocate(allocator, (void*) zone->notify_ns);
    allocator_deallocate(allocator, (void*) zone->policy_name);
    allocator_deallocate(allocator, (void*) zone->signconf_filename);
    allocator_deallocate(allocator, (void*) zone->name);
    allocator_deallocate(allocator, (void*) zone);
    allocator_cleanup(allocator);
    lock_basic_destroy(&zone_lock);
    return;
}


/**
 * Log RDF.
 *
 */
void
log_rdf(ldns_rdf *rdf, const char* pre, int level)
{
    char* str = NULL;
    if (ods_log_get_level() < level + 2) return;
    str = ldns_rdf2str(rdf);
    if (level == 1) {
        ods_log_error("[%s] %s : %s", zone_str, pre?pre:"", str?str:"(null)");
    } else if (level == 2) {
        ods_log_warning("[%s] %s : %s", zone_str, pre?pre:"", str?str:"(null)");
    } else if (level == 3) {
        ods_log_info("[%s] %s : %s", zone_str, pre?pre:"", str?str:"(null)");
    } else if (level == 4) {
        ods_log_verbose("[%s] %s : %s", zone_str, pre?pre:"", str?str:"(null)");
    } else if (level == 5) {
        ods_log_debug("[%s] %s : %s", zone_str, pre?pre:"", str?str:"(null)");
    } else if (level == 6) {
        ods_log_deeebug("[%s] %s : %s", zone_str, pre?pre:"", str?str:"(null)");
    } else {
        ods_log_deeebug("[%s] %s : %s", zone_str, pre?pre:"", str?str:"(null)");
    }
    free((void*)str);
    return;
}




/***************************/
/** BACKUP RECOVERY STUFF **/
/***************************/


/**
 * Backup RRset.
 *
 */
static void
rrset_backup(FILE* fd, rrset_type* rrset)
{
    if (!rrset || !fd) {
        return;
    }
    if (rrset->rrsigs) {
        rrsigs_print(fd, rrset->rrsigs, 1);
    }
    return;
}


/**
 * Backup domain.
 *
 */
void
domain_backup(FILE* fd, domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    char* str = NULL;
    rrset_type* rrset = NULL;

    if (!domain || !fd) {
        return;
    }

    str = ldns_rdf2str(domain->dname);
    if (domain->rrsets) {
        node = ldns_rbtree_first(domain->rrsets);
    }

    fprintf(fd, ";;Domain: name %s status %i\n", str, (int) domain->dstatus);
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        rrset_backup(fd, rrset);
        node = ldns_rbtree_next(node);
    }
    free((void*)str);

    /* denial of existence */
    if (domain->denial) {
        fprintf(fd, ";;Denial\n");
        rrset_print(fd, domain->denial->rrset, 1);
        rrset_backup(fd, domain->denial->rrset);
    }

    fprintf(fd, ";;Domaindone\n");
    return;
}


/**
 * Backup zone data.
 *
 */
static void
zonedata_backup(FILE* fd, zone_type* zone)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    if (!fd || !zone) {
        return;
    }

    node = ldns_rbtree_first(zone->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_backup(fd, domain);
        node = ldns_rbtree_next(node);
    }
    fprintf(fd, ";;\n");
    return;
}


/**
 * Backup zone.
 *
 */
ods_status
zone_backup(zone_type* zone)
{
    char* filename = NULL;
    FILE* fd = NULL;

    ods_log_assert(zone);
    ods_log_assert(zone->domains);
    ods_log_assert(zone->denials);
    ods_log_assert(zone->signconf);

    filename = ods_build_path(zone->name, ".backup", 0);
    fd = ods_fopen(filename, NULL, "w");
    free((void*)filename);

    if (fd) {
        fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
        /** Backup zone */
        fprintf(fd, ";;Zone: name %s class %i ttl %u inbound %u internal "
            "%u outbound %u\n",
            zone->name?zone->name:"(null)",
            (int) zone->klass,
            (unsigned) zone->default_ttl,
            (unsigned) zone->inbound_serial,
            (unsigned) zone->internal_serial,
            (unsigned) zone->outbound_serial);
        /** Backup task */
        if (zone->task) {
            task_backup(fd, (task_type*) zone->task);
        }
        /** Backup signconf */
        signconf_backup(fd, zone->signconf);
        fprintf(fd, ";;\n");
        /** Backup NSEC3 parameters */
        if (zone->nsec3params) {
            nsec3params_backup(fd,
                zone->signconf->nsec3_algo,
                zone->signconf->nsec3_optout,
                zone->signconf->nsec3_iterations,
                zone->signconf->nsec3_salt,
                zone->nsec3params->rr);
        }
        /** Backup keylist */
        keylist_backup(fd, zone->signconf->keys);
        /** Backup domains and stuff */
        zonedata_backup(fd, zone);
        /** Done */
        fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
        ods_fclose(fd);
    } else {
        return ODS_STATUS_FOPEN_ERR;
    }
    return ODS_STATUS_OK;
}


/**
 * Recover RRSIG from backup.
 *
 */
static ods_status
rrset_recover(rrset_type* rrset, ldns_rr* rrsig, const char* locator,
    uint32_t flags)
{
    ods_status status = ODS_STATUS_OK;
    ods_rr* rr = NULL;

    ods_log_assert(rrset);
    ods_log_assert(rrsig);
    ods_log_assert(locator);
    ods_log_assert(flags);

    rr = ods_rr_new(rrsig);
    if (!rr) {
        ods_log_error("[%s] unable to recover RRSIG: convert failed",
            zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }

    if (!rrset->rrsigs) {
        rrset->rrsigs = rrsigs_create((void*) rrset);
    }
    status = rrsigs_add_sig(rrset->rrsigs, rr, locator, flags);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to recover RRSIG: add failed", zone_str);
        ods_rr_free(rr);
/*        log_rr(rrsig, "+RRSIG", 1); */
    } else {
        rrset->rrsig_count += 1;
        /**
         * This RRset was recovered, no need for signing.
         * If the signature is about to expire, the recycle logic will
         * catch that.
         */
        rrset->needs_signing = 0;
    }
    return status;
}


/**
 * Recover domain from backup.
 *
 */
ods_status
domain_recover(zone_type* zone, FILE* fd, domain_type* domain,
    domain_status dstatus)
{
    const char* token = NULL;
    const char* locator = NULL;
    uint32_t flags = 0;
    ldns_rr* rr = NULL;
    rrset_type* rrset = NULL;
    ldns_status lstatus = LDNS_STATUS_OK;
    ldns_rr_type type_covered = LDNS_RR_TYPE_FIRST;

    ods_log_assert(zone);
    ods_log_assert(zone->domains);
    ods_log_assert(domain);
    ods_log_assert(fd);

    domain->dstatus = dstatus;

    while (backup_read_str(fd, &token)) {
        if (ods_strcmp(token, ";;RRSIG") == 0) {
            /* recover signature */
            if (!backup_read_str(fd, &locator) ||
                !backup_read_uint32_t(fd, &flags)) {
                ods_log_error("[%s] signature in backup corrupted",
                    zone_str);
                goto recover_dname_error;
            }
            /* expect signature */
            lstatus = ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL);
            if (lstatus != LDNS_STATUS_OK) {
                ods_log_error("[%s] missing signature in backup", zone_str);
                ods_log_error("[%s] ldns status: %s", zone_str,
                    ldns_get_errorstr_by_id(lstatus));
                goto recover_dname_error;
            }
            if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_RRSIG) {
                ods_log_error("[%s] expecting signature in backup", zone_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }

            type_covered = ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rr));
            rrset = domain_lookup_rrset(domain, type_covered);
            if (!rrset) {
                ods_log_error("[%s] signature type %i not covered",
                    zone_str, type_covered);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }
            ods_log_assert(rrset);
            if (rrset_recover(rrset, rr, locator, flags) != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to recover signature", zone_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }
            /* signature done */
            ldns_rr_free(rr);
            free((void*) locator);
            locator = NULL;
            rr = NULL;
        } else if (ods_strcmp(token, ";;Denial") == 0) {
            /* expect nsec(3) record */
            lstatus = ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL);
            if (lstatus != LDNS_STATUS_OK) {
                ods_log_error("[%s] missing denial in backup", zone_str);
                goto recover_dname_error;
            }
            if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_NSEC &&
                ldns_rr_get_type(rr) != LDNS_RR_TYPE_NSEC3) {
                ods_log_error("[%s] expecting denial in backup", zone_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }

            /* recover denial structure */
            ods_log_assert(!domain->denial);
            domain->denial = denial_create(zone->allocator, ldns_rr_owner(rr),
                (void*) zone);
            ods_log_assert(domain->denial);
            domain->denial->domain = domain; /* back reference */
            /* add the NSEC(3) rr */
            if (!domain->denial->rrset) {
                domain->denial->rrset = rrset_create(domain->denial->owner,
                    zone->default_ttl, ldns_rr_get_type(rr), (void*) zone);
            }
            ods_log_assert(domain->denial->rrset);

            if (rrset_add_rr(domain->denial->rrset, rr) != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to recover denial", zone_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }
            /* commit */
            if (rrset_commit(domain->denial->rrset) != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to recover denial", zone_str);
                goto recover_dname_error;
            }
            /* denial done */
            ldns_rr_free(rr);
            rr = NULL;

            /* recover signature */
            if (!backup_read_check_str(fd, ";;RRSIG") ||
                !backup_read_str(fd, &locator) ||
                !backup_read_uint32_t(fd, &flags)) {
                ods_log_error("[%s] signature in backup corrupted (denial)",
                    zone_str);
                goto recover_dname_error;
            }
            /* expect signature */
            lstatus = ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL);
            if (lstatus != LDNS_STATUS_OK) {
                ods_log_error("[%s] missing signature in backup (denial)",
                    zone_str);
                ods_log_error("[%s] ldns status: %s", zone_str,
                    ldns_get_errorstr_by_id(lstatus));
                goto recover_dname_error;
            }
            if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_RRSIG) {
                ods_log_error("[%s] expecting signature in backup (denial)",
                    zone_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }
            if (!domain->denial->rrset) {
                ods_log_error("[%s] signature type not covered (denial)",
                    zone_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }
            ods_log_assert(domain->denial->rrset);
            if (rrset_recover(domain->denial->rrset, rr, locator, flags) !=
                ODS_STATUS_OK) {
                ods_log_error("[%s] unable to recover signature (denial)",
                    zone_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }
            /* signature done */
            ldns_rr_free(rr);
            free((void*) locator);
            locator = NULL;
            rr = NULL;
        } else if (ods_strcmp(token, ";;Domaindone") == 0) {
            /* domain done */
            free((void*) token);
            token = NULL;
            break;
        } else {
            /* domain corrupted */
            goto recover_dname_error;
        }
        /* done, next token */
        free((void*) token);
        token = NULL;
    }
    return ODS_STATUS_OK;

recover_dname_error:
    free((void*) token);
    token = NULL;

    free((void*) locator);
    locator = NULL;
    return ODS_STATUS_ERR;
}


/**
 * Recover zone data from backup.
 *
 */
static ods_status
zonedata_recover(zone_type* zone, FILE* fd)
{
    const char* token = NULL;
    const char* owner = NULL;
    int dstatus = 0;
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;
    ldns_rdf* rdf = NULL;
    ldns_rbnode_t* denial_node = LDNS_RBTREE_NULL;

    ods_log_assert(zone);
    ods_log_assert(fd);

    while (backup_read_str(fd, &token)) {
        /* domain part */
        if (ods_strcmp(token, ";;Domain:") == 0) {
            if (!backup_read_check_str(fd, "name") ||
                !backup_read_str(fd, &owner) ||
                !backup_read_check_str(fd, "status") ||
                !backup_read_int(fd, &dstatus)) {
                ods_log_error("[%s] domain in backup corrupted", zone_str);
                goto recover_domain_error;
            }
            /* ok, look up domain */
            rdf = ldns_dname_new_frm_str(owner);
            if (rdf) {
                domain = zone_lookup_domain(zone, rdf);
                ldns_rdf_deep_free(rdf);
                rdf = NULL;
            }
            if (!domain) {
                ods_log_error("[%s] domain in backup, but not in zone",
                    zone_str);
                goto recover_domain_error;
            }
            /* lookup success */
            status = domain_recover(zone, fd, domain, dstatus);
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to recover domain", zone_str);
                goto recover_domain_error;
            }
            if (domain->denial) {
                denial_node = denial2node(domain->denial);
                /* insert */
                if (!ldns_rbtree_insert(zone->denials, denial_node)) {
                    ods_log_error("[%s] unable to recover denial", zone_str);
                    free((void*)denial_node);
                    goto recover_domain_error;
                }
                denial_node = NULL;
            }

            /* done, next domain */
            free((void*) owner);
            owner = NULL;
            domain = NULL;
        } else if (ods_strcmp(token, ";;") == 0) {
            /* done with all zone data */
            free((void*) token);
            token = NULL;
            return ODS_STATUS_OK;
        } else {
            /* domain corrupted */
            ods_log_error("[%s] domain in backup corrupted", zone_str);
            goto recover_domain_error;
        }
        free((void*) token);
        token = NULL;
    }

    if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC)) {
        goto recover_domain_error;
    }

    return ODS_STATUS_OK;

recover_domain_error:
    free((void*) owner);
    owner = NULL;

    free((void*) token);
    token = NULL;

    return ODS_STATUS_ERR;
}


/**
 * Recover zone from backup.
 *
 */
ods_status
zone_recover(zone_type* zone)
{
    char* filename = NULL;
    FILE* fd = NULL;
    const char* token = NULL;
    ods_status status = ODS_STATUS_OK;
    /* zone part */
    int klass = 0;
    uint32_t ttl = 0;
    uint32_t inbound = 0;
    uint32_t internal = 0;
    uint32_t outbound = 0;
    /* task part */
    task_type* task = NULL;
    time_t when = 0;
    time_t backoff = 0;
    int what = 0;
    int interrupt = 0;
    int halted = 0;
    int flush = 0;
    /* signconf part */
    time_t lastmod = 0;
    /* nsec3params part */
    const char* salt = NULL;
    ldns_rr* nsec3params_rr = NULL;
    nsec3params_type* nsec3params = NULL;
    /* keys part */
    key_type* key = NULL;
    /* zonedata part */
    int fetch = 0;

    ods_log_assert(zone);
    ods_log_assert(zone->signconf);
    ods_log_assert(zone->domains);
    ods_log_assert(zone->denials);

    filename = ods_build_path(zone->name, ".backup", 0);
    fd = ods_fopen(filename, NULL, "r");
    free((void*)filename);
    if (fd) {
        /* start recovery */
        if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC) ||
            /* zone part */
            !backup_read_check_str(fd, ";;Zone:") ||
            !backup_read_check_str(fd, "name") ||
            !backup_read_check_str(fd, zone->name) ||
            !backup_read_check_str(fd, "class") ||
            !backup_read_int(fd, &klass) ||
            !backup_read_check_str(fd, "ttl") ||
            !backup_read_uint32_t(fd, &ttl) ||
            !backup_read_check_str(fd, "inbound") ||
            !backup_read_uint32_t(fd, &inbound) ||
            !backup_read_check_str(fd, "internal") ||
            !backup_read_uint32_t(fd, &internal) ||
            !backup_read_check_str(fd, "outbound") ||
            !backup_read_uint32_t(fd, &outbound) ||
            /* task part */
            !backup_read_check_str(fd, ";;Task:") ||
            !backup_read_check_str(fd, "when") ||
            !backup_read_time_t(fd, &when) ||
            !backup_read_check_str(fd, "what") ||
            !backup_read_int(fd, &what) ||
            !backup_read_check_str(fd, "interrupt") ||
            !backup_read_int(fd, &interrupt) ||
            !backup_read_check_str(fd, "halted") ||
            !backup_read_int(fd, &halted) ||
            !backup_read_check_str(fd, "backoff") ||
            !backup_read_time_t(fd, &backoff) ||
            !backup_read_check_str(fd, "flush") ||
            !backup_read_int(fd, &flush) ||
            /* signconf part */
            !backup_read_check_str(fd, ";;Signconf:") ||
            !backup_read_check_str(fd, "lastmod") ||
            !backup_read_time_t(fd, &lastmod) ||
            !backup_read_check_str(fd, "resign") ||
            !backup_read_duration(fd,
                &zone->signconf->sig_resign_interval) ||
            !backup_read_check_str(fd, "refresh") ||
            !backup_read_duration(fd,
                &zone->signconf->sig_refresh_interval) ||
            !backup_read_check_str(fd, "valid") ||
            !backup_read_duration(fd,
                &zone->signconf->sig_validity_default) ||
            !backup_read_check_str(fd, "denial") ||
            !backup_read_duration(fd,
                &zone->signconf->sig_validity_denial) ||
            !backup_read_check_str(fd, "jitter") ||
            !backup_read_duration(fd, &zone->signconf->sig_jitter) ||
            !backup_read_check_str(fd, "offset") ||
            !backup_read_duration(fd,
                &zone->signconf->sig_inception_offset) ||
            !backup_read_check_str(fd, "nsec") ||
            !backup_read_rr_type(fd, &zone->signconf->nsec_type) ||
            !backup_read_check_str(fd, "dnskeyttl") ||
            !backup_read_duration(fd, &zone->signconf->dnskey_ttl) ||
            !backup_read_check_str(fd, "soattl") ||
            !backup_read_duration(fd, &zone->signconf->soa_ttl) ||
            !backup_read_check_str(fd, "soamin") ||
            !backup_read_duration(fd, &zone->signconf->soa_min) ||
            !backup_read_check_str(fd, "serial") ||
            !backup_read_str(fd, &zone->signconf->soa_serial) ||
            !backup_read_check_str(fd, "audit") ||
            !backup_read_int(fd, &zone->signconf->audit) ||
            !backup_read_check_str(fd, ";;")) {
            goto recover_error;
        }
        /* nsec3params part */
        if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
             if (!backup_read_check_str(fd, ";;Nsec3parameters:") ||
                 !backup_read_check_str(fd, "salt") ||
                 !backup_read_str(fd, &salt) ||
                 !backup_read_check_str(fd, "algorithm") ||
                 !backup_read_uint32_t(fd, &zone->signconf->nsec3_algo) ||
                 !backup_read_check_str(fd, "optout") ||
                 !backup_read_int(fd, &zone->signconf->nsec3_optout) ||
                 !backup_read_check_str(fd, "iterations") ||
                 !backup_read_uint32_t(fd,
                     &zone->signconf->nsec3_iterations) ||
                 ldns_rr_new_frm_fp(&nsec3params_rr, fd, NULL, NULL, NULL) ||
                 !backup_read_check_str(fd, ";;Nsec3done") ||
                 !backup_read_check_str(fd, ";;")) {
                 goto recover_error;
            }
        }
        /* keys part */
        zone->signconf->keys = keylist_create(zone->signconf->allocator);
        while (backup_read_str(fd, &token)) {
            if (ods_strcmp(token, ";;Key:") == 0) {
                key = key_recover(fd, zone->signconf->allocator);
                if (!key || keylist_push(zone->signconf->keys, key) !=
                    ODS_STATUS_OK) {
                    goto recover_error;
                }
                key = NULL;
            } else if (ods_strcmp(token, ";;") == 0) {
                /* keylist done */
                free((void*) token);
                token = NULL;
                break;
            } else {
                /* keylist corrupted */
                goto recover_error;
            }
            free((void*) token);
            token = NULL;
        }
        /* zonedata part */
        filename = ods_build_path(zone->name, ".inbound", 0);
        status = adbackup_read(zone, filename);
        free((void*)filename);
        if (status != ODS_STATUS_OK) {
            goto recover_error;
        }

        zone->klass = (ldns_rr_class) klass;
        zone->default_ttl = ttl;
        zone->inbound_serial = inbound;
        zone->internal_serial = internal;
        zone->outbound_serial = outbound;
        zone->signconf->nsec3_salt = allocator_strdup(
            zone->signconf->allocator, salt);
        free((void*) salt);
        salt = NULL;
        task = task_create((task_id) what, when, zone->name, (void*) zone);
        if (!task) {
            goto recover_error;
        }
        if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
            nsec3params = nsec3params_create(zone->signconf->nsec3_algo,
                zone->signconf->nsec3_optout,
                zone->signconf->nsec3_iterations,
                zone->signconf->nsec3_salt);
            if (!nsec3params) {
                goto recover_error;
            }
            nsec3params->rr = nsec3params_rr;
            zone->nsec3params = nsec3params;
        }
        zone->task = (void*) task;
        zone->signconf->last_modified = lastmod;

        status = zone_publish_dnskeys(zone, 1);
        if (status != ODS_STATUS_OK) {
            zone->task = NULL;
            zone->nsec3params = NULL;
            goto recover_error;
        }
        status = zone_prepare_nsec3(zone, 1);
        if (status != ODS_STATUS_OK) {
            zone->task = NULL;
            zone->nsec3params = NULL;
            goto recover_error;
        }
        status = zonedata_commit(zone);
        if (status != ODS_STATUS_OK) {
            zone->task = NULL;
            zone->nsec3params = NULL;
            goto recover_error;
        }
        status = zone_entize(zone);
        if (status != ODS_STATUS_OK) {
            zone->task = NULL;
            zone->nsec3params = NULL;
            goto recover_error;
        }
        status = zonedata_recover(zone, fd);
        if (status != ODS_STATUS_OK) {
            zone->task = NULL;
            zone->nsec3params = NULL;
            goto recover_error;
        }
        ods_fclose(fd);

        /* all ok */
        zone->initialized = 1;
        if (zone->stats) {
            lock_basic_lock(&zone->stats->stats_lock);
            stats_clear(zone->stats);
            lock_basic_unlock(&zone->stats->stats_lock);
        }
        return ODS_STATUS_OK;
    } else {
        /* backwards compatible backup recovery (serial) */
        filename = ods_build_path(zone->name, ".state", 0);
        fd = ods_fopen(filename, NULL, "r");
        free((void*)filename);
        if (fd) {
            if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC_V1) ||
                !backup_read_check_str(fd, ";name:") ||
                !backup_read_check_str(fd, zone->name) ||
                !backup_read_check_str(fd, ";class:") ||
                !backup_read_int(fd, &klass) ||
                !backup_read_check_str(fd, ";fetch:") ||
                !backup_read_int(fd, &fetch) ||
                !backup_read_check_str(fd, ";default_ttl:") ||
                !backup_read_uint32_t(fd, &ttl) ||
                !backup_read_check_str(fd, ";inbound_serial:") ||
                !backup_read_uint32_t(fd, &inbound) ||
                !backup_read_check_str(fd, ";internal_serial:") ||
                !backup_read_uint32_t(fd, &internal) ||
                !backup_read_check_str(fd, ";outbound_serial:") ||
                !backup_read_uint32_t(fd, &outbound) ||
                !backup_read_check_str(fd, ODS_SE_FILE_MAGIC_V1))
            {
                goto recover_error;
            }
            zone->klass = (ldns_rr_class) klass;
            zone->default_ttl = ttl;
            zone->inbound_serial = inbound;
            zone->internal_serial = internal;
            zone->outbound_serial = outbound;
            /* all ok */
            zone->initialized = 1;
            if (zone->stats) {
                lock_basic_lock(&zone->stats->stats_lock);
                stats_clear(zone->stats);
                lock_basic_unlock(&zone->stats->stats_lock);
            }
            return ODS_STATUS_UNCHANGED;
        }
        ods_fclose(fd);
    }

    return ODS_STATUS_UNCHANGED;

recover_error:
    ods_log_error("[%s] unable to recover zone %s: corrupted file",
        zone_str, zone->name);
    ods_fclose(fd);

    /* signconf cleanup */
    signconf_cleanup(zone->signconf);
    zone->signconf = signconf_create();
    ods_log_assert(zone->signconf);

    /* task cleanup */
    task_cleanup(task);
    task = NULL;

    /* nsec3params cleanup */
    free((void*)salt);
    salt = NULL;

    ldns_rr_free(nsec3params_rr);
    nsec3params_rr = NULL;

    nsec3params_cleanup(nsec3params);
    nsec3params = NULL;

    /* zonedata cleanup */
    zone_cleanup_domains(zone);
    zone_cleanup_denials(zone);
    zone_init_domains(zone);
    zone_init_denials(zone);
    zone->inbound_serial = 0;
    zone->internal_serial = 0;
    zone->outbound_serial = 0;
    zone->initialized = 0;
    ods_log_assert(zone->domains);
    ods_log_assert(zone->denials);

    if (zone->stats) {
       lock_basic_lock(&zone->stats->stats_lock);
       stats_clear(zone->stats);
       lock_basic_unlock(&zone->stats->stats_lock);
    }
    return ODS_STATUS_ERR;
}
