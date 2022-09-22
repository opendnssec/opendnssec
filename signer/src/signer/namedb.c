/*
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
 * Domain name database.
 *
 */

#include "config.h"
#include "status.h"
#include "file.h"
#include "log.h"
#include "util.h"
#include "signer/backup.h"
#include "signer/namedb.h"
#include "signer/zone.h"

const char* db_str = "namedb";

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
 * Convert a denial to a tree node.
 *
 */
static ldns_rbnode_t*
denial2node(denial_type* denial)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) malloc(sizeof(ldns_rbnode_t));
    if (!node) {
        return NULL;
    }
    node->key = denial->dname;
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
 * Initialize denials.
 *
 */
void
namedb_init_denials(namedb_type* db)
{
    if (db) {
        db->denials = ldns_rbtree_create(domain_compare);
    }
}


/**
 * Initialize domains.
 *
 */
static void
namedb_init_domains(namedb_type* db)
{
    if (db) {
        db->domains = ldns_rbtree_create(domain_compare);
    }
}


/**
 * Create a new namedb.
 *
 */
namedb_type*
namedb_create(void* zone)
{
    namedb_type* db = NULL;
    zone_type* z = (zone_type*) zone;

    ods_log_assert(z);
    ods_log_assert(z->name);
    CHECKALLOC(db = (namedb_type*) malloc(sizeof(namedb_type)));
    if (!db) {
        ods_log_error("[%s] unable to create namedb for zone %s: "
            "allocator_alloc() failed", db_str, z->name);
        return NULL;
    }
    db->zone = zone;

    namedb_init_domains(db);
    if (!db->domains) {
        ods_log_error("[%s] unable to create namedb for zone %s: "
            "init domains failed", db_str, z->name);
        namedb_cleanup(db);
        return NULL;
    }
    namedb_init_denials(db);
    if (!db->denials) {
        ods_log_error("[%s] unable to create namedb for zone %s: "
            "init denials failed", db_str, z->name);
        namedb_cleanup(db);
        return NULL;
    }
    db->inbserial = 0;
    db->intserial = 0;
    db->outserial = 0;
    db->altserial = 0;
    db->is_initialized = 0;
    db->have_serial = 0;
    db->serial_updated = 0;
    db->force_serial = 0;
    return db;
}


/**
 * Internal lookup domain function.
 *
 */
static void*
namedb_domain_search(ldns_rbtree_t* tree, ldns_rdf* dname)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    if (!tree || !dname) {
        return NULL;
    }
    node = ldns_rbtree_search(tree, dname);
    if (node && node != LDNS_RBTREE_NULL) {
        return (void*) node->data;
    }
    return NULL;
}


static uint32_t
max(uint32_t a, uint32_t b)
{
    return (a<b?b:a);
}


/**
 * Determine new SOA SERIAL.
 *
 */
ods_status
namedb_update_serial(namedb_type* db, const char* zone_name, const char* format,
    uint32_t inbound_serial)
{
    uint32_t soa = 0;
    uint32_t prev = 0;
    uint32_t update = 0;
    if (!db || !format || !zone_name) {
        return ODS_STATUS_ASSERT_ERR;
    }
    prev = max(db->outserial, inbound_serial);
    if (!db->have_serial) {
        prev = inbound_serial;
    }
    ods_log_debug("[%s] zone %s update serial: format=%s in=%u internal=%u "
        "out=%u now=%u", db_str, zone_name, format, db->inbserial,
        db->intserial, db->outserial, (uint32_t) time_now());
    if (db->force_serial) {
        soa = db->altserial;
        if (!util_serial_gt(soa, prev)) {
            ods_log_warning("[%s] zone %s unable to enforce serial: %u does not "
                " increase %u. Serial set to %u", db_str, zone_name, soa, prev,
                (prev+1));
            soa = prev + 1;
        } else {
            ods_log_info("[%s] zone %s enforcing serial %u", db_str, zone_name,
                soa);
        }
        db->force_serial = 0;
    } else if (ods_strcmp(format, "unixtime") == 0) {
        soa = (uint32_t) time_now();
        if (!util_serial_gt(soa, prev)) {
            if (!db->have_serial) {
                ods_log_warning("[%s] zone %s unable to use unixtime as serial: "
                    "%u does not increase %u. Serial set to %u", db_str,
                    zone_name, soa, prev, (prev+1));
            }
            soa = prev + 1;
        }
    } else if (ods_strcmp(format, "datecounter") == 0) {
        soa = (uint32_t) time_datestamp(0, "%Y%m%d", NULL) * 100;
        if (!util_serial_gt(soa, prev)) {
            if (!db->have_serial) {
                ods_log_info("[%s] zone %s unable to use datecounter as "
                    "serial: %u does not increase %u. Serial set to %u", db_str,
                    zone_name, soa, prev, (prev+1));
            }
            soa = prev + 1;
        }
    } else if (ods_strcmp(format, "counter") == 0) {
        soa = inbound_serial + 1;
        if (db->have_serial && !util_serial_gt(soa, prev)) {
            soa = prev + 1;
        }
    } else if (ods_strcmp(format, "keep") == 0) {
        prev = db->outserial;
        soa = inbound_serial;
        if (db->have_serial && !util_serial_gt(soa, prev)) {
            ods_log_error("[%s] zone %s cannot keep SOA SERIAL from input zone "
                " (%u): previous output SOA SERIAL is %u", db_str, zone_name,
                soa, prev);
            return ODS_STATUS_CONFLICT_ERR;
        }
    } else {
        ods_log_error("[%s] zone %s unknown serial type %s", db_str, zone_name,
            format);
        return ODS_STATUS_ERR;
    }
    /* serial is stored in 32 bits */
    update = soa - prev;
    if (update > 0x7FFFFFFF) {
        update = 0x7FFFFFFF;
    }
    if (!db->have_serial) {
        db->intserial = soa;
    } else {
        db->intserial = prev + update; /* automatically does % 2^32 */
    }
    ods_log_debug("[%s] zone %s update serial: %u + %u = %u", db_str, zone_name,
        prev, update, db->intserial);
    return ODS_STATUS_OK;
}


/**
 * Add empty non-terminals for domain.
 *
 */
ods_status
namedb_domain_entize(namedb_type* db, domain_type* domain, ldns_rdf* apex)
{
    ldns_rdf* parent_rdf = NULL;
    domain_type* parent_domain = NULL;
    ods_log_assert(apex);
    ods_log_assert(domain);
    ods_log_assert(domain->dname);
    ods_log_assert(db);
    ods_log_assert(db->domains);
    if (domain->parent) {
        /* domain already has parent */
        return ODS_STATUS_OK;
    }

    while (domain && ldns_dname_is_subdomain(domain->dname, apex) &&
           ldns_dname_compare(domain->dname, apex) != 0) {
        /**
         * RFC5155:
         * 4. If the difference in number of labels between the apex and
         *    the original owner name is greater than 1, additional NSEC3
         *    RRs need to be added for every empty non-terminal between
         *     the apex and the original owner name.
         */
        parent_rdf = ldns_dname_left_chop(domain->dname);
        if (!parent_rdf) {
            ods_log_error("[%s] unable to entize domain: left chop failed",
                db_str);
            return ODS_STATUS_ERR;
        }
        parent_domain = namedb_lookup_domain(db, parent_rdf);
        if (!parent_domain) {
            parent_domain = namedb_add_domain(db, parent_rdf);
            ldns_rdf_deep_free(parent_rdf);
            if (!parent_domain) {
                ods_log_error("[%s] unable to entize domain: failed to add "
                    "parent domain", db_str);
                return ODS_STATUS_ERR;
            }
            domain->parent = parent_domain;
            /* continue with the parent domain */
            domain = parent_domain;
        } else {
            ldns_rdf_deep_free(parent_rdf);
            domain->parent = parent_domain;
            /* domain has parent, entize done */
            domain = NULL;
        }
    }
    return ODS_STATUS_OK;
}


/**
 * Lookup domain.
 *
 */
domain_type*
namedb_lookup_domain(namedb_type* db, ldns_rdf* dname)
{
    if (!db) {
        return NULL;
    }
    return (domain_type*) namedb_domain_search(db->domains, dname);
}


/**
 * Add domain to namedb.
 *
 */
domain_type*
namedb_add_domain(namedb_type* db, ldns_rdf* dname)
{
    domain_type* domain = NULL;
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;
    if (!dname || !db || !db->domains) {
        return NULL;
    }
    domain = domain_create(db->zone, dname);
    if (!domain) {
        ods_log_error("[%s] unable to add domain: domain_create() failed",
            db_str);
        return NULL;
    }
    new_node = domain2node(domain);
    if (!new_node) {
        ods_log_error("[%s] unable to add domain: domain2node() failed",
            db_str);
        return NULL;
    }
    if (ldns_rbtree_insert(db->domains, new_node) == NULL) {
        ods_log_error("[%s] unable to add domain: already present", db_str);
        log_dname(domain->dname, "ERR +DOMAIN", LOG_ERR);
        domain_cleanup(domain);
        free((void*)new_node);
        return NULL;
    }
    domain = (domain_type*) new_node->data;
    domain->node = new_node;
    domain->is_new = 1;
    log_dname(domain->dname, "+DOMAIN", LOG_DEEEBUG);
    return domain;
}


/**
 * Delete domain from namedb
 *
 */
domain_type*
namedb_del_domain(namedb_type* db, domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    if (!domain || !db || !db->domains) {
        ods_log_error("[%s] unable to delete domain: !db || !domain", db_str);
        return NULL;
    }
    if (domain->rrsets || domain->denial) {
        ods_log_error("[%s] unable to delete domain: domain in use", db_str);
        log_dname(domain->dname, "ERR -DOMAIN", LOG_ERR);
        return NULL;
    }
    node = ldns_rbtree_delete(db->domains, (const void*)domain->dname);
    if (node) {
        ods_log_assert(domain->node == node);
        ods_log_assert(!domain->rrsets);
        ods_log_assert(!domain->denial);
        free((void*)node);
        domain->node = NULL;
        log_dname(domain->dname, "-DOMAIN", LOG_DEEEBUG);
        return domain;
    }
    ods_log_error("[%s] unable to delete domain: not found", db_str);
    log_dname(domain->dname, "ERR -DOMAIN", LOG_ERR);
    return NULL;
}


/**
 * Lookup denial.
 *
 */
denial_type*
namedb_lookup_denial(namedb_type* db, ldns_rdf* dname)
{
    if (!db) {
        return NULL;
    }
    return (denial_type*) namedb_domain_search(db->denials, dname);
}


/**
 * See if a domain is an empty terminal
 *
 */
static int
domain_is_empty_terminal(domain_type* domain)
{
    ldns_rbnode_t* n = LDNS_RBTREE_NULL;
    domain_type* d = NULL;
    ods_log_assert(domain);
    if (domain->is_apex) {
        return 0;
    }
    if (domain->rrsets) {
        return 0;
    }
    n = ldns_rbtree_next(domain->node);
    if (n) {
        d = (domain_type*) n->data;
    }
    /* if it has children domains, do not delete it */
    if(d && ldns_dname_is_subdomain(d->dname, domain->dname)) {
        return 0;
    }
    return 1;
}


/**
 * See if a domain can be deleted
 *
 */
static int
domain_can_be_deleted(domain_type* domain)
{
    ods_log_assert(domain);
    return (domain_is_empty_terminal(domain) && !domain->denial);
}


/**
 * Add NSEC data point.
 *
 */
static void
namedb_add_nsec_trigger(namedb_type* db, domain_type* domain)
{
    ldns_rr_type dstatus = LDNS_RR_TYPE_FIRST;
    denial_type* denial = NULL;
    ods_log_assert(db);
    ods_log_assert(domain);
    ods_log_assert(!domain->denial);
    dstatus = domain_is_occluded(domain);
    if (dstatus == LDNS_RR_TYPE_DNAME || dstatus == LDNS_RR_TYPE_A) {
       return; /* don't do occluded/glue domain */
    }
    if (!domain->rrsets) {
       return; /* don't do empty domain */
    }
    /* ok, nsecify this domain */
    denial = namedb_add_denial(db, domain->dname, NULL);
    ods_log_assert(denial);
    denial->domain = (void*) domain;
    domain->denial = (void*) denial;
    domain->is_new = 0;
}


/**
 * Add NSEC3 data point.
 *
 */
static void
namedb_add_nsec3_trigger(namedb_type* db, domain_type* domain,
    nsec3params_type* n3p)
{
    ldns_rr_type dstatus = LDNS_RR_TYPE_FIRST;
    denial_type* denial = NULL;
    ods_log_assert(db);
    ods_log_assert(n3p);
    ods_log_assert(domain);
    ods_log_assert(!domain->denial);
    dstatus = domain_is_occluded(domain);
    if (dstatus == LDNS_RR_TYPE_DNAME || dstatus == LDNS_RR_TYPE_A) {
       return; /* don't do occluded/glue domain */
    }
    /* Opt-Out? */
    if (n3p->flags) {
        dstatus = domain_is_delegpt(domain);
        /* If Opt-Out is being used, owner names of unsigned delegations
           MAY be excluded. */
        if (dstatus == LDNS_RR_TYPE_NS) {
            return;
        }
    }
    /* ok, nsecify3 this domain */
    denial = namedb_add_denial(db, domain->dname, n3p);
    ods_log_assert(denial);
    denial->domain = (void*) domain;
    domain->denial = (void*) denial;
    domain->is_new = 0;
}


/**
 * See if denials need to be added.
 *
 */
static void
namedb_add_denial_trigger(namedb_type* db, domain_type* domain)
{
    zone_type* zone = NULL;
    ods_log_assert(db);
    ods_log_assert(domain);
    if (!domain->denial) {
        zone = domain->zone;
        ods_log_assert(zone);
        ods_log_assert(zone->signconf);
        if (!zone->signconf->passthrough) {
            if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC) {
                namedb_add_nsec_trigger(db, domain);
            } else {
                ods_log_assert(zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC3);
                namedb_add_nsec3_trigger(db, domain, zone->signconf->nsec3params);
            }
        }
    }
}


/**
 * Delete NSEC data point.
 *
 */
static void
namedb_del_nsec_trigger(namedb_type* db, domain_type* domain)
{
    ldns_rr_type dstatus = LDNS_RR_TYPE_FIRST;
    denial_type* denial = NULL;
    ods_log_assert(db);
    ods_log_assert(domain);
    ods_log_assert(domain->denial);
    dstatus = domain_is_occluded(domain);
    if (dstatus == LDNS_RR_TYPE_DNAME || dstatus == LDNS_RR_TYPE_A ||
        domain_is_empty_terminal(domain) || !domain->rrsets) {
       /* domain has become occluded/glue or empty non-terminal*/
       denial_diff((denial_type*) domain->denial);
       denial = namedb_del_denial(db, domain->denial);
       denial_cleanup(denial);
       domain->denial = NULL;
    }
}


/**
 * Delete NSEC3 data point.
 *
 */
static void
namedb_del_nsec3_trigger(namedb_type* db, domain_type* domain,
    nsec3params_type* n3p)
{
    ldns_rr_type dstatus = LDNS_RR_TYPE_FIRST;
    denial_type* denial = NULL;
    ods_log_assert(db);
    ods_log_assert(n3p);
    ods_log_assert(domain);
    ods_log_assert(domain->denial);
    dstatus = domain_is_occluded(domain);
    if (dstatus == LDNS_RR_TYPE_DNAME || dstatus == LDNS_RR_TYPE_A ||
        domain_is_empty_terminal(domain)) {
       /* domain has become occluded/glue */
       denial_diff((denial_type*) domain->denial);
       denial = namedb_del_denial(db, domain->denial);
       denial_cleanup(denial);
       domain->denial = NULL;
    } else if (n3p->flags) {
        dstatus = domain_is_delegpt(domain);
        /* If Opt-Out is being used, owner names of unsigned delegations
           MAY be excluded. */
        if (dstatus == LDNS_RR_TYPE_NS) {
            denial_diff((denial_type*) domain->denial);
            denial = namedb_del_denial(db, domain->denial);
            denial_cleanup(denial);
            domain->denial = NULL;
        }
    }
}


/**
 * See if domains/denials can be deleted.
 *
 */
static int
namedb_del_denial_trigger(namedb_type* db, domain_type* domain, int rollback)
{
    domain_type* parent = NULL;
    zone_type* zone = NULL;
    unsigned is_deleted = 0;
    ods_log_assert(db);
    ods_log_assert(domain);
    ods_log_assert(domain->dname);
    zone = domain->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->signconf);
    while(domain) {
        if (!rollback) {
            if (domain->denial) {
                if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC) {
                    namedb_del_nsec_trigger(db, domain);
                } else {
                    ods_log_assert(zone->signconf->nsec_type ==
                        LDNS_RR_TYPE_NSEC3);
                    namedb_del_nsec3_trigger(db, domain,
                        zone->signconf->nsec3params);
                }
            }
        }
        parent = domain->parent;
        if (domain_can_be_deleted(domain)) {
            /* -DOMAIN */
            domain = namedb_del_domain(db, domain);
            domain_cleanup(domain);
            is_deleted = 1;
        }
        /* continue with parent */
        domain = parent;
    }
    return is_deleted;
}


/**
 * Hash domain name.
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
        return NULL;
    }
    hashed_ownername = ldns_dname_cat_clone((const ldns_rdf*) hashed_label,
        (const ldns_rdf*) apex);
    if (!hashed_ownername) {
        return NULL;
    }
    ldns_rdf_deep_free(hashed_label);
    return hashed_ownername;
}


/**
 * Add denial to namedb.
 *
 */
denial_type*
namedb_add_denial(namedb_type* db, ldns_rdf* dname, nsec3params_type* n3p)
{
    zone_type* z = NULL;
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* pnode = LDNS_RBTREE_NULL;
    ldns_rdf* owner = NULL;
    denial_type* denial = NULL;
    denial_type* pdenial = NULL;

    ods_log_assert(db);
    ods_log_assert(db->denials);
    ods_log_assert(dname);
    /* nsec or nsec3 */
    if (n3p) {
        z = (zone_type*) db->zone;
        owner = dname_hash(dname, z->apex, n3p);
    } else {
        owner = ldns_rdf_clone(dname);
    }
    if (!owner) {
        ods_log_error("[%s] unable to add denial: create owner failed",
            db_str);
        return NULL;
    }
    denial = denial_create(db->zone, owner);
    if (!denial) {
        ods_log_error("[%s] unable to add denial: denial_create() failed",
            db_str);
        return NULL;
    }
    new_node = denial2node(denial);
    if (!new_node) {
        ods_log_error("[%s] unable to add denial: denial2node() failed",
            db_str);
        return NULL;
    }
    if (!ldns_rbtree_insert(db->denials, new_node)) {
        ods_log_error("[%s] unable to add denial: already present", db_str);
        log_dname(denial->dname, "ERR +DENIAL", LOG_ERR);
        denial_cleanup(denial);
        free((void*)new_node);
        return NULL;
    }
    /* denial of existence data point added */
    denial = (denial_type*) new_node->data;
    denial->node = new_node;
    denial->nxt_changed = 1;
    pnode = ldns_rbtree_previous(new_node);
    if (!pnode || pnode == LDNS_RBTREE_NULL) {
        pnode = ldns_rbtree_last(db->denials);
    }
    ods_log_assert(pnode);
    pdenial = (denial_type*) pnode->data;
    ods_log_assert(pdenial);
    pdenial->nxt_changed = 1;
    log_dname(denial->dname, "+DENIAL", LOG_DEEEBUG);
    return denial;
}


/**
 * Delete denial from namedb
 *
 */
denial_type*
namedb_del_denial(namedb_type* db, denial_type* denial)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* pnode = LDNS_RBTREE_NULL;
    denial_type* pdenial = NULL;

    if (!denial || !db || !db->denials) {
        return NULL;
    }
    if (denial->rrset && denial->rrset->rr_count) {
        ods_log_error("[%s] unable to delete denial: denial in use [#%lu]",
            db_str, (unsigned long)denial->rrset->rr_count);
        log_dname(denial->dname, "ERR -DENIAL", LOG_ERR);
        return NULL;
    }
    pnode = ldns_rbtree_previous(denial->node);
    if (!pnode || pnode == LDNS_RBTREE_NULL) {
        pnode = ldns_rbtree_last(db->denials);
    }
    ods_log_assert(pnode);
    pdenial = (denial_type*) pnode->data;
    ods_log_assert(pdenial);
    node = ldns_rbtree_delete(db->denials, (const void*)denial->dname);
    if (!node) {
        ods_log_error("[%s] unable to delete denial: not found", db_str);
        log_dname(denial->dname, "ERR -DENIAL", LOG_ERR);
        return NULL;
    }
    ods_log_assert(denial->node == node);
    pdenial->nxt_changed = 1;
    free((void*)node);
    denial->domain = NULL;
    denial->node = NULL;
    log_dname(denial->dname, "-DENIAL", LOG_DEEEBUG);
    return denial;
}


/**
 * Apply differences in db.
 *
 */
void
namedb_diff(namedb_type* db, unsigned is_ixfr, unsigned more_coming)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    if (!db || !db->domains) {
        return;
    }
    node = ldns_rbtree_first(db->domains);
    if (!node || node == LDNS_RBTREE_NULL) {
        return;
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        node = ldns_rbtree_next(node);
        domain_diff(domain, is_ixfr, more_coming);
    }
    node = ldns_rbtree_first(db->domains);
    if (!node || node == LDNS_RBTREE_NULL) {
        return;
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        node = ldns_rbtree_next(node);
        if (!namedb_del_denial_trigger(db, domain, 0)) {
            /* del_denial did not delete domain */
            namedb_add_denial_trigger(db, domain);
        }
    }
}


/**
 * Rollback differences in db.
 *
 */
void
namedb_rollback(namedb_type* db, unsigned keepsc)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    if (!db || !db->domains) {
        return;
    }
    node = ldns_rbtree_first(db->domains);
    if (!node || node == LDNS_RBTREE_NULL) {
        return;
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        node = ldns_rbtree_next(node);
        domain_rollback(domain, keepsc);
        (void) namedb_del_denial_trigger(db, domain, 1);
    }
}


/**
 * Nsecify db.
 *
 */
void
namedb_nsecify(namedb_type* db, uint32_t* num_added)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* nxt_node = LDNS_RBTREE_NULL;
    denial_type* denial = NULL;
    denial_type* nxt = NULL;
    uint32_t nsec_added = 0;
    ods_log_assert(db);
    node = ldns_rbtree_first(db->denials);
    while (node && node != LDNS_RBTREE_NULL) {
        denial = (denial_type*) node->data;
        nxt_node = ldns_rbtree_next(node);
        if (!nxt_node || nxt_node == LDNS_RBTREE_NULL) {
             nxt_node = ldns_rbtree_first(db->denials);
        }
        nxt = (denial_type*) nxt_node->data;
        denial_nsecify(denial, nxt, &nsec_added);
        node = ldns_rbtree_next(node);
    }
    if (num_added) {
        *num_added = nsec_added;
    }
}


/**
 * Examine updates to db.
 *
 */
ods_status
namedb_examine(namedb_type* db)
{
    ods_status status = ODS_STATUS_OK;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;
    int soa_seen = 0;
/*
    ldns_rr_type dstatus = LDNS_RR_TYPE_FIRST;
    ldns_rr_type delegpt = LDNS_RR_TYPE_FIRST;
*/

    if (!db || !db->domains) {
       /* no db, no error */
       return ODS_STATUS_OK;
    }
    if (db->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(db->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_CNAME);
        if (rrset) {
            /* Thou shall not have other data next to CNAME */
            if (domain_count_rrset_is_added(domain) > 1 &&
                rrset_count_rr_is_added(rrset) > 0) {
                log_rrset(domain->dname, rrset->rrtype,
                    "CNAME and other data at the same name", LOG_ERR);
                return ODS_STATUS_CONFLICT_ERR;
            }
            /* Thou shall have at most one CNAME per name */
            if (rrset_count_rr_is_added(rrset) > 1) {
                log_rrset(domain->dname, rrset->rrtype,
                    "multiple CNAMEs at the same name", LOG_ERR);
                return ODS_STATUS_CONFLICT_ERR;
            }
        }
        rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_DNAME);
        if (rrset) {
            /* Thou shall have at most one DNAME per name */
            if (rrset_count_rr_is_added(rrset) > 1) {
                log_rrset(domain->dname, rrset->rrtype,
                    "multiple DNAMEs at the same name", LOG_ERR);
                return ODS_STATUS_CONFLICT_ERR;
            }
        }
        if (!soa_seen && domain->is_apex) {
            rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_SOA);
            if (rrset) {
                /* Thou shall have one and only one SOA */
                if (rrset_count_rr_is_added(rrset) != 1) {
                    log_rrset(domain->dname, rrset->rrtype,
                        "Wrong number of SOA records, should be 1", LOG_ERR);
                    return ODS_STATUS_CONFLICT_ERR;
                }
            } else {
                log_rrset(domain->dname, LDNS_RR_TYPE_SOA, "missing SOA RRset",
                    LOG_ERR);
                return ODS_STATUS_CONFLICT_ERR;
            }
        }
/*
        dstatus = domain_is_occluded(domain);
        delegpt = domain_is_delegpt(domain);
*/
        /* Thou shall not have occluded data in your zone file */
        node = ldns_rbtree_next(node);
    }
    return status;
}


/**
 * Wipe out all NSEC RRsets.
 *
 */
void
namedb_wipe_denial(namedb_type* db)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    denial_type* denial = NULL;
    zone_type* zone = NULL;
    size_t i = 0;

    if (db && db->denials) {
        zone = (zone_type*) db->zone;
        ods_log_assert(zone);
        ods_log_assert(zone->name);
        ods_log_info("[%s] wipe denial of existence space zone %s", db_str,
            zone->name);
        node = ldns_rbtree_first(db->denials);
        while (node && node != LDNS_RBTREE_NULL) {
            denial = (denial_type*) node->data;
            if (!denial->rrset) {
                node = ldns_rbtree_next(node);
                continue;
            }
            for (i=0; i < denial->rrset->rr_count; i++) {
                if (denial->rrset->rrs[i].exists) {
                    /* ixfr -RR */
                    pthread_mutex_lock(&zone->ixfr->ixfr_lock);
                    if (zone->db->is_initialized) {
                        ixfr_del_rr(zone->ixfr, denial->rrset->rrs[i].rr);
                    }
                    pthread_mutex_unlock(&zone->ixfr->ixfr_lock);
                }
                denial->rrset->rrs[i].exists = 0;
                rrset_del_rr(denial->rrset, i);
                i--;
            }
            rrset_drop_rrsigs(zone, denial->rrset);
            rrset_cleanup(denial->rrset);
            denial->rrset = NULL;
            node = ldns_rbtree_next(node);
        }
    }
}

/**
 * Export db to file.
 *
 */
void
namedb_export(FILE* fd, namedb_type* db, ods_status* status)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    if (!fd || !db || !db->domains) {
        if (status) {
            ods_log_error("[%s] unable to export namedb: file descriptor "
                "or name database missing", db_str);
            *status = ODS_STATUS_ASSERT_ERR;
        }
        return;
    }
    node = ldns_rbtree_first(db->domains);
    if (!node || node == LDNS_RBTREE_NULL) {
        fprintf(fd, "; empty zone\n");
        if (status) {
            *status = ODS_STATUS_OK;
        }
        return;
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain) {
            domain_print(fd, domain, status);
        }
        node = ldns_rbtree_next(node);
    }
}


/**
 * Clean up domains in namedb.
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
}


/**
 * Clean up denials.
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
        domain = (domain_type*) denial->domain;
        if (domain) {
            domain->denial = NULL;
        }
        denial_cleanup(denial);
        free((void*)elem);
    }
}


/**
 * Clean up domains.
 *
 */
static void
namedb_cleanup_domains(namedb_type* db)
{
    if (db && db->domains) {
        domain_delfunc(db->domains->root);
        ldns_rbtree_free(db->domains);
        db->domains = NULL;
    }
}


/**
 * Clean up denials.
 *
 */
void
namedb_cleanup_denials(namedb_type* db)
{
    if (db && db->denials) {
        denial_delfunc(db->denials->root);
        ldns_rbtree_free(db->denials);
        db->denials = NULL;
    }
}


/**
 * Clean up namedb.
 *
 */
void
namedb_cleanup(namedb_type* db)
{
    zone_type* z = NULL;
    if (!db) {
        return;
    }
    z = (zone_type*) db->zone;
    if (!z) {
        return;
    }
    namedb_cleanup_denials(db);
    namedb_cleanup_domains(db);
    free(db);
}


/**
 * Backup namedb.
 *
 */
void
namedb_backup2(FILE* fd, namedb_type* db)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    denial_type* denial = NULL;
    if (!fd || !db) {
        return;
    }
    node = ldns_rbtree_first(db->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_backup2(fd, domain, 0);
        node = ldns_rbtree_next(node);
    }
    fprintf(fd, ";\n");
    node = ldns_rbtree_first(db->denials);
    while (node && node != LDNS_RBTREE_NULL) {
        denial = (denial_type*) node->data;
        if (denial->rrset) {
            rrset_print(fd, denial->rrset, 1, NULL);
        }
        node = ldns_rbtree_next(node);
    }
    fprintf(fd, ";\n");
    /* signatures */
    node = ldns_rbtree_first(db->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_backup2(fd, domain, 1);
        node = ldns_rbtree_next(node);
    }
    node = ldns_rbtree_first(db->denials);
    while (node && node != LDNS_RBTREE_NULL) {
        denial = (denial_type*) node->data;
        if (denial->rrset) {
            rrset_backup2(fd, denial->rrset);
        }
        node = ldns_rbtree_next(node);
    }
    fprintf(fd, ";\n");
}
