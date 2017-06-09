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
#include "signer/names.h"

const char* db_str = "namedb";

/**
 * Determine new SOA SERIAL.
 *
 */
ods_status
namedb_update_serial(zone_type* db, const char* zone_name, const char* format,
    uint32_t inbound_serial)
{
    uint32_t soa = 0;
    if (!db || !format || !zone_name) {
        return ODS_STATUS_ASSERT_ERR;
    }
    if (db->nextserial) {
        soa = *db->nextserial;
        free(db->nextserial);
        db->nextserial = NULL;
    } else if (ods_strcmp(format, "unixtime") == 0) {
        soa = (uint32_t) time_now();
    } else if (ods_strcmp(format, "datecounter") == 0) {
        soa = (uint32_t) time_datestamp(0, "%Y%m%d", NULL) * 100;
    } else if (ods_strcmp(format, "counter") == 0) {
        soa = inbound_serial + 1;
        if (db->outboundserial && !util_serial_gt(soa, *db->outboundserial)) {
            soa = *db->outboundserial + 1;
        }
    } else if (ods_strcmp(format, "keep") == 0) {
        soa = inbound_serial;
    } else {
        ods_log_error("[%s] zone %s unknown serial type %s", db_str, zone_name,
            format);
        return ODS_STATUS_ERR;
    }
    if(db->outboundserial) {
        free(db->outboundserial);
    }
    db->outboundserial = malloc(sizeof(uint32_t));
    *db->outboundserial = soa;
    return ODS_STATUS_OK;
}


/**
 * Add empty non-terminals for domain.
 *
 */
ods_status
namedb_domain_entize(names_view_type view, domain_type* domain, ldns_rdf* apex)
{
    ldns_rdf* parent_rdf = NULL;
    domain_type* parent_domain;
    ods_log_assert(apex);
    ods_log_assert(domain);
    ods_log_assert(domain->dname);
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
        parent_domain = names_lookupname(view, parent_rdf);
        if (!parent_domain) {
            parent_domain = names_addname(view, parent_rdf);
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
    /* has children */
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
namedb_add_denial(zone_type* zone, names_view_type view, ldns_rdf* dname)
{
    denial_type* denial;
    denial = denial_create(zone, namedb_denialname(zone, dname));
    denial->changed = 1;
    /* BERRY mark previous node changed */
    return denial;
}

ldns_rdf*
namedb_denialname(zone_type* zone, ldns_rdf* dname)
{
    if (zone->signconf->nsec3params) {
        return dname_hash(dname, zone->apex, zone->signconf->nsec3params);
    } else {
        return ldns_rdf_clone(dname);
    }   
}


/**
 * Nsecify db.
 *
 */
void
namedb_nsecify(zone_type* zone, names_view_type view, uint32_t* num_added)
{
    domain_type* domain;
    names_iterator iter;
    ldns_rdf* firstname;
    ldns_rdf* nextname;
    uint32_t nsec_added = 0;
    
    names_firstdenials(view,&iter);
    if (names_iterate(&iter,&domain)) {
        nextname = firstname = namedb_denialname(zone, domain->dname);
        names_end(&iter);
        for (names_reversedenials(view,&iter); names_iterate(&iter,&domain); names_advance(&iter, NULL)) {
            denial_nsecify(zone, view, domain, nextname, &nsec_added);
            nextname = domain->denial->dname;
        }
        ldns_rdf_free(firstname);
    } else {
        names_end(&iter);
    }
    if (num_added) {
        *num_added = nsec_added;
    }
}


/**
 * Wipe out all NSEC RRsets.
 *
 */
void
namedb_wipe_denial(zone_type* zone, names_view_type view)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    denial_type* denial = NULL;
    size_t i = 0;
    names_iterator iter;

        ods_log_assert(zone);
        ods_log_assert(zone->name);
        ods_log_debug("[%s] wipe denial of existence space zone %s", db_str,
            zone->name);
        for(names_reversedenials(view,&iter); names_iterate(&iter,&denial); names_advance(&iter, NULL)) {
          if (denial->rrset) {
            for (i=0; i < denial->rrset->rr_count; i++) {
                rrset_del_rr(denial->rrset, i);
                i--;
            }
            rrset_drop_rrsigs(zone, denial->rrset);
            rrset_cleanup(denial->rrset);
            denial->rrset = NULL;
          }
        }
}

/**
 * Export db to file.
 *
 */
void
namedb_export(FILE* fd, names_view_type view, ods_status* status)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    names_iterator iter;
    if (!fd) {
        if (status) {
            ods_log_error("[%s] unable to export namedb: file descriptor "
                "or name database missing", db_str);
            *status = ODS_STATUS_ASSERT_ERR;
        }
        return;
    }
    names_alldomains(view,&iter);
    if(names_iterate(&iter,&domain)) {
        do {
            domain_print(fd, domain, status);            
        } while(names_advance(&iter,&domain));
    } else {
        if (status) {
            *status = ODS_STATUS_OK;
        }
        fprintf(fd, "; empty zone\n");
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
        denial_cleanup(denial);
        free((void*)elem);
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
    free(db);
}
