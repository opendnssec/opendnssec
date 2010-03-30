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
#include "v2/zonedata.h"
#include "v2/domain.h"
#include "v2/se_malloc.h"

#include <ldns/ldns.h>


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
    zd->nsec3_domains = NULL;
    return zd;
}


/**
 * Convert a domain to a tree node.
 *
 */
static ldns_rbnode_t*
domain2node(domain_type* domain)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) se_malloc(sizeof(ldns_rbnode_t));
    node->key = domain->name;
    node->data = domain;
    return node;
}


/**
 * Add a domain to the zone data.
 *
 */
domain_type*
zonedata_add_domain(zonedata_type* zd, domain_type* domain, int at_apex)
{
    ldns_rbnode_t* new_node = NULL;
    char* str = NULL;

    new_node = domain2node(domain);
    if (ldns_rbtree_insert(zd->domains, new_node) == NULL) {
        str = ldns_rdf2str(domain->name);
        fprintf(stderr, "unable to add domain '%s'\n", str);
        se_free((void*)str);
        se_free((void*)new_node);
        return NULL;
    }
    domain->domain_status = DOMAIN_STATUS_NONE;
    if (at_apex) {
        domain->domain_status = DOMAIN_STATUS_APEX;
    }
    return domain;
}


/**
 * Add a NSEC3 domain to the zone data.
 *
 */
domain_type*
zonedata_add_nsec3domain(zonedata_type* zd, domain_type* domain, nsec3params_type* nsec3params,
    ldns_rdf* apex)
{
    ldns_rbnode_t* node = NULL, *new_node = NULL;
    domain_type* dname = NULL;
    ldns_rdf* hashed_ownername = NULL, *hashed_label = NULL;
    char* str = NULL;

    /**
     * The owner name of the NSEC3 RR is the hash of the original owner
       name, prepended as a single label to the zone name.
    **/
    hashed_label = ldns_nsec3_hash_name(domain->name,
        nsec3params->algorithm, nsec3params->iterations,
        nsec3params->salt_len, nsec3params->salt_data);
    hashed_ownername = ldns_dname_cat_clone(
        (const ldns_rdf*) hashed_label,
        (const ldns_rdf*) apex);
    ldns_rdf_deep_free(hashed_label);

    node = ldns_rbtree_search(zd->nsec3_domains, hashed_ownername);
    if (!node) {
        dname = domain_create(hashed_ownername);
        ldns_rdf_deep_free(hashed_ownername);

        new_node = domain2node(dname);
        if (!ldns_rbtree_insert(zd->nsec3_domains, new_node)) {
            str = ldns_rdf2str(dname->name);
            fprintf(stderr, "unable to add NSEC3 domain '%s'\n", str);
            se_free((void*)str);
            se_free((void*)new_node);
            domain_cleanup(dname);
            return NULL;
        }

        return dname;
    } else {
        str = ldns_rdf2str(hashed_ownername);
        ldns_rdf_deep_free(hashed_ownername);
        fprintf(stderr, "unable to add NSEC3 domain '%s' (has collision?)\n", str);
        se_free((void*)str);
    }

    return NULL;
}


/**
 * Add a domain to the zone data.
 *
 */
int
zonedata_add_rr(zonedata_type* zd, ldns_rr* rr, int at_apex)
{
    domain_type* domain = NULL, *domain2 = NULL;
    int result = 0;

    domain = domain_create(ldns_rr_owner(rr));
    domain2 = zonedata_lookup_domain(zd, domain);
    if (domain2) {
        domain_cleanup(domain);
    } else {
        domain2 = zonedata_add_domain(zd, domain, at_apex);
        if (!domain2) {
            domain_cleanup(domain);
            return 1;
        }
    }

    result = domain_add_rr(domain2, rr);
    return result;
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
        if (parent->domain_status == DOMAIN_STATUS_ENT_NS ||
            parent->domain_status == DOMAIN_STATUS_ENT_AUTH) {
            parent->domain_status = status;
        } else {
           break;
        }
        parent = parent->parent;
    }
    return;
}

/**
 * Add empty non-terminals to the zone.
 *
 */
static int
zonedata_domain_entize(zonedata_type* zd, domain_type* domain, ldns_rdf* apex)
{
    int unsigned_deleg = 0;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rdf* parent_rdf = NULL;
    domain_type* parent_domain = NULL;

    if (domain->parent) {
        /* domain already has parent */
        return 0;
    }

    if (!rrset_covers_rrtype(domain->auth_rrset, LDNS_RR_TYPE_DS) &&
        domain->ns_rrset) {
        /* ent to unsigned delegation? */
        unsigned_deleg = 1;
    }

    while (domain && ldns_dname_compare(domain->name, apex) != 0) {
        /**
         * RFC5155:
         * 4. If the difference in number of labels between the apex and
         *    the original owner name is greater than 1, additional NSEC3
         *    RRs need to be added for every empty non-terminal between
         *     the apex and the original owner name.
        **/
        parent_rdf = ldns_dname_left_chop(domain->name);
        if (!parent_rdf) {
            fprintf(stderr, "unable to create parent domain name (rdf)\n");
            return 1;
        }

        node = ldns_rbtree_search(zd->domains, parent_rdf);
        if (!node) {
            parent_domain = domain_create(parent_rdf);
            parent_domain = zonedata_add_domain(zd, parent_domain, 0);
            if (!parent_domain) {
                fprintf(stderr, "unable to add parent domain\n");
                return 1;
            }

            parent_domain->domain_status =
                (unsigned_deleg?DOMAIN_STATUS_ENT_NS:DOMAIN_STATUS_ENT_AUTH);
            domain->parent = parent_domain;
            /* continue with the parent domain */
            domain = parent_domain;
        } else {
            ldns_rdf_deep_free(parent_rdf);
            parent_domain = (domain_type*) node->data;
            domain->parent = parent_domain;
            if (parent_domain->domain_status == DOMAIN_STATUS_NONE) {
                if (!parent_domain->auth_rrset && !parent_domain->ns_rrset) {
                    parent_domain->domain_status =
                        (unsigned_deleg?DOMAIN_STATUS_ENT_NS:DOMAIN_STATUS_ENT_AUTH);
                }
            }
            /* done */
            domain = NULL;
        }
    }
    return 0;
}


static void
calculate_domain_status(domain_type* domain)
{
    domain_type* parent = NULL;

    if (domain->domain_status == DOMAIN_STATUS_APEX) {
        return;
    }

    if (!domain->auth_rrset && !domain->ds_rrset && !domain->ns_rrset) {
        /* Empty Non-Terminal */
        return; /* we don't care */
    }

    if (domain->ns_rrset) {
        domain->domain_status = DOMAIN_STATUS_NS;
        return;
    }

    parent = domain->parent;
    while (parent) {
        if (rrset_covers_rrtype(parent->auth_rrset,
            LDNS_RR_TYPE_DNAME) ||
            parent->ns_rrset) {
            domain->domain_status = DOMAIN_STATUS_OCCLUDED;
            zonedata_domain_entize_revised(domain, DOMAIN_STATUS_ENT_GLUE);
            return;
        }
        parent = parent->parent;
    }
    domain->domain_status = DOMAIN_STATUS_AUTH;
    return;
}

static int
domain_is_occluded(domain_type* domain)
{
    return (domain->domain_status == DOMAIN_STATUS_OCCLUDED ||
            domain->domain_status == DOMAIN_STATUS_NONE);
}


static int
domain_is_empty(domain_type* domain)
{
    return (domain->domain_status == DOMAIN_STATUS_ENT_NS ||
            domain->domain_status == DOMAIN_STATUS_ENT_AUTH ||
            domain->domain_status == DOMAIN_STATUS_ENT_GLUE);
}


/**
 * Add empty non-terminals to the zone data.
 *
 */
int
zonedata_entize(zonedata_type* zd, ldns_rdf* apex)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;

        if (zonedata_domain_entize(zd, domain, apex) != 0) {
            fprintf(stderr, "zonedata_domain_entize() failed\n");
            return 1;
        }

        /* domain has parent now, check for glue */
        calculate_domain_status(domain);

        node = ldns_rbtree_next(node);
    }

    return 0;
}


/**
 * Add NSEC records to zone data.
 *
 */
int
zonedata_nsecify_nsec(zonedata_type* zd, uint32_t ttl,
    ldns_rr_class klass)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL, *to = NULL, *apex = NULL;
    int have_next = 0;

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain->domain_status == DOMAIN_STATUS_APEX) {
            apex = domain;
        }

        /* don't do glue-only or empty domains */
        if (domain_is_occluded(domain) ||
            domain_is_empty(domain)) {
            node = ldns_rbtree_next(node);
            continue;
        }
        /* domain status = apex / auth / ns */

        node = ldns_rbtree_next(node);
        have_next = 0;
        while (!have_next) {
            if (node != LDNS_RBTREE_NULL) {
                to = (domain_type*) node->data;
            } else if (apex) {
                to = apex;
            } else {
                return 1;
            }
            /* don't do glue-only or empty domains */
            if (!domain_is_occluded(to) &&
                !domain_is_empty(to)) {
                have_next = 1;
            } else {
                node = ldns_rbtree_next(node);
            }
        }

        if (domain_nsecify_nsec(domain, to, ttl, klass) != 0) {
            fprintf(stderr, "adding NSECs to domain failed\n");
            return 1;
        }
    }

    return 0;
}


/**
 * Add NSEC3 records to zone data.
 *
 */
int
zonedata_nsecify_nsec3(zonedata_type* zd, uint32_t ttl,
    ldns_rr_class klass, nsec3params_type* nsec3params)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* nsec3_node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL, *to = NULL, *apex = NULL;
    char* str = NULL;

    if (zd->nsec3_domains) {
        zonedata_cleanup_domains(zd->nsec3_domains);
    }
    zd->nsec3_domains = ldns_rbtree_create(domain_compare);

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain->domain_status == DOMAIN_STATUS_APEX) {
            apex = domain;
        }
        /* don't do glue-only domains */
        if (domain_is_occluded(domain)) {
            node = ldns_rbtree_next(node);
            continue;
        }

        /* Opt-Out? */
        if (nsec3params->flags) {
            /* If Opt-Out is being used, owner names of unsigned delegations
               MAY be excluded. */
            if (domain->domain_status == DOMAIN_STATUS_NS && !domain->ds_rrset) {
                node = ldns_rbtree_next(node);
                continue;
            }
            if (domain->domain_status == DOMAIN_STATUS_ENT_NS) {
                node = ldns_rbtree_next(node);
                continue;
            }
            if (domain->domain_status == DOMAIN_STATUS_ENT_GLUE ||
                domain->domain_status == DOMAIN_STATUS_OCCLUDED) {
                node = ldns_rbtree_next(node);
                continue;
            }
        }

        if (!apex) {
            fprintf(stderr, "failed to create NSEC3 chain: apex not found\n");
            return 1;
        }

        /* Sort the set of NSEC3 RRs into hash order. */
        domain->nsec3 = zonedata_add_nsec3domain(zd, domain, nsec3params, apex->name);
        if (domain->nsec3 == NULL) {
            str = ldns_rdf2str(domain->name);
            fprintf(stderr, "failed to create NSEC3 domain '%s'\n", str);
            se_free((void*) str);
            return 1;
        }
        domain->nsec3->nsec3 = domain;

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
         * domain->nsec3_wildcard = domain_create(hashed_ownername);
        **/

        node = ldns_rbtree_next(node);
    }

    /**
     * In each NSEC3 RR, insert the next hashed owner name by using the
     * value of the next NSEC3 RR in hash order.  The next hashed owner
     * name of the last NSEC3 RR in the zone contains the value of the
     * hashed owner name of the first NSEC3 RR in the hash order.
    **/
    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (!domain->nsec3) {
            node = ldns_rbtree_next(node);
            continue;
        }
        nsec3_node = ldns_rbtree_search(zd->nsec3_domains,
            domain->nsec3->name);

        if (nsec3_node && nsec3_node != LDNS_RBTREE_NULL) {
            nsec3_node = ldns_rbtree_next(nsec3_node);
        }
        if (!nsec3_node || nsec3_node == LDNS_RBTREE_NULL) {
            nsec3_node = ldns_rbtree_first(zd->nsec3_domains);
        }

        to = (domain_type*) nsec3_node->data;
        if (domain_nsecify_nsec3(domain, to, ttl, klass, nsec3params) != 0) {
            fprintf(stderr, "adding NSECs to domain failed\n");
            return 1;
        }

        node = ldns_rbtree_next(node);
    }
    return 0;
}


/**
 * Lookup domain.
 *
 */
domain_type*
zonedata_lookup_domain(zonedata_type* zd, domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;

    node = ldns_rbtree_search(zd->domains, domain->name);
    if (node && node != LDNS_RBTREE_NULL) {
        return (domain_type*) node->data;
    }
    return NULL;
}


/**
 * Clean up domains in zone data.
 *
 */
void
zonedata_cleanup_domains(ldns_rbtree_t* domain_tree)
{
    ldns_rbnode_t* node = NULL;
    domain_type* name = NULL;

    node = ldns_rbtree_first(domain_tree);
    while (node && node != LDNS_RBTREE_NULL) {
        name = (domain_type*) node->data;
        domain_cleanup(name);
        node = ldns_rbtree_next(node);
    }
    se_rbnode_free(domain_tree->root);
    ldns_rbtree_free(domain_tree);
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
        }
        if (zonedata->nsec3_domains) {
            zonedata_cleanup_domains(zonedata->nsec3_domains);
        }

        se_free((void*) zonedata);
    }
}


/**
 * Print zone data.
 *
 */
void
zonedata_print(FILE* fd, zonedata_type* zonedata)
{
    ldns_rbnode_t* node = NULL;
    domain_type* name = NULL;

    if (zonedata && zonedata->domains) {
        while (node && node != LDNS_RBTREE_NULL) {
           fprintf(fd, "; domain\n");
            name = (domain_type*) node->data;
            domain_print(fd, name, 1);
            node = ldns_rbtree_next(node);
        }
    }
}
