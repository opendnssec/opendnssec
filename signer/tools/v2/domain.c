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
#include "v2/domain.h"
#include "v2/se_malloc.h"

#include <ldns/ldns.h>


/**
 * Create empty domain.
 *
 */
domain_type*
domain_create(ldns_rdf* dname)
{
    domain_type* domain = (domain_type*) se_malloc(sizeof(domain_type));
    domain->name = ldns_rdf_clone(dname);
    domain->parent = NULL;
    domain->nsec3 = NULL;
    domain->auth_rrset = NULL;
    domain->ns_rrset = NULL;
    domain->ds_rrset = NULL;
    domain->nsec_rrset = NULL;
    domain->domain_status = DOMAIN_STATUS_NONE;
    return domain;
}


/**
 * Clean up domain.
 *
 */
void
domain_cleanup(domain_type* domain)
{
    if (domain) {
        ldns_rdf_deep_free(domain->name);
        if (domain->auth_rrset) {
            rrset_cleanup(domain->auth_rrset);
        }
        if (domain->ns_rrset) {
            rrset_cleanup(domain->ns_rrset);
        }
        if (domain->ds_rrset) {
            rrset_cleanup(domain->ds_rrset);
        }
        if (domain->nsec_rrset) {
            rrset_cleanup(domain->nsec_rrset);
        }
        /* don't destroy corresponding parent and nsec3 domain */
        se_free((void*) domain);
    }
}


/**
 * Add RR to domain.
 *
 */
int
domain_add_rr(domain_type* domain, ldns_rr* rr)
{
    ldns_rr_type rr_type = 0, type_covered = 0;

    rr_type = ldns_rr_get_type(rr);
    /* denial of existence */
    if (rr_type == LDNS_RR_TYPE_NSEC || rr_type == LDNS_RR_TYPE_NSEC3) {
        if (!domain->nsec_rrset) {
            domain->nsec_rrset = rrset_create(rr);
            return 0;
        }
        return rrset_add_rr(domain->nsec_rrset, rr);
    }

    /* delegation */
    if (rr_type == LDNS_RR_TYPE_NS &&
        domain->domain_status != DOMAIN_STATUS_APEX) {
        if (!domain->ns_rrset) {
            domain->ns_rrset = rrset_create(rr);
            return 0;
        }
        return rrset_add_rr(domain->ns_rrset, rr);
    }

    /* delegation signer */
    if (rr_type == LDNS_RR_TYPE_DS) {
        if (!domain->ds_rrset) {
            domain->ds_rrset = rrset_create(rr);
            return 0;
        }
        return rrset_add_rr(domain->ds_rrset, rr);
    }

    /* signature */
    if (rr_type == LDNS_RR_TYPE_RRSIG) {
        type_covered = ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rr));
        if (type_covered == LDNS_RR_TYPE_NSEC ||
            type_covered == LDNS_RR_TYPE_NSEC3) {
            return rrset_add_rr(domain->nsec_rrset, rr);
        } else {
            return rrset_add_rr(domain->auth_rrset, rr);
        }
    }

    /* authoritative */
    if (!domain->auth_rrset) {
        domain->auth_rrset = rrset_create(rr);
        return 0;
    }
    return rrset_add_rr(domain->auth_rrset, rr);
}


static void
domain_nsecify_create_bitmap(rrset_type* rrset, ldns_rr_type types[],
    size_t* types_count)
{
    rrset_type* cur_rrset = NULL;

    cur_rrset = rrset;
    while (cur_rrset) {
        types[*types_count] = cur_rrset->rr_type;
        *types_count = *types_count + 1;
        cur_rrset = cur_rrset->next;
    }

    return;
}


/**
 * Add NSEC to domain.
 *
 */
int
domain_nsecify_nsec(domain_type* domain, domain_type* to,
    uint32_t ttl, ldns_rr_class klass)
{
    ldns_rr_type types[1024];
    ldns_rr* nsec_rr = NULL;
    size_t types_count = 0;
    int result = 0;

    /* create types bitmap */
    domain_nsecify_create_bitmap(domain->auth_rrset, types, &types_count);
    domain_nsecify_create_bitmap(domain->ds_rrset, types, &types_count);
    domain_nsecify_create_bitmap(domain->ns_rrset, types, &types_count);
    types[types_count] = LDNS_RR_TYPE_RRSIG;
    types_count++;
    types[types_count] = LDNS_RR_TYPE_NSEC;
    types_count++;

    nsec_rr = ldns_rr_new();
    ldns_rr_set_type(nsec_rr, LDNS_RR_TYPE_NSEC);
    ldns_rr_set_owner(nsec_rr, ldns_rdf_clone(domain->name));
    ldns_rr_push_rdf(nsec_rr, ldns_rdf_clone(to->name));
    ldns_rr_push_rdf(nsec_rr, ldns_dnssec_create_nsec_bitmap(types,
        types_count, LDNS_RR_TYPE_NSEC));

    ldns_rr_set_ttl(nsec_rr, ttl);
    ldns_rr_set_class(nsec_rr, klass);

    if (domain->nsec_rrset) {
        rrset_cleanup(domain->nsec_rrset);
    }
    domain->nsec_rrset = rrset_create(nsec_rr);

    return result;
}


/**
 * Add NSEC3 to domain.
 *
 */
int
domain_nsecify_nsec3(domain_type* domain, domain_type* to,
    uint32_t ttl, ldns_rr_class klass, nsec3params_type* nsec3params)
{
    ldns_status status = LDNS_STATUS_OK;
    ldns_rr* nsec_rr = NULL;
    ldns_rr_type types[1024];
    size_t types_count = 0;
    int result = 0, i = 0;
    ldns_rdf* next_owner_label = NULL;
    ldns_rdf* next_owner_rdf = NULL;
    char* next_owner_string = NULL;

    /* create types bitmap */
    domain_nsecify_create_bitmap(domain->auth_rrset, types, &types_count);
    domain_nsecify_create_bitmap(domain->ds_rrset, types, &types_count);
    domain_nsecify_create_bitmap(domain->ns_rrset, types, &types_count);
    types[types_count] = LDNS_RR_TYPE_RRSIG;
    types_count++;
    types[types_count] = LDNS_RR_TYPE_NSEC3;
    types_count++;

    nsec_rr = ldns_rr_new();
    ldns_rr_set_type(nsec_rr, LDNS_RR_TYPE_NSEC3);

    domain = domain->nsec3;
    ldns_rr_set_owner(nsec_rr, ldns_rdf_clone(domain->name));
    /* either set all to NULL first, or push rdata elements immediately
       and skip nsec3_add_param_rdfs. */
    for (i=0; i < 4; i++) {
        ldns_rr_push_rdf(nsec_rr, NULL);
    }
    ldns_nsec3_add_param_rdfs(nsec_rr, nsec3params->algorithm,
        nsec3params->flags, nsec3params->iterations, nsec3params->salt_len,
        nsec3params->salt_data);

    next_owner_label = ldns_dname_label(to->name, 0);
    next_owner_string = ldns_rdf2str(next_owner_label);
    if (next_owner_string[strlen(next_owner_string)-1] == '.') {
        next_owner_string[strlen(next_owner_string)-1] = '\0';
    }
    status = ldns_str2rdf_b32_ext(&next_owner_rdf, next_owner_string);

    se_free((void*)next_owner_string);
    ldns_rdf_deep_free(next_owner_label);
    if (status != LDNS_STATUS_OK) {
        fprintf(stderr, "failed to create NSEC3 next owner name: %s\n",
            ldns_get_errorstr_by_id(status));
        ldns_rr_free(nsec_rr);
        return 1;
    }

    ldns_rr_push_rdf(nsec_rr, next_owner_rdf);
    ldns_rr_push_rdf(nsec_rr, ldns_dnssec_create_nsec_bitmap(types,
        types_count, LDNS_RR_TYPE_NSEC3));

    ldns_rr_set_ttl(nsec_rr, ttl);
    ldns_rr_set_class(nsec_rr, klass);

    if (domain->nsec_rrset) {
        rrset_cleanup(domain->nsec_rrset);
    }
    domain->nsec_rrset = rrset_create(nsec_rr);

    return result;
}


static char*
status2str(int status)
{
    switch (status) {
        case DOMAIN_STATUS_NONE:
            return "none";
        case DOMAIN_STATUS_APEX:
            return "apex";
        case DOMAIN_STATUS_AUTH:
            return "authoritative";
        case DOMAIN_STATUS_NS:
            return "delegation";
        case DOMAIN_STATUS_ENT_NS:
            return "empty non-ternminal to unsigned delegation";
        case DOMAIN_STATUS_ENT_AUTH:
            return "empty non-terminal";
        case DOMAIN_STATUS_ENT_GLUE:
            return "empty non-terminal to glue";
        case DOMAIN_STATUS_OCCLUDED:
            return "glue";
    }
    return "unknown status";
}

/**
 * Print domain.
 *
 */
void
domain_print(FILE* fd, domain_type* domain, int skip_soa)
{
    char* str = NULL;

    if (domain) {
        if (domain->domain_status == DOMAIN_STATUS_APEX ||
            domain->domain_status == DOMAIN_STATUS_AUTH) {
            rrset_print(fd, domain->auth_rrset, NULL, 1, 0, skip_soa);
            rrset_print(fd, domain->nsec_rrset, NULL, 1, 0, skip_soa);
        } else if (domain->domain_status == DOMAIN_STATUS_NS) {
            rrset_print(fd, domain->ns_rrset, NULL, 1, 0, skip_soa);
            rrset_print(fd, domain->ds_rrset, NULL, 1, 0, skip_soa);
            rrset_print(fd, domain->nsec_rrset, NULL, 1, 0, skip_soa);
        } else if (domain->domain_status == DOMAIN_STATUS_OCCLUDED) {
            rrset_print(fd, domain->auth_rrset, NULL, 1, 1, skip_soa);
        }

        if (domain->nsec3) {
            if (!skip_soa) {
                str = ldns_rdf2str(domain->nsec3->name);
                fprintf(fd, "; $NSEC3 %s\n", str);
                se_free((void*)str);
            }
            rrset_print(fd, domain->nsec3->nsec_rrset, NULL, 1, 0, skip_soa);
        }
        fprintf(fd, "\n");
    }
}
