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
 * Domain.
 *
 */

#include "config.h"
#include "log.h"
#include "signer/backup.h"
#include "signer/denial.h"
#include "signer/domain.h"
#include "signer/ixfr.h"
#include "signer/zone.h"

static const char* dname_str = "domain";


/**
 * Log domain name.
 *
 */
void
log_dname(ldns_rdf *rdf, const char* pre, int level)
{
    char* str = NULL;
    if (ods_log_get_level() < level) {
        return;
    }
    str = ldns_rdf2str(rdf);
    if (!str) {
        return;
    }
    if (level == LOG_EMERG) {
        ods_fatal_exit("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_ALERT) {
        ods_log_alert("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_CRIT) {
        ods_log_crit("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_ERR) {
        ods_log_error("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_WARNING) {
        ods_log_warning("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_NOTICE) {
        ods_log_info("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_INFO) {
        ods_log_verbose("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_DEBUG) {
        ods_log_debug("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_DEEEBUG) {
        ods_log_deeebug("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else {
        ods_log_deeebug("[%s] %s: %s", dname_str, pre?pre:"", str);
    }
    free((void*)str);
}


/**
 * Create domain.
 *
 */
domain_type*
domain_create(ldns_rdf* dname)
{
    domain_type* domain = NULL;
    if (!dname) {
        return NULL;
    }
    CHECKALLOC(domain = (domain_type*) malloc(sizeof(domain_type)));
    domain->dname = ldns_rdf_clone(dname);
    if (!domain->dname) {
        ods_log_error("[%s] unable to create domain: ldns_rdf_clone() "
            "failed", dname_str);
        free(domain);
        return NULL;
    }
    domain->denial = NULL; /* no reference yet */
    domain->rrsets = NULL;
    domain->parent = NULL;
    domain->is_apex = 0;
    return domain;
}


/**
 * Look up RRset at this domain.
 *
 */
rrset_type*
domain_lookup_rrset(domain_type* domain, ldns_rr_type rrtype)
{
    rrset_type* rrset = NULL;
    if (!domain || !domain->rrsets || !rrtype) {
        return NULL;
    }
    rrset = domain->rrsets;
    while (rrset && rrset->rrtype != rrtype) {
        rrset = rrset->next;
    }
    return rrset;
}


/**
 * Add RRset to domain.
 *
 */
void
domain_add_rrset(domain_type* domain, rrset_type* rrset)
{
    rrset_type** p = NULL;
    denial_type* denial = NULL;
    ods_log_assert(domain);
    ods_log_assert(rrset);
    if (!domain->rrsets) {
        domain->rrsets = rrset;
    } else {
        p = &domain->rrsets;
        while(*p) {
            p = &((*p)->next);
        }
        *p = rrset;
        rrset->next = NULL;
    }
    log_rrset(domain->dname, rrset->rrtype, "+RRSET", LOG_DEEEBUG);
    if (domain->denial) {
        denial = (denial_type*) domain->denial;
        denial->changed = 1;
    }
}


/**
 * Check whether the domain is a delegation point.
 *
 */
ldns_rr_type
domain_is_delegpt(names_view_type view, domain_type* domain)
{
    ods_log_assert(domain);
    if (domain->is_apex) {
        return LDNS_RR_TYPE_SOA;
    }
    if (domain_lookup_rrset(domain, LDNS_RR_TYPE_NS)) {
        if (domain_lookup_rrset(domain, LDNS_RR_TYPE_DS)) {
            /* Signed delegation */
            return LDNS_RR_TYPE_DS;
        } else {
            /* Unsigned delegation */
            return LDNS_RR_TYPE_NS;
        }
    }
    /* Authoritative */
    return LDNS_RR_TYPE_SOA;
}


/**
 * Check whether the domain is occluded.
 *
 */
ldns_rr_type
domain_is_occluded(names_view_type view, domain_type* domain)
{
    names_iterator iter;
    domain_type* parent = NULL;
    ods_log_assert(domain);
    if (domain->is_apex) {
        return LDNS_RR_TYPE_SOA;
    }
    for(names_parentdomains(view,domain,&iter); names_iterate(&iter, &parent); names_advance(&iter,NULL)) {
        if (domain_lookup_rrset(parent, LDNS_RR_TYPE_NS)) {
            /* Glue / Empty non-terminal to Glue */
            names_end(&iter);
            return LDNS_RR_TYPE_A;
        }
        if (domain_lookup_rrset(parent, LDNS_RR_TYPE_DNAME)) {
            /* Occluded data / Empty non-terminal to Occluded data */
            names_end(&iter);
            return LDNS_RR_TYPE_DNAME;
        }
    }
    /* Authoritative or delegation */
    return LDNS_RR_TYPE_SOA;
}


/**
 * Print domain.
 *
 */
void
domain_print(FILE* fd, domain_type* domain, ods_status* status)
{
    char* str = NULL;
    rrset_type* rrset = NULL;
    rrset_type* soa_rrset = NULL;
    rrset_type* cname_rrset = NULL;
    if (!domain || !fd) {
        if (status) {
            ods_log_crit("[%s] unable to print domain: domain or fd missing",
                dname_str);
            *status = ODS_STATUS_ASSERT_ERR;
        }
        return;
    }
    /* empty non-terminal? */
    if (!domain->rrsets) {
        str = ldns_rdf2str(domain->dname);
        fprintf(fd, ";;Empty non-terminal %s\n", str);
        free((void*)str);
        /* Denial of Existence */
        if (domain->denial) {
            denial_print(fd, (denial_type*) domain->denial, status);
        }
        return;
    }
    /* no other data may accompany a CNAME */
    cname_rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_CNAME);
    if (cname_rrset) {
        rrset_print(fd, cname_rrset, 0, status);
    } else {
        /* if SOA, print soa first */
        if (domain->is_apex) {
            soa_rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_SOA);
            if (soa_rrset) {
                rrset_print(fd, soa_rrset, 0, status);
                if (status && *status != ODS_STATUS_OK) {
                    return;
                }
            }
        }
        /* print other RRsets */
        rrset = domain->rrsets;
        while (rrset) {
            /* skip SOA RRset */
            if (rrset->rrtype != LDNS_RR_TYPE_SOA) {
                rrset_print(fd, rrset, 0, status);
            }
            if (status && *status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to print one or more RRsets: %s",
                    dname_str, ods_status2str(*status));
                return;
            }
            rrset = rrset->next;
        }
    }
    /* Denial of Existence */
    if (domain->denial) {
        denial_print(fd, (denial_type*) domain->denial, status);
    }
}


/**
 * Clean up domain.
 *
 */
void
domain_cleanup(domain_type* domain)
{
    if (!domain) {
        return;
    }
    ldns_rdf_deep_free(domain->dname);
    rrset_cleanup(domain->rrsets);
    free(domain);
}
