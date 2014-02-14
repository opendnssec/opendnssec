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
#include "shared/log.h"
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
    return;
}


/**
 * Create domain.
 *
 */
domain_type*
domain_create(void* zoneptr, ldns_rdf* dname)
{
    domain_type* domain = NULL;
    zone_type* zone = (zone_type*) zoneptr;
    if (!dname || !zoneptr) {
        return NULL;
    }
    domain = (domain_type*) allocator_alloc(
        zone->allocator, sizeof(domain_type));
    if (!domain) {
        ods_log_error("[%s] unable to create domain: allocator_alloc() "
            "failed", dname_str);
        return NULL;
    }
    domain->dname = ldns_rdf_clone(dname);
    if (!domain->dname) {
        ods_log_error("[%s] unable to create domain: ldns_rdf_clone() "
            "failed", dname_str);
        allocator_deallocate(zone->allocator, domain);
        return NULL;
    }
    domain->zone = zoneptr;
    domain->denial = NULL; /* no reference yet */
    domain->node = NULL; /* not in db yet */
    domain->rrsets = NULL;
    domain->parent = NULL;
    domain->is_apex = 0;
    domain->is_new = 0;
    return domain;
}


/**
 * Count the number of RRsets at this domain.
 *
 */
size_t
domain_count_rrset(domain_type* domain)
{
    rrset_type* rrset = NULL;
    size_t count = 0;
    if (!domain) {
        return 0;
    }
    rrset = domain->rrsets;
    while (rrset) {
        count++; /* rr_count may be zero */
        rrset = rrset->next;
    }
    return count;
}


/**
 * Count the number of RRsets at this domain with RRs that have is_added.
 *
 */
size_t
domain_count_rrset_is_added(domain_type* domain)
{
    rrset_type* rrset = NULL;
    size_t count = 0;
    if (!domain) {
        return 0;
    }
    rrset = domain->rrsets;
    while (rrset) {
        if (rrset_count_rr_is_added(rrset)) {
            count++;
        }
        rrset = rrset->next;
    }
    return count;
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
    rrset->domain = (void*) domain;
    if (domain->denial) {
        denial = (denial_type*) domain->denial;
        denial->bitmap_changed = 1;
    }
    return;
}


/**
 * Delete RRset from domain.
 *
 */
rrset_type*
domain_del_rrset(domain_type* domain, ldns_rr_type rrtype)
{
    rrset_type* cur = NULL;
    denial_type* denial = NULL;
    if (!domain || !rrtype) {
        return NULL;
    }
    if (!domain->rrsets) {
        ods_log_error("[%s] unable to delete RRset: RRset with RRtype %s "
            "does not exist", dname_str, rrset_type2str(rrtype));
        return NULL;
    }
    if (domain->rrsets->rrtype == rrtype) {
        cur = domain->rrsets;
        domain->rrsets = cur->next;
        cur->domain = NULL;
        cur->next = NULL;
        log_rrset(domain->dname, rrtype, "-RRSET", LOG_DEEEBUG);
        if (domain->denial) {
            denial = (denial_type*) domain->denial;
            denial->bitmap_changed = 1;
        }
        return cur;
    }
    cur = domain->rrsets;
    while (cur) {
        if (!cur->next) {
            ods_log_error("[%s] unable to delete RRset: RRset with RRtype %s "
                "does not exist", dname_str, rrset_type2str(rrtype));
            return NULL;
        }
        ods_log_assert(cur->next);
        if (cur->next->rrtype != rrtype) {
            cur = cur->next;
        } else {
            ods_log_assert(cur->next->rrtype == rrtype);
            cur->next = cur->next->next;
            cur = cur->next;
            cur->domain = NULL;
            cur->next = NULL;
            log_rrset(domain->dname, rrtype, "-RRSET", LOG_DEEEBUG);
            if (domain->denial) {
                denial = (denial_type*) domain->denial;
                denial->bitmap_changed = 1;
            }
            return cur;
        }
    }
    ods_log_error("[%s] unable to delete RRset: RRset with RRtype %s "
        "does not exist", dname_str, rrset_type2str(rrtype));
    return NULL;
}


/**
 * Apply differences at domain.
 *
 */
void
domain_diff(domain_type* domain, unsigned is_ixfr, unsigned more_coming)
{
    denial_type* denial = NULL;
    rrset_type* rrset = NULL;
    rrset_type* prev_rrset = NULL;

    if (!domain) {
        return;
    }
    rrset = domain->rrsets;
    while (rrset) {
        if (rrset->rrtype == LDNS_RR_TYPE_NSEC3PARAMS ||
            rrset->rrtype == LDNS_RR_TYPE_DNSKEY) {
            /* always do full diff on NSEC3PARAMS | DNSKEY RRset */
            rrset_diff(rrset, 0, more_coming);
        } else {
            rrset_diff(rrset, is_ixfr, more_coming);
        }
        if (rrset->rr_count <= 0) {
            /* delete entire rrset */
            if (!prev_rrset) {
                domain->rrsets = rrset->next;
            } else {
                prev_rrset->next = rrset->next;
            }
            rrset->next = NULL;
            log_rrset(domain->dname, rrset->rrtype, "-RRSET", LOG_DEEEBUG);
            rrset_cleanup(rrset);
            if (!prev_rrset) {
                rrset = domain->rrsets;
            } else {
                rrset = prev_rrset->next;
            }
            if (domain->denial) {
                denial = (denial_type*) domain->denial;
                denial->bitmap_changed = 1;
            }
        } else {
            /* just go to next rrset */
            prev_rrset = rrset;
            rrset = rrset->next;
        }
    }
    return;
}


/**
 * Rollback differences at domain.
 *
 */
void
domain_rollback(domain_type* domain, int keepsc)
{
    denial_type* denial = NULL;
    rrset_type* rrset = NULL;
    rrset_type* prev_rrset = NULL;
    ldns_rr* del_rr = NULL;
    int del_rrset = 0;
    uint16_t i = 0;
    if (!domain) {
        return;
    }
    rrset = domain->rrsets;
    while (rrset) {
        if (keepsc) {
            /* skip rollback for NSEC3PARAM and DNSKEY RRset */
            if (rrset->rrtype == LDNS_RR_TYPE_NSEC3PARAMS ||
                rrset->rrtype == LDNS_RR_TYPE_DNSKEY) {
                prev_rrset = rrset;
                rrset = rrset->next;
                continue;
            }
        }
        /* walk rrs */
        for (i=0; i < rrset->rr_count; i++) {
            rrset->rrs[i].is_added = 0;
            rrset->rrs[i].is_removed = 0;
            if (!rrset->rrs[i].exists) {
                /* can we delete the RRset? */
                if(rrset->rr_count == 1) {
                    del_rrset = 1;
                }
                del_rr = rrset->rrs[i].rr;
                rrset_del_rr(rrset, i);
                ldns_rr_free(del_rr);
                del_rr = NULL;
                i--;
            }
        }
        /* next rrset */
        if (del_rrset) {
            /* delete entire rrset */
            if (!prev_rrset) {
                domain->rrsets = rrset->next;
            } else {
                prev_rrset->next = rrset->next;
            }
            rrset->next = NULL;
            log_rrset(domain->dname, rrset->rrtype, "-RRSET", LOG_DEEEBUG);
            rrset_cleanup(rrset);
            if (!prev_rrset) {
                rrset = domain->rrsets;
            } else {
                rrset = prev_rrset->next;
            }
            if (domain->denial) {
                denial = (denial_type*) domain->denial;
                denial->bitmap_changed = 0;
            }
            del_rrset = 0;
        } else {
            /* just go to next rrset */
            prev_rrset = rrset;
            rrset = rrset->next;
        }
    }
    return;
}


/**
 * Check whether a domain is an empty non-terminal to unsigned delegation.
 *
 */
int
domain_ent2unsignedns(domain_type* domain)
{
    ldns_rbnode_t* n = LDNS_RBTREE_NULL;
    domain_type* d = NULL;

    ods_log_assert(domain);
    if (domain->rrsets) {
        return 0; /* not an empty non-terminal */
    }
    n = ldns_rbtree_next(domain->node);
    while (n && n != LDNS_RBTREE_NULL) {
        d = (domain_type*) n->data;
        if (!ldns_dname_is_subdomain(d->dname, domain->dname)) {
            break;
        }
        if (d->rrsets) {
            if (domain_is_delegpt(d) != LDNS_RR_TYPE_NS &&
                domain_is_occluded(d) == LDNS_RR_TYPE_SOA) {
                /* domain has signed delegation/auth */
                return 0;
            }
        }
        /* maybe there is data at the next domain */
        n = ldns_rbtree_next(n);
    }
    return 1;
}


/**
 * Check whether the domain is a delegation point.
 *
 */
ldns_rr_type
domain_is_delegpt(domain_type* domain)
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
domain_is_occluded(domain_type* domain)
{
    domain_type* parent = NULL;
    ods_log_assert(domain);
    if (domain->is_apex) {
        return LDNS_RR_TYPE_SOA;
    }
    parent = domain->parent;
    while (parent && !parent->is_apex) {
        if (domain_lookup_rrset(parent, LDNS_RR_TYPE_NS)) {
            /* Glue / Empty non-terminal to Glue */
            return LDNS_RR_TYPE_A;
        }
        if (domain_lookup_rrset(parent, LDNS_RR_TYPE_DNAME)) {
            /* Occluded data / Empty non-terminal to Occluded data */
            return LDNS_RR_TYPE_DNAME;
        }
        parent = parent->parent;
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
    return;
}


/**
 * Clean up domain.
 *
 */
void
domain_cleanup(domain_type* domain)
{
    zone_type* zone = NULL;
    if (!domain) {
        return;
    }
    zone = (zone_type*) domain->zone;
    ldns_rdf_deep_free(domain->dname);
    rrset_cleanup(domain->rrsets);
    allocator_deallocate(zone->allocator, (void*)domain);
    return;
}


/**
 * Backup domain.
 *
 */
void
domain_backup2(FILE* fd, domain_type* domain, int sigs)
{
    rrset_type* rrset = NULL;
    if (!domain || !fd) {
        return;
    }
    /* if SOA, print soa first */
    if (domain->is_apex) {
        rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_SOA);
        if (rrset) {
            if (sigs) {
                rrset_backup2(fd, rrset);
            } else {
                rrset_print(fd, rrset, 1, NULL);
            }
        }
    }
    rrset = domain->rrsets;
    while (rrset) {
        /* skip SOA RRset */
        if (rrset->rrtype != LDNS_RR_TYPE_SOA) {
            if (sigs) {
                rrset_backup2(fd, rrset);
            } else {
                rrset_print(fd, rrset, 1, NULL);
            }
        }
        rrset = rrset->next;
    }
    return;
}
