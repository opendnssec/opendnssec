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
 * RRset.
 *
 */

#include "config.h"
#include "file.h"
#include "hsm.h"
#include "log.h"
#include "util.h"
#include "signer/rrset.h"
#include "signer/zone.h"

static const char* rrset_str = "rrset";


/**
 * Log RR.
 *
 */
void
log_rr(ldns_rr* rr, const char* pre, int level)
{
    char* str = NULL;
    size_t i = 0;

    if (ods_log_get_level() < level) {
        return;
    }
    str = ldns_rr2str(rr);
    if (!str) {
        ods_log_error("[%s] %s: Error converting RR to string", rrset_str,
            pre?pre:"");
        return;
    }
    str[(strlen(str))-1] = '\0';
    /* replace tabs with white space */
    for (i=0; i < strlen(str); i++) {
        if (str[i] == '\t') {
            str[i] = ' ';
        }
    }
    if (level == LOG_EMERG) {
        ods_fatal_exit("[%s] %s: %s", rrset_str, pre?pre:"", str);
    } else if (level == LOG_ALERT) {
        ods_log_alert("[%s] %s: %s", rrset_str, pre?pre:"", str);
    } else if (level == LOG_CRIT) {
        ods_log_crit("[%s] %s: %s", rrset_str, pre?pre:"", str);
    } else if (level == LOG_ERR) {
        ods_log_error("[%s] %s: %s", rrset_str, pre?pre:"", str);
    } else if (level == LOG_WARNING) {
        ods_log_warning("[%s] %s: %s", rrset_str, pre?pre:"", str);
    } else if (level == LOG_NOTICE) {
        ods_log_info("[%s] %s: %s", rrset_str, pre?pre:"", str);
    } else if (level == LOG_INFO) {
        ods_log_verbose("[%s] %s: %s", rrset_str, pre?pre:"", str);
    } else if (level == LOG_DEBUG) {
        ods_log_debug("[%s] %s: %s", rrset_str, pre?pre:"", str);
    } else if (level == LOG_DEEEBUG) {
        ods_log_deeebug("[%s] %s: %s", rrset_str, pre?pre:"", str);
    } else {
        ods_log_deeebug("[%s] %s: %s", rrset_str, pre?pre:"", str);
    }
    free((void*)str);
}


/**
 * Log RRset.
 *
 */
void
log_rrset(ldns_rdf* dname, ldns_rr_type type, const char* pre, int level)
{
    char* str = NULL;
    size_t i = 0;

    if (ods_log_get_level() < level) {
        return;
    }
    str = ldns_rdf2str(dname);
    if (!str) {
        return;
    }
    str[(strlen(str))-1] = '\0';
    /* replace tabs with white space */
    for (i=0; i < strlen(str); i++) {
        if (str[i] == '\t') {
            str[i] = ' ';
        }
    }
    if (level == LOG_EMERG) {
        ods_fatal_exit("[%s] %s: <%s,%s>", rrset_str, pre?pre:"", str,
            rrset_type2str(type));
    } else if (level == LOG_ALERT) {
        ods_log_alert("[%s] %s: <%s,%s>", rrset_str, pre?pre:"", str,
            rrset_type2str(type));
    } else if (level == LOG_CRIT) {
        ods_log_crit("[%s] %s: <%s,%s>", rrset_str, pre?pre:"", str,
            rrset_type2str(type));
    } else if (level == LOG_ERR) {
        ods_log_error("[%s] %s: <%s,%s>", rrset_str, pre?pre:"", str,
            rrset_type2str(type));
    } else if (level == LOG_WARNING) {
        ods_log_warning("[%s] %s: <%s,%s>", rrset_str, pre?pre:"", str,
            rrset_type2str(type));
    } else if (level == LOG_NOTICE) {
        ods_log_info("[%s] %s: <%s,%s>", rrset_str, pre?pre:"", str,
            rrset_type2str(type));
    } else if (level == LOG_INFO) {
        ods_log_verbose("[%s] %s: <%s,%s>", rrset_str, pre?pre:"", str,
            rrset_type2str(type));
    } else if (level == LOG_DEBUG) {
        ods_log_debug("[%s] %s: <%s,%s>", rrset_str, pre?pre:"", str,
            rrset_type2str(type));
    } else if (level == LOG_DEEEBUG) {
        ods_log_deeebug("[%s] %s: <%s,%s>", rrset_str, pre?pre:"", str,
            rrset_type2str(type));
    } else {
        ods_log_deeebug("[%s] %s: <%s,%s>", rrset_str, pre?pre:"", str,
            rrset_type2str(type));
    }
    free((void*)str);
}


/**
 * Get the string-format of RRtype.
 *
 */
const char*
rrset_type2str(ldns_rr_type type)
{
    if (type == LDNS_RR_TYPE_IXFR) {
        return "IXFR";
    } else if (type == LDNS_RR_TYPE_AXFR) {
        return "AXFR";
    } else if (type == LDNS_RR_TYPE_MAILB) {
        return "MAILB";
    } else if (type == LDNS_RR_TYPE_MAILA) {
        return "MAILA";
    } else if (type == LDNS_RR_TYPE_ANY) {
        return "ANY";
    } else {
        const ldns_rr_descriptor* descriptor = ldns_rr_descript(type);
        if (descriptor && descriptor->_name) {
            return descriptor->_name;
        }
    }
    return "TYPE???";
}


/**
 * Create RRset.
 *
 */
rrset_type*
rrset_create(void* zoneptr, ldns_rr_type type)
{
    zone_type* zone = (zone_type*) zoneptr;
    rrset_type* rrset = NULL;
    if (!type || !zoneptr) {
        return NULL;
    }
    CHECKALLOC(rrset = (rrset_type*) malloc(sizeof(rrset_type)));
    if (!rrset) {
        ods_log_error("[%s] unable to create RRset %u: allocator_alloc() "
            "failed", rrset_str, (unsigned) type);
        return NULL;
    }
    rrset->next = NULL;
    rrset->rrs = NULL;
    rrset->rrsigs = NULL;
    rrset->domain = NULL;
    rrset->zone = zoneptr;
    rrset->rrtype = type;
    rrset->rr_count = 0;
    rrset->rrsig_count = 0;
    rrset->needs_signing = 0;
    return rrset;
}


/**
 * Lookup RR in RRset.
 *
 */
rr_type*
rrset_lookup_rr(rrset_type* rrset, ldns_rr* rr)
{
    ldns_status lstatus = LDNS_STATUS_OK;
    int cmp = 0;
    size_t i = 0;

    if (!rrset || !rr || rrset->rr_count <= 0) {
       return NULL;
    }
    for (i=0; i < rrset->rr_count; i++) {
        lstatus = util_dnssec_rrs_compare(rrset->rrs[i].rr, rr, &cmp);
        if (lstatus != LDNS_STATUS_OK) {
            ods_log_error("[%s] unable to lookup RR: compare failed (%s)",
                rrset_str, ldns_get_errorstr_by_id(lstatus));
            return NULL;
        }
        if (!cmp) { /* equal */
            return &rrset->rrs[i];
        }
    }
    return NULL;
}


/**
 * Count the number of RRs in this RRset that have is_added.
 *
 */
size_t
rrset_count_rr_is_added(rrset_type* rrset)
{
    size_t i = 0;
    size_t count = 0;
    if (!rrset) {
        return 0;
    }
    for (i=0; i < rrset->rr_count; i++) {
        if (rrset->rrs[i].is_added) {
            count++;
        }
    }
    return count;
}


/**
 * Add RR to RRset.
 *
 */
rr_type*
rrset_add_rr(rrset_type* rrset, ldns_rr* rr)
{
    rr_type* rrs_old = NULL;
    zone_type* zone = NULL;

    ods_log_assert(rrset);
    ods_log_assert(rr);
    ods_log_assert(rrset->rrtype == ldns_rr_get_type(rr));

    zone = (zone_type*) rrset->zone;
    rrs_old = rrset->rrs;
    CHECKALLOC(rrset->rrs = (rr_type*) malloc((rrset->rr_count + 1) * sizeof(rr_type)));
    if (!rrset->rrs) {
        ods_fatal_exit("[%s] fatal unable to add RR: allocator_alloc() failed",
            rrset_str);
    }
    if (rrs_old) {
        memcpy(rrset->rrs, rrs_old, (rrset->rr_count) * sizeof(rr_type));
    }
    free(rrs_old);
    rrset->rr_count++;
    rrset->rrs[rrset->rr_count - 1].owner = rrset->domain;
    rrset->rrs[rrset->rr_count - 1].rr = rr;
    rrset->rrs[rrset->rr_count - 1].exists = 0;
    rrset->rrs[rrset->rr_count - 1].is_added = 1;
    rrset->rrs[rrset->rr_count - 1].is_removed = 0;
    rrset->needs_signing = 1;
    log_rr(rr, "+RR", LOG_DEEEBUG);
    return &rrset->rrs[rrset->rr_count -1];
}


/**
 * Delete RR from RRset.
 *
 */
void
rrset_del_rr(rrset_type* rrset, uint16_t rrnum)
{
    rr_type* rrs_orig = NULL;
    zone_type* zone = NULL;

    ods_log_assert(rrset);
    ods_log_assert(rrnum < rrset->rr_count);

    zone = (zone_type*) rrset->zone;
    log_rr(rrset->rrs[rrnum].rr, "-RR", LOG_DEEEBUG);
    rrset->rrs[rrnum].owner = NULL;
    rrset->rrs[rrnum].rr = NULL;
    while (rrnum < rrset->rr_count-1) {
        rrset->rrs[rrnum] = rrset->rrs[rrnum+1];
        rrnum++;
    }
    memset(&rrset->rrs[rrset->rr_count-1], 0, sizeof(rr_type));
    rrs_orig = rrset->rrs;
    CHECKALLOC(rrset->rrs = (rr_type*) malloc((rrset->rr_count - 1) * sizeof(rr_type)));
    if(!rrset->rrs) {
        ods_fatal_exit("[%s] fatal unable to delete RR: allocator_alloc() failed",
            rrset_str);
    }
    memcpy(rrset->rrs, rrs_orig, (rrset->rr_count -1) * sizeof(rr_type));
    free(rrs_orig);
    rrset->rr_count--;
    rrset->needs_signing = 1;
}


/**
 * Apply differences at RRset.
 *
 */
void
rrset_diff(rrset_type* rrset, unsigned is_ixfr, unsigned more_coming)
{
    zone_type* zone = NULL;
    uint16_t i = 0;
    uint8_t del_sigs = 0;
    if (!rrset) {
        return;
    }
    zone = (zone_type*) rrset->zone;
    for (i=0; i < rrset->rr_count; i++) {
        if (rrset->rrs[i].is_added) {
            if (!rrset->rrs[i].exists) {
                /* ixfr +RR */
                lock_basic_lock(&zone->ixfr->ixfr_lock);
                ixfr_add_rr(zone->ixfr, rrset->rrs[i].rr);
                lock_basic_unlock(&zone->ixfr->ixfr_lock);
                del_sigs = 1;
            }
            rrset->rrs[i].exists = 1;
            if ((rrset->rrtype == LDNS_RR_TYPE_DNSKEY ||
                 rrset->rrtype == LDNS_RR_TYPE_NSEC3PARAMS) && more_coming) {
                continue;
            }
            rrset->rrs[i].is_added = 0;
        } else if (!is_ixfr || rrset->rrs[i].is_removed) {
            if (rrset->rrs[i].exists) {
                /* ixfr -RR */
                lock_basic_lock(&zone->ixfr->ixfr_lock);
                ixfr_del_rr(zone->ixfr, rrset->rrs[i].rr);
                lock_basic_unlock(&zone->ixfr->ixfr_lock);
            }
            rrset->rrs[i].exists = 0;
            rrset_del_rr(rrset, i);
            del_sigs = 1;
            i--;
        }
    }
    if (del_sigs) {
       for (i=0; i < rrset->rrsig_count; i++) {
            /* ixfr -RRSIG */
            lock_basic_lock(&zone->ixfr->ixfr_lock);
            ixfr_del_rr(zone->ixfr, rrset->rrsigs[i].rr);
            lock_basic_unlock(&zone->ixfr->ixfr_lock);
            rrset_del_rrsig(rrset, i);
            i--;
        }
    }
}


/**
 * Add RRSIG to RRset.
 *
 */
rrsig_type*
rrset_add_rrsig(rrset_type* rrset, ldns_rr* rr,
    const char* locator, uint32_t flags)
{
    rrsig_type* rrsigs_old = NULL;
    zone_type* zone = NULL;
    ods_log_assert(rrset);
    ods_log_assert(rr);
    ods_log_assert(ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG);
    zone = (zone_type*) rrset->zone;
    rrsigs_old = rrset->rrsigs;
    CHECKALLOC(rrset->rrsigs = (rrsig_type*) malloc((rrset->rrsig_count + 1) * sizeof(rrsig_type)));
    if (!rrset->rrsigs) {
        ods_fatal_exit("[%s] fatal unable to add RRSIG: allocator_alloc() failed",
            rrset_str);
    }
    if (rrsigs_old) {
        memcpy(rrset->rrsigs, rrsigs_old,
            (rrset->rrsig_count) * sizeof(rrsig_type));
    }
    free(rrsigs_old);
    rrset->rrsig_count++;
    rrset->rrsigs[rrset->rrsig_count - 1].owner = rrset->domain;
    rrset->rrsigs[rrset->rrsig_count - 1].rr = rr;
    rrset->rrsigs[rrset->rrsig_count - 1].key_locator = locator;
    rrset->rrsigs[rrset->rrsig_count - 1].key_flags = flags;
    log_rr(rr, "+RRSIG", LOG_DEEEBUG);
    return &rrset->rrsigs[rrset->rrsig_count -1];
}


/**
 * Delete RRSIG from RRset.
 *
 */
void
rrset_del_rrsig(rrset_type* rrset, uint16_t rrnum)
{
    rrsig_type* rrsigs_orig = NULL;
    zone_type* zone = NULL;
    ods_log_assert(rrset);
    ods_log_assert(rrnum < rrset->rrsig_count);
    zone = (zone_type*) rrset->zone;
    log_rr(rrset->rrsigs[rrnum].rr, "-RRSIG", LOG_DEEEBUG);
    rrset->rrsigs[rrnum].owner = NULL;
    rrset->rrsigs[rrnum].rr = NULL;
    free((void*)rrset->rrsigs[rrnum].key_locator);
    rrset->rrsigs[rrnum].key_locator = NULL;
    while (rrnum < rrset->rrsig_count-1) {
        rrset->rrsigs[rrnum] = rrset->rrsigs[rrnum+1];
        rrnum++;
    }
    memset(&rrset->rrsigs[rrset->rrsig_count-1], 0, sizeof(rrsig_type));
    rrsigs_orig = rrset->rrsigs;
    CHECKALLOC(rrset->rrsigs = (rrsig_type*) malloc((rrset->rrsig_count - 1) * sizeof(rrsig_type)));
    if(!rrset->rrsigs) {
        ods_fatal_exit("[%s] fatal unable to delete RRSIG: allocator_alloc() failed",
            rrset_str);
    }
    memcpy(rrset->rrsigs, rrsigs_orig,
        (rrset->rrsig_count -1) * sizeof(rrsig_type));
    free(rrsigs_orig);
    rrset->rrsig_count--;
}


/**
 * Recycle signatures from RRset and drop unreusable signatures.
 *
 */
static uint32_t
rrset_recycle(rrset_type* rrset, time_t signtime, ldns_rr_type dstatus,
    ldns_rr_type delegpt)
{
    uint32_t refresh = 0;
    uint32_t expiration = 0;
    uint32_t inception = 0;
    uint32_t reusedsigs = 0;
    unsigned drop_sig = 0;
    size_t i = 0;
    key_type* key = NULL;
    zone_type* zone = NULL;

    if (!rrset) {
        return 0;
    }
    zone = (zone_type*) rrset->zone;
    /* Calculate the Refresh Window = Signing time + Refresh */
    if (zone->signconf && zone->signconf->sig_refresh_interval) {
        refresh = (uint32_t) (signtime +
            duration2time(zone->signconf->sig_refresh_interval));
    }
    /* Check every signature if it matches the recycling logic. */
    for (i=0; i < rrset->rrsig_count; i++) {
        drop_sig = 0;
        /* 0. Skip delegation, glue and occluded RRsets */
        if (dstatus != LDNS_RR_TYPE_SOA || (delegpt != LDNS_RR_TYPE_SOA &&
            rrset->rrtype != LDNS_RR_TYPE_DS)) {
            drop_sig = 1;
            goto recycle_drop_sig;
        }
        ods_log_assert(dstatus == LDNS_RR_TYPE_SOA ||
            (delegpt == LDNS_RR_TYPE_SOA || rrset->rrtype == LDNS_RR_TYPE_DS));
        /* 1. If the RRset has changed, drop all signatures */
        /* 2. If Refresh is disabled, drop all signatures */
        if (rrset->needs_signing || refresh <= (uint32_t) signtime) {
            drop_sig = 1;
            goto recycle_drop_sig;
        }
        /* 3. Expiration - Refresh has passed */
        expiration = ldns_rdf2native_int32(
            ldns_rr_rrsig_expiration(rrset->rrsigs[i].rr));
        if (expiration < refresh) {
            drop_sig = 1;
            goto recycle_drop_sig;
        }
        /* 4. Inception has not yet passed */
        inception = ldns_rdf2native_int32(
            ldns_rr_rrsig_inception(rrset->rrsigs[i].rr));
        if (inception > (uint32_t) signtime) {
            drop_sig = 1;
            goto recycle_drop_sig;
        }
        /* 5. Corresponding key is dead (key is locator+flags) */
        key = keylist_lookup_by_locator(zone->signconf->keys,
            rrset->rrsigs[i].key_locator);
        if (!key || key->flags != rrset->rrsigs[i].key_flags) {
            drop_sig = 1;
        }

recycle_drop_sig:
        if (drop_sig) {
            /* A rule mismatched, refresh signature */
            /* ixfr -RRSIG */
            lock_basic_lock(&zone->ixfr->ixfr_lock);
            ixfr_del_rr(zone->ixfr, rrset->rrsigs[i].rr);
            lock_basic_unlock(&zone->ixfr->ixfr_lock);
            rrset_del_rrsig(rrset, i);
            i--;
        } else {
            /* All rules ok, recycle signature */
            reusedsigs += 1;
        }
    }
    return reusedsigs;
}


/**
 * Is the list of RRSIGs ok?
 *
 */
static int
rrset_sigok(rrset_type* rrset, key_type* key)
{
    key_type* sigkey = NULL;
    zone_type* zone = NULL;
    size_t i = 0;
    ods_log_assert(rrset);
    ods_log_assert(key);
    ods_log_assert(key->locator);
    zone = (zone_type*) rrset->zone;
    ods_log_assert(zone);

    /* Does this key have a RRSIG? */
    for (i=0; i < rrset->rrsig_count; i++) {
        if (ods_strcmp(key->locator, rrset->rrsigs[i].key_locator) == 0 &&
            key->flags == rrset->rrsigs[i].key_flags) {
            /* Active key already has a valid RRSIG. SIGOK */
            return 1;
        }
    }
    /* DNSKEY RRset always needs to be signed with active key */
    if (rrset->rrtype == LDNS_RR_TYPE_DNSKEY) {
        return 0;
    }
    /* Let's look for RRSIGs from inactive ZSKs */
    for (i=0; i < rrset->rrsig_count; i++) {
        /* Same algorithm? */
        if (key->algorithm != ldns_rdf2native_int8(
                ldns_rr_rrsig_algorithm(rrset->rrsigs[i].rr))) {
            /* Not the same algorithm, so this one does not count */
            continue;
        }
        /* Inactive key? */
        sigkey = keylist_lookup_by_locator(zone->signconf->keys,
            rrset->rrsigs[i].key_locator);
        ods_log_assert(sigkey);
        if (sigkey->zsk) {
            /* Active key, so this one does not count */
            continue;
        }
        /* So we found a valid RRSIG from an inactive key. SIGOK */
        return 1;
    }
    /* We need a new RRSIG. */
    return 0;
}

/**
 * Is the RRset signed with this algorithm?
 *
 */
static int
rrset_sigalgo(rrset_type* rrset, uint8_t algorithm)
{
    size_t i = 0;
    if (!rrset) {
        return 0;
    }
    for (i=0; i < rrset->rrsig_count; i++) {
        if (algorithm == ldns_rdf2native_int8(
                ldns_rr_rrsig_algorithm(rrset->rrsigs[i].rr))) {
            return 1;
        }
    }
    return 0;
}

/**
 * Is the RRset signed with this locator?
 *
 */
static int
rrset_siglocator(rrset_type* rrset, const char* locator)
{
    size_t i = 0;
    if (!rrset) {
        return 0;
    }
    for (i=0; i < rrset->rrsig_count; i++) {
        if (!ods_strcmp(locator, rrset->rrsigs[i].key_locator)) {
            return 1;
        }
    }
    return 0;
}


/**
 * Transmogrify the RRset to a RRlist.
 *
 */
static ldns_rr_list*
rrset2rrlist(rrset_type* rrset)
{
    ldns_rr_list* rr_list = NULL;
    int ret = 0;
    size_t i = 0;
    rr_list = ldns_rr_list_new();
    for (i=0; i < rrset->rr_count; i++) {
        if (!rrset->rrs[i].exists) {
            log_rr(rrset->rrs[i].rr, "RR does not exist", LOG_WARNING);
            continue;
        }
        /* clone if you want to keep the original format in the signed zone */
        ldns_rr2canonical(rrset->rrs[i].rr);
        ret = (int) ldns_rr_list_push_rr(rr_list, rrset->rrs[i].rr);
        if (!ret) {
            ldns_rr_list_free(rr_list);
            return NULL;
        }
        if (rrset->rrtype == LDNS_RR_TYPE_CNAME ||
            rrset->rrtype == LDNS_RR_TYPE_DNAME) {
            /* singleton types */
            return rr_list;
        }
    }
    ldns_rr_list_sort(rr_list);
    return rr_list;
}


/**
 * Calculate the signature validation period.
 *
 */
static void
rrset_sigvalid_period(signconf_type* sc, ldns_rr_type rrtype, time_t signtime,
    time_t* inception, time_t* expiration)
{
    time_t jitter = 0;
    time_t offset = 0;
    time_t validity = 0;
    time_t random_jitter = 0;
    if (!sc || !rrtype || !signtime) {
        return;
    }
    jitter = duration2time(sc->sig_jitter);
    if (jitter) {
        random_jitter = ods_rand(jitter*2);
    }
    offset = duration2time(sc->sig_inception_offset);
    if (rrtype == LDNS_RR_TYPE_NSEC || rrtype == LDNS_RR_TYPE_NSEC3) {
        validity = duration2time(sc->sig_validity_denial);
    } else {
        validity = duration2time(sc->sig_validity_default);
    }
    *inception = signtime - offset;
    *expiration = (signtime + validity + random_jitter) - jitter;
}


/**
 * Sign RRset.
 *
 */
ods_status
rrset_sign(hsm_ctx_t* ctx, rrset_type* rrset, time_t signtime)
{
    zone_type* zone = NULL;
    uint32_t newsigs = 0;
    uint32_t reusedsigs = 0;
    ldns_rr* rrsig = NULL;
    ldns_rr_list* rr_list = NULL;
    rrsig_type* signature = NULL;
    const char* locator = NULL;
    time_t inception = 0;
    time_t expiration = 0;
    size_t i = 0;
    domain_type* domain = NULL;
    ldns_rr_type dstatus = LDNS_RR_TYPE_FIRST;
    ldns_rr_type delegpt = LDNS_RR_TYPE_FIRST;

    ods_log_assert(ctx);
    ods_log_assert(rrset);
    zone = (zone_type*) rrset->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->signconf);
    /* Recycle signatures */
    if (rrset->rrtype == LDNS_RR_TYPE_NSEC ||
        rrset->rrtype == LDNS_RR_TYPE_NSEC3) {
        dstatus = LDNS_RR_TYPE_SOA;
        delegpt = LDNS_RR_TYPE_SOA;
    } else {
        domain = (domain_type*) rrset->domain;
        dstatus = domain_is_occluded(domain);
        delegpt = domain_is_delegpt(domain);
    }
    reusedsigs = rrset_recycle(rrset, signtime, dstatus, delegpt);
    rrset->needs_signing = 0;

    ods_log_assert(rrset->rrs);
    ods_log_assert(rrset->rrs[0].rr);

    /* Skip delegation, glue and occluded RRsets */
    if (dstatus != LDNS_RR_TYPE_SOA) {
        log_rrset(ldns_rr_owner(rrset->rrs[0].rr), rrset->rrtype,
            "skip signing occluded RRset", LOG_DEEEBUG);
        return ODS_STATUS_OK;
    }
    if (delegpt != LDNS_RR_TYPE_SOA && rrset->rrtype != LDNS_RR_TYPE_DS) {
        log_rrset(ldns_rr_owner(rrset->rrs[0].rr), rrset->rrtype,
            "skip signing delegation RRset", LOG_DEEEBUG);
        return ODS_STATUS_OK;
    }

    log_rrset(ldns_rr_owner(rrset->rrs[0].rr), rrset->rrtype,
        "sign RRset", LOG_DEEEBUG);
    ods_log_assert(dstatus == LDNS_RR_TYPE_SOA ||
        (delegpt == LDNS_RR_TYPE_SOA || rrset->rrtype == LDNS_RR_TYPE_DS));
    /* Transmogrify rrset */
    rr_list = rrset2rrlist(rrset);
    if (!rr_list) {
        ods_log_error("[%s] unable to sign RRset[%i]: rrset2rrlist() failed",
            rrset_str, rrset->rrtype);
        return ODS_STATUS_MALLOC_ERR;
    }
    if (ldns_rr_list_rr_count(rr_list) <= 0) {
        /* Empty RRset, no signatures needed */
        ldns_rr_list_free(rr_list);
        return ODS_STATUS_OK;
    }
    /* Calculate signature validity */
    rrset_sigvalid_period(zone->signconf, rrset->rrtype, signtime,
         &inception, &expiration);
    /* Walk keys */
    for (i=0; i < zone->signconf->keys->count; i++) {
        /* If not ZSK don't sign other RRsets */
        if (!zone->signconf->keys->keys[i].zsk &&
            rrset->rrtype != LDNS_RR_TYPE_DNSKEY) {
            continue;
        }
        /* If not KSK don't sign DNSKEY RRset */
        if (!zone->signconf->keys->keys[i].ksk &&
            rrset->rrtype == LDNS_RR_TYPE_DNSKEY) {
            continue;
        }
        /* Additional rules for signatures */
        if (rrset_siglocator(rrset, zone->signconf->keys->keys[i].locator)) {
            continue;
        }
        if (rrset->rrtype != LDNS_RR_TYPE_DNSKEY &&
	    rrset_sigalgo(rrset, zone->signconf->keys->keys[i].algorithm)) {
            continue;
        }

        /**
         * currently, there is no rule that the number of signatures
         * over this RRset equals the number of active keys.
         */
        if (rrset_sigok(rrset, &zone->signconf->keys->keys[i])) {
            ods_log_debug("[%s] RRset[%i] with key %s returns sigok",
               rrset_str, rrset->rrtype, zone->signconf->keys->keys[i].locator);
        }

        /* Sign the RRset with this key */
        ods_log_deeebug("[%s] signing RRset[%i] with key %s", rrset_str,
            rrset->rrtype, zone->signconf->keys->keys[i].locator);
        rrsig = lhsm_sign(ctx, rr_list, &zone->signconf->keys->keys[i],
            zone->apex, inception, expiration);
        if (!rrsig) {
            ods_log_crit("[%s] unable to sign RRset[%i]: lhsm_sign() failed",
                rrset_str, rrset->rrtype);
            ldns_rr_list_free(rr_list);
            return ODS_STATUS_HSM_ERR;
        }
        /* Add signature */
        locator = strdup(zone->signconf->keys->keys[i].locator);
        signature = rrset_add_rrsig(rrset, rrsig, locator,
            zone->signconf->keys->keys[i].flags);
        newsigs++;
        /* ixfr +RRSIG */
        ods_log_assert(signature->rr);
        lock_basic_lock(&zone->ixfr->ixfr_lock);
        ixfr_add_rr(zone->ixfr, signature->rr);
        lock_basic_unlock(&zone->ixfr->ixfr_lock);
    }
    /* RRset signing completed */
    ldns_rr_list_free(rr_list);
    lock_basic_lock(&zone->stats->stats_lock);
    if (rrset->rrtype == LDNS_RR_TYPE_SOA) {
        zone->stats->sig_soa_count += newsigs;
    }
    zone->stats->sig_count += newsigs;
    zone->stats->sig_reuse += reusedsigs;
    lock_basic_unlock(&zone->stats->stats_lock);
    return ODS_STATUS_OK;
}


/**
 * Print RRset.
 *
 */
void
rrset_print(FILE* fd, rrset_type* rrset, int skip_rrsigs,
    ods_status* status)
{
    uint16_t i = 0;
    ods_status result = ODS_STATUS_OK;

    if (!rrset || !fd) {
        ods_log_crit("[%s] unable to print RRset: rrset or fd missing",
            rrset_str);
        if (status) {
            *status = ODS_STATUS_ASSERT_ERR;
        }
    } else {
        for (i=0; i < rrset->rr_count; i++) {
            if (rrset->rrs[i].exists) {
                result = util_rr_print(fd, rrset->rrs[i].rr);
                if (rrset->rrtype == LDNS_RR_TYPE_CNAME ||
                    rrset->rrtype == LDNS_RR_TYPE_DNAME) {
                    /* singleton types */
                    break;
                }
                if (result != ODS_STATUS_OK) {
                    zone_type* zone = (zone_type*) rrset->zone;
                    log_rrset(ldns_rr_owner(rrset->rrs[i].rr), rrset->rrtype,
                        "error printing RRset", LOG_CRIT);
                    zone->adoutbound->error = 1;
                    break;
                }
            }
        }
        if (! (skip_rrsigs || !rrset->rrsig_count)) {
            for (i=0; i < rrset->rrsig_count; i++) {
                result = util_rr_print(fd, rrset->rrsigs[i].rr);
                if (result != ODS_STATUS_OK) {
                    zone_type* zone = (zone_type*) rrset->zone;
                    log_rrset(ldns_rr_owner(rrset->rrs[i].rr), rrset->rrtype,
                        "error printing RRset", LOG_CRIT);
                    zone->adoutbound->error = 1;
                    break;
                }
            }
        }
        if (status) {
            *status = result;
        }
    }
}


/**
 * Clean up RRset.
 *
 */
void
rrset_cleanup(rrset_type* rrset)
{
    uint16_t i = 0;
    zone_type* zone = NULL;
    if (!rrset) {
       return;
    }
    rrset_cleanup(rrset->next);
    rrset->next = NULL;
    rrset->domain = NULL;
    zone = (zone_type*) rrset->zone;
    for (i=0; i < rrset->rr_count; i++) {
        ldns_rr_free(rrset->rrs[i].rr);
        rrset->rrs[i].owner = NULL;
    }
    for (i=0; i < rrset->rrsig_count; i++) {
        free((void*)rrset->rrsigs[i].key_locator);
        ldns_rr_free(rrset->rrsigs[i].rr);
        rrset->rrsigs[i].owner = NULL;
    }
    free(rrset->rrs);
    free(rrset->rrsigs);
    free(rrset);
}


/**
 * Backup RRset.
 *
 */
void
rrset_backup2(FILE* fd, rrset_type* rrset)
{
    char* str = NULL;
    uint16_t i = 0;
    if (!rrset || !fd) {
        return;
    }
    for (i=0; i < rrset->rrsig_count; i++) {
        str = ldns_rr2str(rrset->rrsigs[i].rr);
        if (!str) {
            continue;
        }
        str[(strlen(str))-1] = '\0';
        fprintf(fd, "%s; {locator %s flags %u}\n", str,
            rrset->rrsigs[i].key_locator, rrset->rrsigs[i].key_flags);
        free((void*)str);
    }
}
