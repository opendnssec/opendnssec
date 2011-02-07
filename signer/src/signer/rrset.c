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
 * RRset.
 *
 */

#include "config.h"
#include "shared/duration.h"
#include "shared/hsm.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/rrset.h"
#include "util/se_malloc.h"

#include <ldns/ldns.h>

static const char* rrset_str = "rrset";


/**
 * Log RR.
 *
 */
void
log_rr(ldns_rr* rr, const char* pre, int level)
{
    char* str = NULL;

    str = ldns_rr2str(rr);
    if (str) {
        str[(strlen(str))-1] = '\0';
    }
    if (level == 1) {
        ods_log_error("%s %s", pre?pre:"", str?str:"(null)");
    } else if (level == 2) {
        ods_log_warning("%s %s", pre?pre:"", str?str:"(null)");
    } else if (level == 3) {
        ods_log_info("%s %s", pre?pre:"", str?str:"(null)");
    } else if (level == 4) {
        ods_log_verbose("%s %s", pre?pre:"", str?str:"(null)");
    } else if (level == 5) {
        ods_log_debug("%s %s", pre?pre:"", str?str:"(null)");
    } else if (level == 6) {
        ods_log_deeebug("%s %s", pre?pre:"", str?str:"(null)");
    } else {
        ods_log_deeebug("%s %s", pre?pre:"", str?str:"(null)");
    }
    free((void*)str);
    return;
}


/**
 * Create new RRset.
 *
 */
rrset_type*
rrset_create(ldns_rr_type rrtype)
{
    rrset_type* rrset = (rrset_type*) se_calloc(1, sizeof(rrset_type));

    if (!rrtype) {
        ods_log_error("[%s] unable to create RRset: no RRtype", rrset_str);
        return NULL;
    }
    ods_log_assert(rrtype);

    rrset->rr_type = rrtype;
    rrset->rr_count = 0;
    rrset->rrsig_count = 0;
    rrset->add_count = 0;
    rrset->del_count = 0;
    rrset->internal_serial = 0;
    rrset->rrs = ldns_dnssec_rrs_new();
    rrset->add = NULL;
    rrset->del = NULL;
    rrset->rrsigs = NULL;
    rrset->drop_signatures = 0;
    return rrset;
}


/**
 * Create new RRset from RR.
 *
 */
rrset_type*
rrset_create_frm_rr(ldns_rr* rr)
{
    rrset_type* rrset = (rrset_type*) se_calloc(1, sizeof(rrset_type));
    ods_log_assert(rr);
    rrset->rr_type = ldns_rr_get_type(rr);
    rrset->rr_count = 1;
    rrset->add_count = 0;
    rrset->del_count = 0;
    rrset->rrsig_count = 0;
    rrset->internal_serial = 0;
    rrset->rrs = ldns_dnssec_rrs_new();
    rrset->rrs->rr = rr;
    rrset->add = NULL;
    rrset->del = NULL;
    rrset->rrsigs = NULL;
    rrset->drop_signatures = 0;
    return rrset;
}

/**
 * Compare RRs in a RRset
 *
 */
int
rrset_compare_rrs(ldns_dnssec_rrs* rrs1, ldns_dnssec_rrs* rrs2)
{
    int cmp = 0;
    ldns_status status = LDNS_STATUS_OK;

    if (!rrs1 || !rrs2) {
        return 1;
    }
    while (rrs1 && rrs2) {
        if (rrs1->rr && rrs2->rr) {
            status = util_dnssec_rrs_compare(rrs1->rr, rrs2->rr, &cmp);
            if (status != LDNS_STATUS_OK || cmp != 0) {
                return cmp;
            }
            /* check ttl */
            if (ldns_rr_ttl(rrs1->rr) != ldns_rr_ttl(rrs2->rr)) {
                return ldns_rr_ttl(rrs1->rr) - ldns_rr_ttl(rrs2->rr);
            }

            /* the same */
        } else {
            return 1;
        }
        rrs1 = rrs1->next;
        rrs2 = rrs2->next;
    }

    if (!rrs1 && !rrs2) {
        return 0;
    }
    return 1;
}


/**
 * Examine NS RRs and verify its RDATA.
 *
 */
static int
rrs_examine_ns_rdata(ldns_dnssec_rrs* rrs, ldns_rdf* nsdname)
{
    ldns_dnssec_rrs* walk = NULL;

    if (!rrs || !nsdname) {
        return 1;
    }
    walk = rrs;
    while (walk) {
        if (walk->rr &&
            ldns_dname_compare(ldns_rr_rdf(walk->rr, 0), nsdname) == 0) {
            return 0;
        }
        walk = walk->next;
    }
    return 1;
}


/**
 * Examine NS RRset and verify its RDATA.
 *
 */
int
rrset_examine_ns_rdata(rrset_type* rrset, ldns_rdf* nsdname)
{
    if (!rrset || !nsdname || rrset->rr_type != LDNS_RR_TYPE_NS) {
        return 1;
    }

    if (rrs_examine_ns_rdata(rrset->add, nsdname) == 0) {
        return 0;
    }
    if (rrs_examine_ns_rdata(rrset->del, nsdname) == 0) {
        return 1;
    }
    if (rrs_examine_ns_rdata(rrset->rrs, nsdname) == 0) {
        return 0;
    }
    return 1;
}


/**
 * Return the number of pending added RRs in RRset.
 *
 */
int
rrset_count_add(rrset_type* rrset)
{
    ods_log_assert(rrset);
    return rrset->add_count;
}


/**
 * Return the number of pending deleted RRs in RRset.
 *
 */
int
rrset_count_del(rrset_type* rrset)
{
    ods_log_assert(rrset);
    return rrset->del_count;
}


/**
 * Return the number of RRs in RRset after an update.
 *
 */
int
rrset_count_RR(rrset_type* rrset)
{
    ods_log_assert(rrset);
    return ((rrset->rr_count + rrset->add_count) - rrset->del_count);
}


/**
 * Count the number of RRs in this RRset.
 *
 */
size_t
rrset_count_rr(rrset_type* rrset, int which)
{
    if (!rrset) {
        return 0;
    }
    switch (which) {
        case COUNT_ADD:
            return rrset->add_count;
        case COUNT_DEL:
            return rrset->del_count;
        case COUNT_RR:
        default:
            return rrset->rr_count;
    }
    return rrset->rr_count;
}


/**
 * Add RR to RRset.
 *
 */
ldns_rr*
rrset_add_rr(rrset_type* rrset, ldns_rr* rr)
{
    ldns_status status = LDNS_STATUS_OK;

    if (!rr) {
        ods_log_error("[%s] unable to add RR: no RR", rrset_str);
        return NULL;
    }
    ods_log_assert(rr);

    if (!rrset) {
        ods_log_error("[%s] unable to add RR: no storage", rrset_str);
        return NULL;
    }
    ods_log_assert(rrset);

    if (rrset->rr_type != ldns_rr_get_type(rr)) {
        ods_log_error("[%s] unable to add RR: RRtype mismatch", rrset_str);
        return NULL;
    }

    if (!rrset->add) {
        rrset->add = ldns_dnssec_rrs_new();
    }

    if (!rrset->add->rr) {
        rrset->add->rr = rr;
        rrset->add_count = 1;
        log_rr(rr, "+rr", 7);
    } else {
        status = util_dnssec_rrs_add_rr(rrset->add, rr);
        if (status != LDNS_STATUS_OK) {
            if (status == LDNS_STATUS_NO_DATA) {
                ods_log_warning("[%s] unable to add RR to RRset (%i): "
                      "duplicate", rrset_str, rrset->rr_type);
                log_rr(rr, "+rr", 2);
                return NULL;
            } else {
                ods_log_error("[%s] unable to add RR to RRset (%i): %s",
                    rrset_str, rrset->rr_type,
                    ldns_get_errorstr_by_id(status));
                log_rr(rr, "+rr", 1);
                ldns_dnssec_rrs_deep_free(rrset->add);
                rrset->add = NULL;
                rrset->add_count = 0;
                return NULL;
            }
        }
        rrset->add_count += 1;
        log_rr(rr, "+rr", 7);
    }
    return rr;
}


/**
 * Delete RR from RRset.
 *
 */
ldns_rr*
rrset_del_rr(rrset_type* rrset, ldns_rr* rr, int dupallowed)
{
    ldns_status status = LDNS_STATUS_OK;

    if (!rr) {
        ods_log_error("[%s] unable to delete RR: no RR", rrset_str);
        return NULL;
    }
    ods_log_assert(rr);

    if (!rrset) {
        ods_log_error("[%s] unable to delete RR: no storage", rrset_str);
        return NULL;
    }
    ods_log_assert(rrset);

    if (rrset->rr_type != ldns_rr_get_type(rr)) {
        ods_log_error("[%s] unable to delete RR: RRtype mismatch", rrset_str);
        return NULL;
    }

    if (!rrset->del) {
        rrset->del = ldns_dnssec_rrs_new();
    }

    if (!rrset->del->rr) {
        rrset->del->rr = rr;
        rrset->del_count = 1;
        log_rr(rr, "-rr", 7);
    } else {
        status = util_dnssec_rrs_add_rr(rrset->del, rr);
        if (status != LDNS_STATUS_OK) {
            if (status == LDNS_STATUS_NO_DATA) {
                if (dupallowed) {
                    return rr;
                }
                ods_log_warning("[%s] unable to delete RR from RRset (%i): "
                    "duplicate", rrset_str, rrset->rr_type);
                log_rr(rr, "-rr", 2);
                return NULL;
            } else {
                ods_log_error("[%s] unable to delete RR from RRset (%i): %s",
                   rrset_str, rrset->rr_type,
                   ldns_get_errorstr_by_id(status));
                log_rr(rr, "-rr", 1);
                ldns_dnssec_rrs_deep_free(rrset->del);
                rrset->del = NULL;
                rrset->del_count = 0;
                return NULL;
            }
        }
        rrset->del_count += 1;
        log_rr(rr, "-rr", 7);
    }
    return rr;
}


/**
 * Wipe out current RRs in RRset.
 *
 */
ods_status
rrset_wipe_out(rrset_type* rrset)
{
    ldns_dnssec_rrs* rrs = NULL;
    ldns_rr* del_rr = NULL;
    int error = 0;

    if (rrset) {
        rrs = rrset->rrs;
    }

    while (rrs) {
        if (rrs->rr) {
            del_rr = ldns_rr_clone(rrs->rr);
            if (rrset_del_rr(rrset, del_rr,
                (ldns_rr_get_type(del_rr) == LDNS_RR_TYPE_DNSKEY)) == NULL) {
                ods_log_error("[%s] unable to wipe RR from RRset (%i)",
                    rrset_str, rrset->rr_type);
                ldns_rr_free(del_rr);
                error = 1;
            }
            del_rr = NULL;
        }
        rrs = rrs->next;
    }

    if (error) {
        return ODS_STATUS_ERR;
    }
    return ODS_STATUS_OK;
}


/**
 * Calculate differences between the current RRset and the pending new one.
 *
 */
ods_status
rrset_diff(rrset_type* rrset, keylist_type* kl)
{
    ods_status status = ODS_STATUS_OK;
    ldns_status lstatus = LDNS_STATUS_OK;
    ldns_dnssec_rrs* current = NULL;
    ldns_dnssec_rrs* pending = NULL;
    ldns_dnssec_rrs* prev = NULL;
    ldns_rr* rr = NULL;
    int cmp = 0;

    if (!rrset) {
        return status;
    }

    current = rrset->rrs;
    pending = rrset->add;

    if (!current || !current->rr) {
        current = NULL;
    }
    if (!pending || !pending->rr) {
        pending = NULL;
    }

    while (current && pending) {
        lstatus = util_dnssec_rrs_compare(current->rr, pending->rr, &cmp);
        if (lstatus != LDNS_STATUS_OK) {
                ods_log_error("[%s] diff failed: compare failed (%s)",
                    rrset_str, ldns_get_errorstr_by_id(lstatus));
                return ODS_STATUS_ERR;
        }

        if (cmp > 0) {
            prev = pending;
            pending = pending->next;
        } else if (cmp < 0) {
            /* pend current RR to be removed */
            if (rrset->rr_type != LDNS_RR_TYPE_DNSKEY ||
                !keylist_lookup_by_dnskey(kl, current->rr)) {

                rr = ldns_rr_clone(current->rr);
                rr = rrset_del_rr(rrset, rr,
                    (ldns_rr_get_type(rr) == LDNS_RR_TYPE_DNSKEY));
                if (!rr) {
                    ods_log_error("[%s] diff failed: failed to delete RR",
                        rrset_str);
                    return ODS_STATUS_ERR;
                }
            }

            current = current->next;
        } else { /* equal RRs */
            /* remove pending RR */
            if (!prev) {
                rrset->add = pending->next;
            } else {
                prev->next = pending->next;
            }
            pending->next = NULL;
            rrset->add_count -= 1;

            ldns_dnssec_rrs_deep_free(pending);
            pending = NULL;

            current = current->next;
            if (!prev) {
                pending = rrset->add;
            } else {
                pending = prev->next;
            }
        }
    }

    if (pending) {
        ods_log_assert(!current);
        /* all newly added RRs */
    }

    if (current) {
        ods_log_assert(!pending);
        while (current) {
            /* pend current RR to be removed */
            if (rrset->rr_type != LDNS_RR_TYPE_DNSKEY ||
                !keylist_lookup_by_dnskey(kl, current->rr)) {

                rr = ldns_rr_clone(current->rr);
                rr = rrset_del_rr(rrset, rr,
                    (ldns_rr_get_type(rr) == LDNS_RR_TYPE_DNSKEY));
                if (!rr) {
                    ods_log_error("[%s] diff failed: failed to delete RR",
                        rrset_str);
                    return ODS_STATUS_ERR;
                }
            }
            current = current->next;
        }
    }
    return ODS_STATUS_OK;
}


/**
 * Commit deletion.
 *
 */
static ods_status
rrset_commit_del(rrset_type* rrset, ldns_rr* rr)
{
    ldns_status status = LDNS_STATUS_OK;
    ldns_dnssec_rrs* rrs = NULL;
    ldns_dnssec_rrs* prev_rrs = NULL;
    int cmp = 0;

    if (!rr) {
        ods_log_error("[%s] unable to commit del RR: no RR", rrset_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rr);
    if (!rrset) {
        ods_log_error("[%s] unable to commit del RR: no storage", rrset_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rrset);

    rrs = rrset->rrs;
    while (rrs) {
        status = util_dnssec_rrs_compare(rrs->rr, rr, &cmp);
        if (status != LDNS_STATUS_OK) {
            ods_log_error("[%s] unable to commit del RR: compare failed",
                rrset_str);
            return ODS_STATUS_ERR;
        }

        if (cmp == 0) {
            /* this is it */
            if (prev_rrs) {
                prev_rrs->next = rrs->next;
            } else {
                rrset->rrs = rrs->next;
            }
            rrs->next = NULL;
            ldns_dnssec_rrs_deep_free(rrs);
            rrs = NULL;

            rrset->rr_count -= 1;
            rrset->del_count -= 1;
            log_rr(rr, "-RR", 3);
            return ODS_STATUS_OK;
        }

        /* keep looking */
        prev_rrs = rrs;
        rrs = rrs->next;
    }

    ods_log_warning("[%s] unable to commit del RR: no such RR", rrset_str);
    log_rr(rr, "-RR", 2);
    return ODS_STATUS_UNCHANGED;
}


/**
 * Commit addition.
 *
 */
static ods_status
rrset_commit_add(rrset_type* rrset, ldns_rr* rr)
{
    ldns_status status = LDNS_STATUS_OK;

    if (!rr) {
        ods_log_error("[%s] unable to commit add RR: no RR", rrset_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rr);
    if (!rrset) {
        ods_log_error("[%s] unable to commit add RR: no storage", rrset_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rrset);

    if (!rrset->rrs) {
        rrset->rrs = ldns_dnssec_rrs_new();
    }

    if (!rrset->rrs->rr) {
        rrset->rrs->rr = rr;
        rrset->rr_count += 1;
        rrset->add_count -= 1;
        log_rr(rr, "+RR", 3);
        return ODS_STATUS_OK;
    } else {
        status = util_dnssec_rrs_add_rr(rrset->rrs, rr);
        if (status != LDNS_STATUS_OK) {
            if (status == LDNS_STATUS_NO_DATA) {
                ods_log_warning("[%s] unable to commit add RR: duplicate",
                    rrset_str);
                log_rr(rr, "+RR", 2);
                return ODS_STATUS_UNCHANGED;
            } else {
                ods_log_error("[%s] unable to commit add RR: %s",
                    rrset_str, ldns_get_errorstr_by_id(status));
                log_rr(rr, "+RR", 1);
                return ODS_STATUS_ERR;
            }
        }
        log_rr(rr, "+RR", 3);
        rrset->rr_count += 1;
        rrset->add_count -= 1;
        return ODS_STATUS_OK;
    }
    /* not reached */
    return ODS_STATUS_ERR;
}


/**
 * Commit updates from RRset.
 *
 */
ods_status
rrset_commit(rrset_type* rrset)
{
    ldns_dnssec_rrs* rrs = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!rrset) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rrset);

    if (rrset->del_count || rrset->add_count) {
        rrset->drop_signatures = 1;
    }

    /* delete RRs */
    rrs = rrset->del;
    while (rrs) {
        status = rrset_commit_del(rrset, rrs->rr);
        if (status != ODS_STATUS_OK) {
            ods_log_alert("[%s] commit RRset (%i) failed", rrset_str,
                rrset->rr_type);
            return status;
        }
        rrs = rrs->next;
    }
    ldns_dnssec_rrs_deep_free(rrset->del);
    rrset->del = NULL;
    rrset->del_count = 0;

    /* add RRs */
    rrs = rrset->add;
    while (rrs) {
        status = rrset_commit_add(rrset, rrs->rr);
        if (status != ODS_STATUS_OK) {
            ods_log_alert("[%s] commit RRset (%i) failed", rrset_str,
                rrset->rr_type);
            return status;
        }
        rrs = rrs->next;
    }
    ldns_dnssec_rrs_free(rrset->add);
    rrset->add = NULL;
    rrset->add_count = 0;

    /* update serial */

    return ODS_STATUS_OK;
}


/**
 * Rollback updates from RRset.
 *
 */
void
rrset_rollback(rrset_type* rrset)
{
    if (!rrset) {
        return;
    }

    if (rrset->add) {
        ldns_dnssec_rrs_deep_free(rrset->add);
        rrset->add = NULL;
        rrset->add_count = 0;
    }
    if (rrset->del) {
        ldns_dnssec_rrs_deep_free(rrset->del);
        rrset->del = NULL;
        rrset->del_count = 0;
    }
    return;
}


/**
 * Recover RR from backup.
 *
 */
int
rrset_recover_rr_from_backup(rrset_type* rrset, ldns_rr* rr)
{
    return !(rrset_commit_add(rrset, rr) == LDNS_STATUS_OK);
}


/**
 * Recover RR from backup.
 *
 */
int
rrset_recover_rrsig_from_backup(rrset_type* rrset, ldns_rr* rrsig,
    const char* locator, uint32_t flags)
{
    int error = 0;

    ods_log_assert(rrset);
    ods_log_assert(rrsig);

    if (!rrset->rrsigs) {
        rrset->rrsigs = rrsigs_create();
    }

    error = rrsigs_add_sig(rrset->rrsigs, rrsig, locator, flags);
    if (!error) {
        rrset->rrsig_count += 1;
    } else {
        switch (error) {
            case 2:
                ods_log_warning("[%s] error adding RRSIG to RRset (%i): duplicate",
                    rrset_str, rrset->rr_type);
                log_rr(rrsig, "+RR", 2);
                break;
            case 1:
                ods_log_error("[%s] error adding RRSIG to RRset (%i): compare failed",
                    rrset_str, rrset->rr_type);
                log_rr(rrsig, "+RR", 2);
                break;
            default:
                ods_log_error("[%s] error adding RRSIG to RRset (%i): unknown error",
                    rrset_str, rrset->rr_type);
                log_rr(rrsig, "+RR", 2);
                break;
        }
    }
    return error;
}


/**
 * Drop signatures from RRset.
 *
 */
static int
rrset_recycle_rrsigs(rrset_type* rrset, signconf_type* sc, time_t signtime,
    uint32_t* reusedsigs)
{
    rrsigs_type* rrsigs = NULL;
    rrsigs_type* prev_rrsigs = NULL;
    rrsigs_type* next_rrsigs = NULL;
    uint32_t refresh = 0;
    uint32_t expiration = 0;
    uint32_t inception = 0;
    int drop_sig = 0;
    key_type* key = NULL;

    if (sc && sc->sig_refresh_interval) {
        refresh = (uint32_t) (signtime +
            duration2time(sc->sig_refresh_interval));
    }

    /* 1. If the RRset has changed, drop all signatures */
    /* 2. If Refresh is disabled, drop all signatures */
    if (rrset->drop_signatures || !refresh) {
        ods_log_debug("[%s] drop signatures for RRset[%i]", rrset_str, rrset->rr_type);
        if (rrset->rrsigs) {
            rrsigs_cleanup(rrset->rrsigs);
            rrset->rrsigs = NULL;
        }
        rrset->rrsig_count = 0;
        rrset->drop_signatures = 0;
        return 0;
    }

    /* 3. Check every signature if it matches the recycling logic. */
    rrsigs = rrset->rrsigs;
    while (rrsigs) {
        if (!rrsigs->rr) {
            ods_log_warning("[%s] signature set has no RRSIG record: "
                "drop signatures for RRset[%i]", rrset_str, rrset->rr_type);
            rrsigs_cleanup(rrset->rrsigs);
            rrset->rrsigs = NULL;
            rrset->rrsig_count = 0;
            rrset->drop_signatures = 0;
            return 0;
        }

        expiration = ldns_rdf2native_int32(
            ldns_rr_rrsig_expiration(rrsigs->rr));
        inception = ldns_rdf2native_int32(
            ldns_rr_rrsig_inception(rrsigs->rr));

        if (expiration < refresh) {
            /* 3a. Expiration - Refresh has passed */
            drop_sig = 1;
            ods_log_deeebug("[%s] refresh signature for RRset[%i]: expiration minus "
                "refresh has passed: %u - %u < (signtime)", rrset_str,
                rrset->rr_type, expiration, refresh, (uint32_t) signtime);
        } else if (inception > (uint32_t) signtime) {
            /* 3b. Inception has not yet passed */
            drop_sig = 1;
            ods_log_deeebug("[%s] refresh signature for RRset[%i]: inception has "
                "not passed: %u < %u (signtime)", rrset_str,
                rrset->rr_type, inception, (uint32_t) signtime);
        } else {
            /* 3c. Corresponding key is dead */
            key = keylist_lookup(sc->keys, rrsigs->key_locator);
            if (!key) {
                drop_sig = 1;
                ods_log_deeebug("[%s] refresh signature for RRset[%i]: key %s %u "
                "is dead", rrset_str,
                rrset->rr_type, rrsigs->key_locator, rrsigs->key_flags);
            } else if (key->flags != rrsigs->key_flags) {
                drop_sig = 1;
                ods_log_deeebug("[%s] refresh signature for RRset[%i]: key %s %u "
                "flags mismatch", rrset_str,
                rrset->rr_type, rrsigs->key_locator, rrsigs->key_flags);
            }
        }

        next_rrsigs = rrsigs->next;
        if (drop_sig) {
            /* A rule mismatched, refresh signature */
            if (prev_rrsigs) {
                prev_rrsigs->next = rrsigs->next;
            } else {
                rrset->rrsigs = rrsigs->next;
            }
            log_rr(rrsigs->rr, "-RRSIG", 7);
            rrset->rrsig_count -= 1;
            rrsigs->next = NULL;
            rrsigs_cleanup(rrsigs);
        } else {
            /* All rules ok, recycle signature */
            ods_log_deeebug("[%s] recycle signature for RRset[%i] (refresh=%u, "
                "signtime=%u, inception=%u, expiration=%u)", rrset_str, rrset->rr_type,
                refresh, (uint32_t) signtime, inception, expiration);
            log_rr(rrsigs->rr, "*RRSIG", 7);
            *reusedsigs += 1;
            prev_rrsigs = rrsigs;
        }
        rrsigs = next_rrsigs;
    }
    return 0;
}


/**
 * See if there exists a signature with this algorithm.
 *
 */
static int
rrset_signed_with_algorithm(rrset_type* rrset, uint8_t algorithm)
{
    rrsigs_type* rrsigs = NULL;

    if (!rrset || !algorithm) {
        return 0;
    }

    rrsigs = rrset->rrsigs;
    while (rrsigs) {
        if (rrsigs->rr && algorithm ==
            ldns_rdf2native_int8(ldns_rr_rrsig_algorithm(rrsigs->rr))) {
            return 1;
        }
        rrsigs = rrsigs->next;
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
    ldns_dnssec_rrs* rrs = NULL;
    ldns_rr_list* rr_list = NULL;
    int error = 0;

    rr_list = ldns_rr_list_new();
    rrs = rrset->rrs;
    while (rrs && rrs->rr) {
        error = (int) ldns_rr_list_push_rr(rr_list, rrs->rr);
        if (!error) {
            ldns_rr_list_free(rr_list);
            return NULL;
        }
        if (rrset->rr_type == LDNS_RR_TYPE_CNAME ||
            rrset->rr_type == LDNS_RR_TYPE_DNAME) {
            /* singleton types */
            return rr_list;
        }
        rrs = rrs->next;
    }
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

    /**
     * Additional check for signature lifetimes.
     */
    if (((validity + offset + random_jitter) - jitter) <
        ((validity + offset) - jitter) ) {
        ods_log_error("[%s] signature validity %u too low, should be at "
            "least %u", rrset_str,
            ((validity + offset + random_jitter) - jitter),
            ((validity + offset) - jitter));
    } else if (((validity + offset + random_jitter) - jitter) >
               ((validity + offset) + jitter) ) {
        ods_log_error("[%s] signature validity %u too high, should be at "
            "most %u", rrset_str,
            ((validity + offset + random_jitter) - jitter),
            ((validity + offset) + jitter));
    } else {
        ods_log_debug("[%s] signature validity %u in range [%u - %u]",
            rrset_str, ((validity + offset + random_jitter) - jitter),
            ((validity + offset) - jitter),
            ((validity + offset) + jitter));
    }
    *inception = signtime - offset;
    *expiration = (signtime + validity + random_jitter) - jitter;
    return;
}


/**
 * Sign RRset.
 *
 */
int
rrset_sign(hsm_ctx_t* ctx, rrset_type* rrset, ldns_rdf* owner,
    signconf_type* sc, time_t signtime, stats_type* stats)
{
    int error = 0;
    uint32_t newsigs = 0;
    uint32_t reusedsigs = 0;
    ldns_rr* rrsig = NULL;
    ldns_rr_list* rr_list = NULL;
    rrsigs_type* new_rrsigs = NULL;
    rrsigs_type* walk_rrsigs = NULL;
    key_type* key = NULL;
    time_t inception = 0;
    time_t expiration = 0;

    if (!rrset) {
        ods_log_error("[%s] unable to sign RRset: no RRset", rrset_str);
        return 1;
    }
    ods_log_assert(rrset);

    if (!owner) {
        ods_log_error("[%s] unable to sign RRset: no owner", rrset_str);
        return 1;
    }
    ods_log_assert(owner);

    if (!sc) {
        ods_log_error("[%s] unable to sign RRset: no signconf", rrset_str);
        return 1;
    }
    ods_log_assert(sc);

    /* drop unrecyclable signatures */
    error = rrset_recycle_rrsigs(rrset, sc, signtime, &reusedsigs);

    /* convert the RRset */
    rr_list = rrset2rrlist(rrset);
    if (!rr_list) {
        ods_log_error("[%s] unable to sign RRset[%i]: to RRlist failed",
            rrset->rr_type);
        return 1;
    }
    if (ldns_rr_list_rr_count(rr_list) <= 0) {
        /* empty RRset, no signatures needed */
        ldns_rr_list_free(rr_list);
        return 0;
    }

    /* prepare for signing */
    new_rrsigs = rrsigs_create();
    if (!rrset->rrsigs) {
        rrset->rrsigs = rrsigs_create();
    }
    rrset_sigvalid_period(sc, rrset->rr_type, signtime,
         &inception, &expiration);

    key = sc->keys->first_key;
    while (key) {
        /* ksk or zsk ? */
        if (!key->zsk && rrset->rr_type != LDNS_RR_TYPE_DNSKEY) {
            ods_log_deeebug("[%s] skipping key %s for signing RRset[%i]: no "
                "active ZSK", rrset_str, key->locator, rrset->rr_type);
            key = key->next;
            continue;
        }
        if (!key->ksk && rrset->rr_type == LDNS_RR_TYPE_DNSKEY) {
            ods_log_deeebug("[%s] skipping key %s for signing RRset[%i]: no "
                "active KSK", rrset_str, key->locator, rrset->rr_type);
            key = key->next;
            continue;
        }

        /* is there a signature with this algorithm already? */
        if (rrset_signed_with_algorithm(rrset, key->algorithm)) {
            ods_log_deeebug("skipping key %s for signing: RRset[%i] "
                "already has signature with same algorithm", key->locator);
            key = key->next;
            continue;
        }

        /**
         * currently, there is no rule that the number of signatures
         * over this RRset equals the number of active keys.
         */

        /* sign the RRset with current key */
        ods_log_deeebug("[%s] signing RRset[%i] with key %s", rrset_str,
            rrset->rr_type, key->locator);
        rrsig = lhsm_sign(ctx, rr_list, key, owner, inception, expiration);
        if (!rrsig) {
            ods_log_error("[%s] unable to sign RRset[%i]: error creating "
                "RRSIG RR", rrset_str, rrset->rr_type);
            ldns_rr_list_free(rr_list);
            rrsigs_cleanup(new_rrsigs);
            return 1;
        }
        /* add the signature to the set of new signatures */
        ods_log_deeebug("[%s] new signature created for RRset[%i]", rrset_str,
            rrset->rr_type);
        error = rrsigs_add_sig(new_rrsigs, rrsig, key->locator,
            key->flags);
        if (error) {
            ods_log_error("[%s] unable to sign RRset[%i]: error adding RRSIG",
                rrset_str, rrset->rr_type);
                log_rr(rrsig, "+RRSIG", 1);
                ldns_rr_list_free(rr_list);
                rrsigs_cleanup(new_rrsigs);
            return 1;
        }
        /* next key */
        key = key->next;
    }

    /* signing completed, add the signatures to the right RRset */
    walk_rrsigs = new_rrsigs;
    while (walk_rrsigs) {
        if (walk_rrsigs->rr) {
            ods_log_deeebug("[%s] adding signature to RRset[%i]", rrset_str,
                    rrset->rr_type);
            error = rrsigs_add_sig(rrset->rrsigs,
                ldns_rr_clone(walk_rrsigs->rr),
                walk_rrsigs->key_locator, walk_rrsigs->key_flags);
            if (error) {
                ods_log_error("[%s] unable to sign RRset[%i]: error adding "
                    "RRSIG to RRset[%i]", rrset_str, rrset->rr_type);
                log_rr(walk_rrsigs->rr, "+RRSIG", 1);
                ldns_rr_list_free(rr_list);
                rrsigs_cleanup(new_rrsigs);
                return 1;
            }
            rrset->rrsig_count += 1;
            newsigs++;
            log_rr(walk_rrsigs->rr, "+RRSIG", 6);
        }
        walk_rrsigs = walk_rrsigs->next;
    }

    /* clean up */
    rrsigs_cleanup(new_rrsigs);
    ldns_rr_list_free(rr_list);

    if (rrset->rr_type == LDNS_RR_TYPE_SOA) {
        stats->sig_soa_count += newsigs;
    }
    stats->sig_count += newsigs;
    stats->sig_reuse += reusedsigs;
    return 0;
}


/**
 * Clean up RRset.
 *
 */
void
rrset_cleanup(rrset_type* rrset)
{
    if (!rrset) {
        return;
    }
    if (rrset->rrs) {
        ldns_dnssec_rrs_deep_free(rrset->rrs);
        rrset->rrs = NULL;
    }
    if (rrset->add) {
        ldns_dnssec_rrs_deep_free(rrset->add);
        rrset->add = NULL;
    }
    if (rrset->del) {
        ldns_dnssec_rrs_deep_free(rrset->del);
        rrset->del = NULL;
    }
    if (rrset->rrsigs) {
        rrsigs_cleanup(rrset->rrsigs);
        rrset->rrsigs = NULL;
    }
    se_free((void*) rrset);
    return;
}


/**
 * Print RRset.
 *
 */
void
rrset_print(FILE* fd, rrset_type* rrset, int skip_rrsigs)
{
    if (!rrset || !fd) {
        return;
    }
    ods_log_assert(fd);
    ods_log_assert(rrset);

    if (rrset->rrs) {
        if (rrset->rr_type == LDNS_RR_TYPE_CNAME ||
            rrset->rr_type == LDNS_RR_TYPE_DNAME) {
            /* singleton types */
            if (rrset->rrs->rr) {
                ldns_rr_print(fd, rrset->rrs->rr);
            }
        } else {
            ldns_dnssec_rrs_print(fd, rrset->rrs);
        }
    }
    if (rrset->rrsigs && !skip_rrsigs) {
        rrsigs_print(fd, rrset->rrsigs, 0);
    }
    return;
}


/**
 * Print RRSIGs from RRset.
 *
 */
void
rrset_print_rrsig(FILE* fd, rrset_type* rrset)
{
    if (!rrset || !fd) {
        return;
    }
    ods_log_assert(fd);
    ods_log_assert(rrset);

    if (rrset->rrsigs) {
        rrsigs_print(fd, rrset->rrsigs, 1);
    }
    return;
}
