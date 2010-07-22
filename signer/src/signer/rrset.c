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
#include "signer/hsm.h"
#include "signer/rrset.h"
#include "util/duration.h"
#include "util/log.h"
#include "util/se_malloc.h"
#include "util/util.h"

#include <ldns/ldns.h> /* ldns_rr_*(), ldns_dnssec_*() */


/**
 * Create new RRset.
 *
 */
rrset_type*
rrset_create(ldns_rr_type rrtype)
{
    rrset_type* rrset = (rrset_type*) se_calloc(1, sizeof(rrset_type));
    se_log_assert(rrtype);
    rrset->rr_type = rrtype;
    rrset->rr_count = 0;
    rrset->inbound_serial = 0;
    rrset->outbound_serial = 0;
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
    se_log_assert(rr);
    rrset->rr_type = ldns_rr_get_type(rr);
    rrset->rr_count = 1;
    rrset->inbound_serial = 0;
    rrset->outbound_serial = 0;
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
                return 1;
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
 * Log RR.
 *
 */
static void
rrset_log_rr(ldns_rr* rr, const char* pre, int level)
{
    char* str = NULL;

    str = ldns_rr2str(rr);
    str[(strlen(str))-1] = '\0';
    if (level == 1) {
        se_log_error("%s %s", pre, str);
    } else if (level == 2) {
        se_log_warning("%s %s", pre, str);
    } else if (level == 3) {
        se_log_info("%s %s", pre, str);
    } else if (level == 4) {
        se_log_verbose("%s %s", pre, str);
    } else {
        se_log_debug("%s %s", pre, str);
    }
    se_free((void*)str);
    return;
}


/**
 * Add pending RR.
 *
 */
static ldns_status
rrset_add_pending_rr(rrset_type* rrset, ldns_rr* rr)
{
    ldns_status status = LDNS_STATUS_OK;

    if (!rrset->rrs) {
        rrset->rrs = ldns_dnssec_rrs_new();
    }

    if (!rrset->rrs->rr) {
        rrset->rrs->rr = rr;
        rrset->rr_count += 1;
        rrset_log_rr(rr, "+RR", 5);
        return LDNS_STATUS_OK;
    } else {
        status = util_dnssec_rrs_add_rr(rrset->rrs, rr);
        if (status != LDNS_STATUS_OK) {
            if (status == LDNS_STATUS_NO_DATA) {
                se_log_warning("error adding RR to RRset (%i): duplicate",
                    rrset->rr_type);
                rrset_log_rr(rr, "+RR", 2);
                return LDNS_STATUS_OK;
            } else {
                se_log_error("error adding RR to RRset (%i): %s",
                    rrset->rr_type, ldns_get_errorstr_by_id(status));
                rrset_log_rr(rr, "+RR", 1);
                return status;
            }
        }
        rrset_log_rr(rr, "+RR", 5);
        rrset->rr_count += 1;
        return LDNS_STATUS_OK;
    }
    return LDNS_STATUS_ERR;
}


/**
 * Delete pending RR.
 *
 */
static int
rrset_del_pending_rr(rrset_type* rrset, ldns_rr* rr)
{
    ldns_dnssec_rrs* rrs = NULL;
    ldns_dnssec_rrs* prev_rrs = NULL;

    rrs = rrset->rrs;
    while (rrs) {
        if (ldns_rr_compare(rrs->rr, rr) == 0) {
            /* this is it */
            if (prev_rrs) {
                prev_rrs->next = rrs->next;
            } else {
                rrset->rrs = rrs->next;
            }
            ldns_rr_free(rrs->rr);
            se_free((void*)rrs);
            return 1;
        }
        prev_rrs = rrs;
        rrs = rrs->next;
    }
    rrset_log_rr(rr, "-RR", 2);
    return 0;
}


/**
 * Add RR to RRset.
 *
 */
int
rrset_update(rrset_type* rrset, uint32_t serial)
{
    ldns_dnssec_rrs* rrs = NULL;
    int addcount = 0;
    int delcount = 0;

    se_log_assert(rrset);
    se_log_assert(serial);

    if (DNS_SERIAL_GT(serial, rrset->inbound_serial)) {
        /* compare del and add */
        if (rrset_compare_rrs(rrset->del, rrset->add) != 0) {
            rrset->drop_signatures = 1;
        }

        /* delete RRs */
        rrs = rrset->del;
        while (rrs) {
            if (rrs->rr) {
                delcount = rrset_del_pending_rr(rrset, rrs->rr);
            }
            rrs = rrs->next;
        }
        ldns_dnssec_rrs_deep_free(rrset->del);
        rrset->del = NULL;

        /* add RRs */
        rrs = rrset->add;
        while (rrs) {
            if (rrs->rr) {
                addcount = rrset_add_pending_rr(rrset, rrs->rr);
            }
            rrs = rrs->next;
        }
        ldns_dnssec_rrs_free(rrset->add);
        rrset->add = NULL;
        rrset->rr_count = rrset->rr_count + addcount;
        rrset->rr_count = rrset->rr_count - delcount;
        rrset->inbound_serial = serial;
    }
    return 0;
}


/**
 * Return the number of RRs in RRset.
 *
 */
int
rrset_count_rr(rrset_type* rrset)
{
    se_log_assert(rrset);
    return rrset->rr_count;
}


/**
 * Add RR to RRset.
 *
 */
int
rrset_add_rr(rrset_type* rrset, ldns_rr* rr)
{
    ldns_status status = LDNS_STATUS_OK;

    se_log_assert(rr);
    se_log_assert(rrset);
    se_log_assert(ldns_rr_get_type(rr) == rrset->rr_type);

    if (!rrset->add) {
        rrset->add = ldns_dnssec_rrs_new();
    }

    if (!rrset->add->rr) {
        rrset->add->rr = rr;
        rrset_log_rr(rr, "+rr", 5);
    } else {
        status = util_dnssec_rrs_add_rr(rrset->add, rr);
        if (status != LDNS_STATUS_OK) {
            if (status == LDNS_STATUS_NO_DATA) {
                se_log_warning("error adding RR to pending add RRset (%i): "
                    "duplicate", rrset->rr_type);
                rrset_log_rr(rr, "+rr", 2);
                return 0;
            } else {
                se_log_error("error adding RR to pending add RRset (%i): %s",
                    rrset->rr_type, ldns_get_errorstr_by_id(status));
                rrset_log_rr(rr, "+rr", 1);
                return 1;
            }
        }
        rrset_log_rr(rr, "+rr", 5);
    }
    return 0;
}


/**
 * Delete RR from RRset.
 *
 */
int
rrset_del_rr(rrset_type* rrset, ldns_rr* rr)
{
    ldns_status status = LDNS_STATUS_OK;

    se_log_assert(rr);
    se_log_assert(rrset);
    se_log_assert(ldns_rr_get_type(rr) == rrset->rr_type);

    if (!rrset->del) {
        rrset->del = ldns_dnssec_rrs_new();
    }

    if (!rrset->del->rr) {
        rrset->del->rr = rr;
        rrset_log_rr(rr, "-rr", 5);
    } else {
        status = util_dnssec_rrs_add_rr(rrset->del, rr);
        if (status != LDNS_STATUS_OK) {
            if (status == LDNS_STATUS_NO_DATA) {
                se_log_warning("error adding RR to pending del RRset (%i): "
                    "duplicate", rrset->rr_type);
                rrset_log_rr(rr, "-rr", 2);
                return 0;
            } else {
                se_log_error("error adding RR to pending del RRset (%i): %s",
                   rrset->rr_type, ldns_get_errorstr_by_id(status));
                rrset_log_rr(rr, "-rr", 1);
                return 1;
            }
        }
        rrset_log_rr(rr, "-rr", 5);
    }
    return 0;
}


/**
 * Drop signatures from RRset.
 *
 */
static int
rrset_drop_rrsigs(rrset_type* rrset, signconf_type* sc, time_t signtime)
{
    ldns_dnssec_rrs* rrs = NULL;
    ldns_dnssec_rrs* prev_rrs = NULL;
    uint32_t refresh = 0;
    uint32_t expiration = 0;

    if (rrset->drop_signatures) {
        se_log_debug("drop signatures for RRset[%i]", rrset->rr_type);
        if (rrset->rrsigs) {
            ldns_dnssec_rrs_deep_free(rrset->rrsigs);
            rrset->rrsigs = NULL;
        }
        rrset->drop_signatures = 0;
        return 0;
    }

    /* check freshness of existing signatures */
    rrs = rrset->rrsigs;
    while (rrs) {
        expiration = ldns_rdf2native_int32(ldns_rr_rrsig_expiration(rrs->rr));
        if (sc->sig_refresh_interval) {
            refresh = (uint32_t) (signtime +
                duration2time(sc->sig_refresh_interval));
        } else {
            refresh = 0;
        }

        if (!refresh || expiration < refresh) {
            /* this is it */
            se_log_debug("refresh signatures for RRset[%i] (refresh=%u, "
                "expiration=%u)", rrset->rr_type, refresh, expiration);
            if (prev_rrs) {
                prev_rrs->next = rrs->next;
            } else {
                rrset->rrsigs = rrs->next;
            }
            rrset_log_rr(rrs->rr, "-RRSIG", 5);
            ldns_rr_free(rrs->rr);
            se_free((void*)rrs);
        }
        prev_rrs = rrs;
        rrs = rrs->next;
    }
    return 0;
}


/**
 * Set the inception and expiration values for int the RRSIG RDATA.
 *
 */
static void
rrset_sign_set_timers(signconf_type* sc, ldns_rr_type rrtype, time_t signtime,
    time_t* inception, time_t* expiration)
{
    time_t jitter = 0;
    time_t offset = 0;
    time_t validity = 0;
    time_t random_jitter = 0;

    se_log_assert(sc);
    se_log_assert(rrtype);
    se_log_assert(signtime);

    jitter = duration2time(sc->sig_jitter);
    if (jitter) {
        random_jitter = se_rand(jitter*2);
    }
    offset = duration2time(sc->sig_inception_offset);
    if (rrtype == LDNS_RR_TYPE_NSEC || rrtype == LDNS_RR_TYPE_NSEC3) {
        validity = duration2time(sc->sig_validity_denial);
    } else {
        validity = duration2time(sc->sig_validity_default);
    }
    *inception = signtime - offset;
    *expiration = signtime + validity - jitter + random_jitter;
    return;
}


/**
 * Convert RRset to RR list.
 *
 */
static ldns_rr_list*
rrset2rrlist(rrset_type* rrset)
{
    ldns_dnssec_rrs* rrs = NULL;
    ldns_rr_list* rr_list;
    int error = 0;

    rr_list = ldns_rr_list_new();
    rrs = rrset->rrs;
    while (rrs) {
        error  = (int) ldns_rr_list_push_rr(rr_list, rrs->rr);
        if (!error) {
            ldns_rr_list_free(rr_list);
            return NULL;
        }
        rrs = rrs->next;
    }
    return rr_list;
}


/**
 * Sign RRset.
 *
 */
int
rrset_sign(hsm_ctx_t* ctx, rrset_type* rrset, ldns_rdf* owner,
    signconf_type* sc, time_t signtime)
{
    int error = 0;
    ldns_status status = LDNS_STATUS_OK;
    ldns_rr* rrsig = NULL;
    ldns_rr_list* rr_list = NULL;
    key_type* key = NULL;
    time_t inception = 0;
    time_t expiration = 0;

    se_log_assert(rrset);
    se_log_assert(sc);

    if (DNS_SERIAL_GT(rrset->inbound_serial, rrset->outbound_serial)) {
        error = rrset_drop_rrsigs(rrset, sc, signtime);
        if (!rrset->rrsigs) {
            rrset->rrsigs = ldns_dnssec_rrs_new();
        }
        if (!rrset->rrsigs->rr) {
            /* signatures were dropped, create new */
            rr_list = rrset2rrlist(rrset);
            if (!rr_list) {
                se_log_error("error signing rrset[%i], cannot convert to rr "
                    "list", rrset->rr_type);
                return 1;
            }
            rrset_sign_set_timers(sc, rrset->rr_type, signtime,
                 &inception, &expiration);
            key = sc->keys->first_key;
            while (key) {
                if ((!key->zsk && rrset->rr_type != LDNS_RR_TYPE_DNSKEY) ||
                    (!key->ksk && rrset->rr_type == LDNS_RR_TYPE_DNSKEY)) {
                    key = key->next;
                    continue;
                }
                rrsig = hsm_sign_rrset_with_key(ctx, owner, key, rr_list,
                     inception, expiration);
                if (!rrsig) {
                    se_log_error("error creating RRSIG for rrset[%i]",
                        rrset->rr_type);
                    ldns_rr_list_free(rr_list);
                    return 1;
                }
                if (!rrset->rrsigs->rr) {
                    rrset->rrsigs->rr = rrsig;
                    rrset_log_rr(rrsig, "+RRSIG", 5);
                } else {
                    status = util_dnssec_rrs_add_rr(rrset->rrsigs, rrsig);
                    if (status != LDNS_STATUS_OK) {
                        if (status == LDNS_STATUS_NO_DATA) {
                            se_log_warning("error adding RRSIG to RRset "
                                "(%i): duplicate", rrset->rr_type);
                            rrset_log_rr(rrsig, "+RRSIG", 2);
                        } else {
                            se_log_error("error adding RRSIG to RRset "
                                "(%i): %s", rrset->rr_type,
                                ldns_get_errorstr_by_id(status));
                            rrset_log_rr(rrsig, "+RRSIG", 1);
                            ldns_rr_list_free(rr_list);
                            return 1;
                        }
                    } else {
                        rrset_log_rr(rrsig, "+RRSIG", 5);
                    }
                }
                key = key->next;
            }
        } else {
            se_log_debug("reuse signatures for RRset[%i]", rrset->rr_type);
        }
        rrset->outbound_serial = rrset->inbound_serial;
    }
    return 0;
}


/**
 * Delete all RRs from RRset.
 *
 */
int
rrset_del_rrs(rrset_type* rrset)
{
    ldns_dnssec_rrs* rrs = NULL;
    ldns_rr* rr = NULL;

    se_log_assert(rrset);
    if (!rrset->rrs) {
        return 0;
    }
    if (!rrset->del) {
        rrset->del = ldns_dnssec_rrs_new();
    }
    rrs = rrset->rrs;
    while (rrs) {
        if (rrs->rr) {
            rr = ldns_rr_clone(rrs->rr);
            if (rrset_del_rr(rrset, rr) != 0) {
                return 1;
            }
        }
        rrs = rrs->next;
    }
    return 0;
}


/**
 * Clean up RRset.
 *
 */
void
rrset_cleanup(rrset_type* rrset)
{
    if (rrset) {
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
            ldns_dnssec_rrs_deep_free(rrset->rrsigs);
            rrset->rrsigs = NULL;
        }
        se_free((void*) rrset);
    } else {
        se_log_warning("cleanup empty rrset");
    }
    return;
}


/**
 * Print RRset.
 *
 */
void
rrset_print(FILE* fd, rrset_type* rrset, int skip_rrsigs)
{
    if (rrset->rrs) {
        ldns_dnssec_rrs_print(fd, rrset->rrs);
    }
    if (rrset->rrsigs && !skip_rrsigs) {
        ldns_dnssec_rrs_print(fd, rrset->rrsigs);
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
    if (rrset->rrsigs) {
        ldns_dnssec_rrs_print(fd, rrset->rrsigs);
    }
    return;
}
