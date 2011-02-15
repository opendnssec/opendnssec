/*
 * $Id$
 *
 * Copyright (c) 2009-2011 NLNet Labs. All rights reserved.
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
 *
 * Adapter API.
 */

#include "config.h"
#include "adapter/adapi.h"
#include "shared/log.h"
#include "shared/status.h"
#include "signer/zone.h"

#include <ldns/ldns.h>

static const char* adapi_str = "adapter";


/*
 * Do full zone transaction.
 *
 */
ods_status
adapi_trans_full(zone_type* zone)
{
    if (!zone || !zone->zonedata) {
        ods_log_error("[%s] unable to start full zone transaction: "
            "no zone data", adapi_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->zonedata);
    if (!zone->signconf) {
        ods_log_error("[%s] unable to start full zone transaction: "
            "no signer configuration", adapi_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf);

    return zonedata_diff(zone->zonedata, zone->signconf->keys);
}


/*
 * Do incremental zone transaction.
 *
 */
ods_status
adapi_trans_diff(zone_type* zone)
{
    if (!zone || !zone->zonedata) {
        ods_log_error("[%s] unable to start incremental zone transaction: "
            "no zone data", adapi_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->zonedata);

    return ODS_STATUS_OK;
}


/**
 * Add RR.
 *
 */
ods_status
adapi_add_rr(zone_type* zone, ldns_rr* rr)
{
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;

    if (!rr) {
        ods_log_error("[%s] unable to add RR: no RR", adapi_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rr);

    if (!zone || !zone->zonedata) {
        ods_log_error("[%s] unable to add RR: no storage", adapi_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->zonedata);

    /* lookup domain */
    domain = zonedata_lookup_domain(zone->zonedata, ldns_rr_owner(rr));
    if (!domain) {
        /* add domain */
        domain = domain_create(ldns_rr_owner(rr));
        if (!domain) {
            ods_log_error("[%s] unable to add RR: create domain failed",
                adapi_str);
            return ODS_STATUS_ERR;
        }
        if (zonedata_add_domain(zone->zonedata, domain) == NULL) {
            ods_log_error("[%s] unable to add RR: add domain failed",
                adapi_str);
            return ODS_STATUS_ERR;
        }
        if (ldns_dname_compare(domain->dname, zone->dname) == 0) {
            domain->dstatus = DOMAIN_STATUS_APEX;
        }
    }
    ods_log_assert(domain);

    /* lookup RRset */
    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (!rrset) {
        /* add RRset */
        rrset = rrset_create(ldns_rr_get_type(rr));
        if (!rrset) {
            ods_log_error("[%s] unable to add RR: create RRset failed",
                adapi_str);
            return ODS_STATUS_ERR;
        }
        if (domain_add_rrset(domain, rrset) == NULL) {
            ods_log_error("[%s] unable to add RR: add RRset failed",
                adapi_str);
            return ODS_STATUS_ERR;
        }
    }
    ods_log_assert(rrset);

    /* add RR */
    if (rrset_add_rr(rrset, rr) == NULL) {
        ods_log_error("[%s] unable to add RR: pend RR failed", adapi_str);
        return ODS_STATUS_ERR;
    }

    return ODS_STATUS_OK;
}


/**
 * Delete RR.
 *
 */
ods_status
adapi_del_rr(zone_type* zone, ldns_rr* rr)
{
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;

    if (!rr) {
        ods_log_error("[%s] unable to del RR: no RR", adapi_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rr);

    if (!zone || !zone->zonedata) {
        ods_log_error("[%s] unable to del RR: no storage", adapi_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->zonedata);

    /* lookup domain */
    domain = zonedata_lookup_domain(zone->zonedata, ldns_rr_owner(rr));
    if (!domain) {
        /* no domain, no del */
        ods_log_warning("[%s] unable to del RR: no such domain", adapi_str);
        return ODS_STATUS_UNCHANGED;
    }
    ods_log_assert(domain);

    /* lookup RRset */
    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (!rrset) {
        /* no RRset, no del */
        ods_log_warning("[%s] unable to del RR: no such RRset", adapi_str);
        return ODS_STATUS_UNCHANGED;
    }
    ods_log_assert(rrset);

    /* del RR */
    if (rrset_del_rr(rrset, rr, (ldns_rr_get_type(rr) == LDNS_RR_TYPE_DNSKEY))
            == NULL) {
        ods_log_error("[%s] unable to del RR: pend RR failed", adapi_str);
        return ODS_STATUS_ERR;
    }
    return ODS_STATUS_OK;
}
