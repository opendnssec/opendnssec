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
#include "shared/duration.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/zone.h"

#include <ldns/ldns.h>

static const char* adapi_str = "adapter";


/**
 * Get the inbound serial.
 *
 */
uint32_t
adapi_get_serial(zone_type* zone)
{
    if (!zone || !zone->zonedata) {
        ods_log_error("[%s] unable to get serial: "
            "no zone data", adapi_str);
        return 0;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->zonedata);
    return zone->zonedata->inbound_serial;
}


/**
 * Set the inbound serial.
 *
 */
void
adapi_set_serial(zone_type* zone, uint32_t serial)
{
    if (!zone || !zone->zonedata) {
        ods_log_error("[%s] unable to set serial: "
            "no zone data", adapi_str);
        return;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->zonedata);
    zone->zonedata->inbound_serial = serial;
    return;
}


/**
 * Get origin.
 *
 */
ldns_rdf*
adapi_get_origin(zone_type* zone)
{
    if (!zone) {
        ods_log_error("[%s] unable to get origin: "
            "no zone", adapi_str);
        return NULL;
    }
    ods_log_assert(zone);
    return zone->dname;
}


/**
 * Get ttl.
 *
 */
uint32_t
adapi_get_ttl(zone_type* zone)
{
    if (!zone || !zone->zonedata) {
        ods_log_error("[%s] unable to get ttl: "
            "no zone data", adapi_str);
        return 0;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->zonedata);
    return zone->zonedata->default_ttl;
}


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
    ldns_rdf* soa_min = NULL;
    ldns_rr_type type = LDNS_RR_TYPE_FIRST;
    uint32_t tmp = 0;

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

    if (!zone->signconf) {
        ods_log_error("[%s] unable to add RR: no signconf", adapi_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf);

    /* in-zone? */
    if (ldns_dname_compare(zone->dname, ldns_rr_owner(rr)) != 0 &&
        !ldns_dname_is_subdomain(ldns_rr_owner(rr), zone->dname)) {
        ods_log_warning("[%s] zone %s contains out-of-zone data, skipping",
            adapi_str, zone->name?zone->name:"(null)");
        /* ok, just filter */
        return ODS_STATUS_OK;
    }

    /* type specific configuration */
    type = ldns_rr_get_type(rr);
    if (type == LDNS_RR_TYPE_DNSKEY && zone->signconf->dnskey_ttl) {
        tmp = (uint32_t) duration2time(zone->signconf->dnskey_ttl);
        ods_log_verbose("[%s] zone %s set DNSKEY TTL to %u",
            adapi_str, zone->name?zone->name:"(null)", tmp);
        ldns_rr_set_ttl(rr, tmp);
    }
    if (type == LDNS_RR_TYPE_SOA) {
        if (zone->signconf->soa_ttl) {
            tmp = (uint32_t) duration2time(zone->signconf->soa_ttl);
            ods_log_verbose("[%s] zone %s set SOA TTL to %u",
                adapi_str, zone->name?zone->name:"(null)", tmp);
            ldns_rr_set_ttl(rr, tmp);
        }
        if (zone->signconf->soa_min) {
            tmp = (uint32_t) duration2time(zone->signconf->soa_min);
            ods_log_verbose("[%s] zone %s set SOA MINIMUM to %u",
                adapi_str, zone->name?zone->name:"(null)", tmp);
            soa_min = ldns_rr_set_rdf(rr,
                ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, tmp),
                SE_SOA_RDATA_MINIMUM);
            if (soa_min) {
                ldns_rdf_deep_free(soa_min);
            } else {
                ods_log_error("[%s] zone %s failed to replace SOA MINIMUM "
                    "rdata", adapi_str, zone->name?zone->name:"(null)");
                return ODS_STATUS_ASSERT_ERR;
            }
        }
    }

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
