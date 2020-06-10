/*
 * Copyright (c) 2009-2018 NLNet Labs.
 * All rights reserved.
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
 */

/**
 *
 * Adapter API.
 */

#include "config.h"
#include "hsm.h"
#include "signer/signconf.h"
#include "adapter/adapi.h"
#include "duration.h"
#include "log.h"
#include "status.h"
#include "util.h"
#include "signer/zone.h"

#include <ldns/ldns.h>

static const char* adapi_str = "adapter";


/**
 * Get origin.
 *
 */
ldns_rdf*
adapi_get_origin(zone_type* zone)
{
    if (!zone) {
        return NULL;
    }
    return zone->apex;
}


/**
 * Get ttl.
 *
 */
uint32_t
adapi_get_ttl(zone_type* zone)
{
    if (!zone) {
        return 0;
    }
    return zone->default_ttl;
}


/**
 * Process DNSKEY.
 *
 */
static void
adapi_process_dnskey(zone_type* zone, ldns_rr* rr)
{
    uint32_t tmp = 0;
    ods_log_assert(rr);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);
    tmp = (uint32_t) duration2time(zone->signconf->dnskey_ttl);
    ods_log_verbose("[%s] zone %s set dnskey ttl to %u",
        adapi_str, zone->name, tmp);
    ldns_rr_set_ttl(rr, tmp);
}


/**
 * Process RR.
 *
 */
static ods_status
adapi_process_rr(zone_type* zone, names_view_type view, ldns_rr* rr, int add, int backup)
{
    ods_status status = ODS_STATUS_OK;
    uint32_t tmp = 0;
    ods_log_assert(rr);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);
    /* We only support IN class */
    if (ldns_rr_get_class(rr) != LDNS_RR_CLASS_IN) {
        ods_log_warning("[%s] only class in is supported, changing class "
            "to in", adapi_str);
        ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    }
    /* RR processing */
    if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
        if (ldns_dname_compare(ldns_rr_owner(rr), zone->apex)) {
            ods_log_error("[%s] unable to %s rr to zone: soa record has "
                "invalid owner name", adapi_str, add?"add":"delete");
            return ODS_STATUS_ERR;
        }
    } else {
        if (ldns_dname_compare(ldns_rr_owner(rr), zone->apex) &&
            !ldns_dname_is_subdomain(ldns_rr_owner(rr), zone->apex)) {
            ods_log_warning("[%s] zone %s contains out-of-zone data, "
                "skipping", adapi_str, zone->name);
            return ODS_STATUS_UNCHANGED;
        } else if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_DNSKEY) {
            adapi_process_dnskey(zone, rr);
        } else if (util_is_dnssec_rr(rr) && !backup) {
            if (!zone->signconf->passthrough) {
                ods_log_warning("[%s] zone %s contains dnssec data (type=%u), skipping", adapi_str, zone->name, (unsigned) ldns_rr_get_type(rr));
                return ODS_STATUS_UNCHANGED;
            }
        } else if (zone->signconf->max_zone_ttl) {
            /* Convert MaxZoneTTL */
            tmp = (uint32_t) duration2time(zone->signconf->max_zone_ttl);
        }
    }
    /* //MaxZoneTTL. Only set for RRtype != SOA && RRtype != DNSKEY */
    if (tmp && tmp < ldns_rr_ttl(rr)) {
        /* capping ttl to MaxZoneTTL */
        ldns_rr_set_ttl(rr, tmp);
    }

    /* TODO: DNAME and CNAME checks */
    /* TODO: NS and DS checks */

    if (add) {
        return zone_add_rr(zone, view, rr);
    } else {
        return zone_del_rr(zone, view, rr);
    }
    /* not reached */
    return ODS_STATUS_ERR;
}


/**
 * Add RR.
 *
 */
ods_status
adapi_add_rr(zone_type* zone, names_view_type view, ldns_rr* rr, int backup)
{
    return adapi_process_rr(zone, view, rr, 1, backup);
}


/**
 * Delete RR.
 *
 */
ods_status
adapi_del_rr(zone_type* zone, names_view_type view, ldns_rr* rr, int backup)
{
    return adapi_process_rr(zone, view, rr, 0, backup);
}
