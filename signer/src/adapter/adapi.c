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
 * Get class.
 *
 */
ldns_rr_class
adapi_get_class(zone_type* zone)
{
    if (!zone) {
        ods_log_error("[%s] unable to get class: "
            "no zone", adapi_str);
        return LDNS_RR_CLASS_FIRST;
    }
    ods_log_assert(zone);
    return zone->klass;
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
    return zone_add_rr(zone, rr, 1);
}


/**
 * Delete RR.
 *
 */
ods_status
adapi_del_rr(zone_type* zone, ldns_rr* rr)
{
    return zone_del_rr(zone, rr, 1);
}
