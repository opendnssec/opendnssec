/*
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
#include "duration.h"
#include "log.h"
#include "status.h"
#include "util.h"
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
    if (!zone || !zone->db) {
        return 0;
    }
    return zone->db->inbserial;
}


/**
 * Set the inbound serial.
 *
 */
void
adapi_set_serial(zone_type* zone, uint32_t serial)
{
    if (!zone || !zone->db) {
        return;
    }
    zone->db->inbserial = serial;
}


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


/*
 * Do full zone transaction.
 *
 */
void
adapi_trans_full(zone_type* zone, unsigned more_coming)
{
    time_t start = 0;
    time_t end = 0;
    uint32_t num_added = 0;
    if (!zone || !zone->db) {
        return;
    }
    namedb_diff(zone, zone->db, 0, more_coming);

    if (zone->stats) {
        pthread_mutex_lock(&zone->stats->stats_lock);
        zone->stats->nsec_time = 0;
        zone->stats->nsec_count = 0;
        pthread_mutex_unlock(&zone->stats->stats_lock);
    }
    start = time(NULL);
    /* nsecify(3) */
    namedb_nsecify(zone, zone->db, &num_added);
    end = time(NULL);
    if (zone->stats) {
        pthread_mutex_lock(&zone->stats->stats_lock);
        if (!zone->stats->start_time) {
            zone->stats->start_time = start;
        }
        zone->stats->nsec_time = (end-start);
        zone->stats->nsec_count = num_added;
        pthread_mutex_unlock(&zone->stats->stats_lock);
    }
}


/*
 * Do incremental zone transaction.
 *
 */
void
adapi_trans_diff(zone_type* zone, unsigned more_coming)
{
    time_t start = 0;
    time_t end = 0;
    uint32_t num_added = 0;
    if (!zone || !zone->db) {
        return;
    }
    namedb_diff(zone, zone->db, 1, more_coming);

   if (zone->stats) {
        pthread_mutex_lock(&zone->stats->stats_lock);
        zone->stats->nsec_time = 0;
        zone->stats->nsec_count = 0;
        pthread_mutex_unlock(&zone->stats->stats_lock);
    }
    start = time(NULL);
    /* nsecify(3) */
    namedb_nsecify(zone, zone->db, &num_added);
    end = time(NULL);
    if (zone->stats) {
        pthread_mutex_lock(&zone->stats->stats_lock);
        if (!zone->stats->start_time) {
            zone->stats->start_time = start;
        }
        zone->stats->nsec_time = (end-start);
        zone->stats->nsec_count = num_added;
        pthread_mutex_unlock(&zone->stats->stats_lock);
    }
}


/**
 * Process SOA.
 *
 */
static ods_status
adapi_process_soa(zone_type* zone, ldns_rr* rr, int add, int backup)
{
    uint32_t tmp = 0;
    ldns_rdf* soa_rdata = NULL;
    ods_status status = ODS_STATUS_OK;

    ods_log_assert(rr);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);

    if (backup) {
        /* no need to do processing */
        return ODS_STATUS_OK;
    }
    if (zone->signconf->soa_ttl) {
        tmp = (uint32_t) duration2time(zone->signconf->soa_ttl);
        ods_log_verbose("[%s] zone %s set soa ttl to %u",
            adapi_str, zone->name, tmp);
        ldns_rr_set_ttl(rr, tmp);
    }
    if (zone->signconf->soa_min) {
        tmp = (uint32_t) duration2time(zone->signconf->soa_min);
        ods_log_verbose("[%s] zone %s set soa minimum to %u",
            adapi_str, zone->name, tmp);
        soa_rdata = ldns_rr_set_rdf(rr,
            ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, tmp),
            SE_SOA_RDATA_MINIMUM);
        if (soa_rdata) {
            ldns_rdf_deep_free(soa_rdata);
            soa_rdata = NULL;
        } else {
            ods_log_error("[%s] unable to %s soa to zone %s: failed to replace "
                "soa minimum rdata", adapi_str, add?"add":"delete",
                zone->name);
            return ODS_STATUS_ASSERT_ERR;
        }
    }
    if (!add) {
        /* we are done */
        return ODS_STATUS_OK;
    }
    tmp = ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
    status = namedb_update_serial(zone->db, zone->name,
        zone->signconf->soa_serial, tmp);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to add soa to zone %s: failed to replace "
            "soa serial rdata (%s)", adapi_str, zone->name,
            ods_status2str(status));
        if (status == ODS_STATUS_CONFLICT_ERR) {
            ods_log_error("[%s] If this is the result of a key rollover, "
                "please increment the serial in the unsigned zone %s",
                adapi_str, zone->name);
        }
        return status;
    }
    ods_log_verbose("[%s] zone %s set soa serial to %u", adapi_str,
        zone->name, zone->db->intserial);
    soa_rdata = ldns_rr_set_rdf(rr, ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32,
        zone->db->intserial), SE_SOA_RDATA_SERIAL);
    if (soa_rdata) {
        ldns_rdf_deep_free(soa_rdata);
        soa_rdata = NULL;
    } else {
        ods_log_error("[%s] unable to add soa to zone %s: failed to replace "
            "soa serial rdata", adapi_str, zone->name);
        return ODS_STATUS_ERR;
    }
    zone->db->serial_updated = 1;
    return ODS_STATUS_OK;
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
adapi_process_rr(zone_type* zone, ldns_rr* rr, int add, int backup)
{
    ods_status status = ODS_STATUS_OK;
    uint32_t tmp = 0;
    ods_log_assert(rr);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->db);
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
        status = adapi_process_soa(zone, rr, add, backup);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to %s rr: failed to process soa "
                "record", adapi_str, add?"add":"delete");
            return status;
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
            ods_log_warning("[%s] zone %s contains dnssec data (type=%u), "
                "skipping", adapi_str, zone->name,
                (unsigned) ldns_rr_get_type(rr));
            return ODS_STATUS_UNCHANGED;
        } else if (zone->signconf->max_zone_ttl) {
            /* Convert MaxZoneTTL */
            tmp = (uint32_t) duration2time(zone->signconf->max_zone_ttl);
        }
    }
    /* //MaxZoneTTL. Only set for RRtype != SOA && RRtype != DNSKEY */
    if (tmp && tmp < ldns_rr_ttl(rr)) {
        char* str = ldns_rdf2str(ldns_rr_owner(rr));
        if (str) {
            size_t i = 0;
            str[(strlen(str))-1] = '\0';
            /* replace tabs with white space */
            for (i=0; i < strlen(str); i++) {
                if (str[i] == '\t') {
                    str[i] = ' ';
                }
            }
            ods_log_debug("[%s] capping ttl %u to MaxZoneTTL %u for rrset "
                "<%s,%s>", adapi_str, ldns_rr_ttl(rr), tmp, str,
                rrset_type2str(ldns_rr_get_type(rr)));
        }
        ldns_rr_set_ttl(rr, tmp);
    }

    /* TODO: DNAME and CNAME checks */
    /* TODO: NS and DS checks */

    if (add) {
        return zone_add_rr(zone, rr, 1);
    } else {
        return zone_del_rr(zone, rr, 1);
    }
    /* not reached */
    return ODS_STATUS_ERR;
}


/**
 * Add RR.
 *
 */
ods_status
adapi_add_rr(zone_type* zone, ldns_rr* rr, int backup)
{
    return adapi_process_rr(zone, rr, 1, backup);
}


/**
 * Delete RR.
 *
 */
ods_status
adapi_del_rr(zone_type* zone, ldns_rr* rr, int backup)
{
    return adapi_process_rr(zone, rr, 0, backup);
}


/**
 * Print zone.
 *
 */
ods_status
adapi_printzone(FILE* fd, zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    if (!fd || !zone || !zone->db) {
        ods_log_error("[%s] unable to print zone: file descriptor, zone or "
            "name database missing", adapi_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    namedb_export(fd, zone->db, &status);
    return status;
}


/**
 * Print axfr.
 *
 */
ods_status
adapi_printaxfr(FILE* fd, zone_type* zone)
{
    rrset_type* rrset = NULL;
    ods_status status = ODS_STATUS_OK;
    if (!fd || !zone || !zone->db) {
        ods_log_error("[%s] unable to print axfr: file descriptor, zone or "
            "name database missing", adapi_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    namedb_export(fd, zone->db, &status);
    if (status == ODS_STATUS_OK) {
        rrset = zone_lookup_rrset(zone, zone->apex, LDNS_RR_TYPE_SOA);
        ods_log_assert(rrset);
        rrset_print(fd, rrset, 1, &status);
    }
    return status;
}


/**
 * Print ixfr.
 *
 */
ods_status
adapi_printixfr(FILE* fd, zone_type* zone)
{
    rrset_type* rrset = NULL;
    ods_status status = ODS_STATUS_OK;
    if (!fd || !zone || !zone->db || !zone->ixfr) {
        ods_log_error("[%s] unable to print ixfr: file descriptor, zone or "
            "name database missing", adapi_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    if (!zone->db->is_initialized) {
        /* no ixfr yet */
        return ODS_STATUS_OK;
    }
    rrset = zone_lookup_rrset(zone, zone->apex, LDNS_RR_TYPE_SOA);
    ods_log_assert(rrset);
    rrset_print(fd, rrset, 1, &status);
    if (status != ODS_STATUS_OK) {
        return status;
    }
    pthread_mutex_lock(&zone->ixfr->ixfr_lock);
    if (ixfr_print(fd, zone->ixfr)) {
        zone->adoutbound->error = 1;
    }
    pthread_mutex_unlock(&zone->ixfr->ixfr_lock);
    rrset_print(fd, rrset, 1, &status);
    return status;
}
