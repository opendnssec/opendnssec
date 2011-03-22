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
 * Zone signing tools.
 *
 */

#include "config.h"
#include "adapter/adapter.h"
#include "shared/file.h"
#include "shared/log.h"
#include "signer/tools.h"
#include "signer/zone.h"

static const char* tools_str = "tools";


/**
 * Read zone from input adapter.
 *
 */
ods_status
tools_input(zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    int error = 0;
    char* tmpname = NULL;
    time_t start = 0;
    time_t end = 0;

    if (!zone) {
        ods_log_error("[%s] unable to read zone: no zone", tools_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);

    if (!zone->zonedata) {
        ods_log_error("[%s] unable to read zone: no zone data", tools_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->zonedata);

    ods_log_assert(zone->adinbound);
    ods_log_assert(zone->signconf);

    if (zone->stats) {
        lock_basic_lock(&zone->stats->stats_lock);
        zone->stats->sort_done = 0;
        zone->stats->sort_count = 0;
        zone->stats->sort_time = 0;
        lock_basic_unlock(&zone->stats->stats_lock);
    }

    if (zone->adinbound->type == ADAPTER_FILE) {
        if (zone->fetch) {
            ods_log_verbose("fetch zone %s",
                zone->name?zone->name:"(null)");
            tmpname = ods_build_path(
                zone->adinbound->configstr, ".axfr", 0);
            error = ods_file_copy(tmpname, zone->adinbound->configstr);
            if (error) {
                ods_log_error("[%s] unable to copy axfr file %s to %s",
                    tools_str, tmpname, zone->adinbound->configstr);
                free((void*)tmpname);
                return ODS_STATUS_ERR;
            }
            free((void*)tmpname);
        }
    }

    start = time(NULL);
    status = adapter_read(zone);
    if (status == ODS_STATUS_OK) {
        tmpname = ods_build_path(zone->name, ".inbound", 0);
        status = ods_file_copy(zone->adinbound->configstr, tmpname);
        free((void*)tmpname);
        tmpname = NULL;
    }

    if (status == ODS_STATUS_OK) {
        ods_log_verbose("[%s] commit updates for zone %s", tools_str,
                zone->name?zone->name:"(null)");
        status = zonedata_commit(zone->zonedata);
    } else {
        ods_log_warning("[%s] rollback updates for zone %s", tools_str,
                zone->name?zone->name:"(null)");
        zonedata_rollback(zone->zonedata);
    }
    end = time(NULL);

    if (status == ODS_STATUS_OK && zone->stats) {
        lock_basic_lock(&zone->stats->stats_lock);
        zone->stats->start_time = start;
        zone->stats->sort_time = (end-start);
        zone->stats->sort_done = 1;
        lock_basic_unlock(&zone->stats->stats_lock);
    }
    return status;
}


/**
 * Nsecify zone.
 *
 */
ods_status
tools_nsecify(zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    time_t start = 0;
    time_t end = 0;
    uint32_t ttl = 0;
    uint32_t num_added = 0;

    if (!zone) {
        ods_log_error("[%s] unable to nsecify zone: no zone", tools_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);

    if (!zone->zonedata) {
        ods_log_error("[%s] unable to nsecify zone %s: no zonedata",
            tools_str, zone->name);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->zonedata);

    if (!zone->signconf) {
        ods_log_error("[%s] unable to nsecify zone %s: no signconf",
            tools_str, zone->name);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf);

    if (zone->stats) {
        lock_basic_lock(&zone->stats->stats_lock);
        zone->stats->nsec_time = 0;
        zone->stats->nsec_count = 0;
        lock_basic_unlock(&zone->stats->stats_lock);
    }

    start = time(NULL);
    /* determine NSEC(3) ttl */
    ttl = zone->zonedata->default_ttl;
    if (zone->signconf->soa_min) {
        ttl = (uint32_t) duration2time(zone->signconf->soa_min);
    }
    /* add missing empty non-terminals */
    status = zonedata_entize(zone->zonedata, zone->dname);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to nsecify zone %s: failed to add empty ",
            "non-terminals", tools_str, zone->name);
        return status;
    }

    /* NSEC or NSEC3? */
    if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC) {
        status = zonedata_nsecify(zone->zonedata, zone->klass, ttl,
            &num_added);
    } else if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
        if (zone->signconf->nsec3_optout) {
            ods_log_debug("[%s] OptOut is being used for zone %s",
                tools_str, zone->name);
        }
        ods_log_assert(zone->nsec3params);
        status = zonedata_nsecify3(zone->zonedata, zone->klass, ttl,
            zone->nsec3params, &num_added);
    } else {
        ods_log_error("[%s] unable to nsecify zone %s: unknown RRtype %u for ",
            "denial of existence", tools_str, zone->name,
            (unsigned) zone->signconf->nsec_type);
        return ODS_STATUS_ERR;
    }
    end = time(NULL);
    if (status == ODS_STATUS_OK && zone->stats) {
        lock_basic_lock(&zone->stats->stats_lock);
        if (!zone->stats->start_time) {
            zone->stats->start_time = start;
        }
        zone->stats->nsec_time = (end-start);
        zone->stats->nsec_count = num_added;
        lock_basic_unlock(&zone->stats->stats_lock);
    }
    return status;
}


/**
 * Audit zone.
 *
 */
ods_status
tools_audit(zone_type* zone, char* working_dir, char* cfg_filename)
{
    char* inbound = NULL;
    char* finalized = NULL;
    char str[SYSTEM_MAXLEN];
    ods_status status = ODS_STATUS_OK;
    int error = 0;
    time_t start = 0;
    time_t end = 0;

    if (!zone) {
        ods_log_error("[%s] unable to audit zone: no zone", tools_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);

    if (!zone->signconf) {
        ods_log_error("[%s] unable to audit zone %s: no signconf",
            tools_str, zone->name?zone->name:"(null)");
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf);

    if (zone->stats) {
        lock_basic_lock(&zone->stats->stats_lock);
        if (zone->stats->sort_done == 0 &&
            (zone->stats->sig_count <= zone->stats->sig_soa_count)) {
            lock_basic_unlock(&zone->stats->stats_lock);
            return ODS_STATUS_OK;
        }
        lock_basic_unlock(&zone->stats->stats_lock);
    }

    if (zone->signconf->audit) {
        inbound = ods_build_path(zone->name, ".inbound", 0);
        finalized = ods_build_path(zone->name, ".finalized", 0);
        status = adfile_write(zone, finalized);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] audit zone %s failed: unable to write zone",
                tools_str, zone->name?zone->name:"(null)");
            free((void*)finalized);
            return status;
        }

        snprintf(str, SYSTEM_MAXLEN, "%s -c %s -u %s/%s -s %s/%s -z %s > /dev/null",
            ODS_SE_AUDITOR,
            cfg_filename?cfg_filename:ODS_SE_CFGFILE,
            working_dir?working_dir:"",
            inbound?inbound:"(null)",
            working_dir?working_dir:"",
            finalized?finalized:"(null)",
            zone->name?zone->name:"(null)");

        start = time(NULL);
        ods_log_debug("system call: %s", str);
        error = system(str);
        if (finalized) {
            if (!error) {
                unlink(finalized);
            }
            free((void*)finalized);
        }
        free((void*)inbound);

        if (error) {
            status = ODS_STATUS_ERR;
        }
        end = time(NULL);
        if (status == ODS_STATUS_OK && zone->stats) {
            lock_basic_lock(&zone->stats->stats_lock);
            zone->stats->audit_time = (end-start);
            lock_basic_unlock(&zone->stats->stats_lock);
        }
    }
    return status;
}


/**
 * Write zone to output adapter.
 *
 */
ods_status
tools_output(zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    char str[SYSTEM_MAXLEN];
    int error = 0;
    uint32_t outbound_serial = 0;

    if (!zone) {
        ods_log_error("[%s] unable to write zone: no zone", tools_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);

    if (!zone->adoutbound) {
        ods_log_error("[%s] unable to write zone %s: no outbound adapter",
            tools_str, zone->name?zone->name:"(null)");
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->adoutbound);

    if (zone->stats) {
        lock_basic_lock(&zone->stats->stats_lock);
        if (zone->stats->sort_done == 0 &&
            (zone->stats->sig_count <= zone->stats->sig_soa_count)) {
            ods_log_verbose("[%s] skip write zone %s serial %u (zone not "
                "changed)", tools_str, zone->name?zone->name:"(null)",
                zone->zonedata->internal_serial);
            stats_clear(zone->stats);
            lock_basic_unlock(&zone->stats->stats_lock);
            zone->zonedata->internal_serial =
                zone->zonedata->outbound_serial;
            return ODS_STATUS_OK;
        }
        lock_basic_unlock(&zone->stats->stats_lock);
    }

    outbound_serial = zone->zonedata->outbound_serial;
    zone->zonedata->outbound_serial = zone->zonedata->internal_serial;
    status = adapter_write(zone);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to write zone %s: adapter failed",
            tools_str, zone->name);
        zone->zonedata->outbound_serial = outbound_serial;
        return status;
    }

    /* initialize zonedata */
    zone->zonedata->initialized = 1;

    /* kick the nameserver */
    if (zone->notify_ns) {
        ods_log_verbose("[%s] notify nameserver: %s", tools_str,
            zone->notify_ns);
        snprintf(str, SYSTEM_MAXLEN, "%s > /dev/null",
            zone->notify_ns);
        error = system(str);
        if (error) {
           ods_log_error("[%s] failed to notify nameserver", tools_str);
           status = ODS_STATUS_ERR;
        }
    }
    /* log stats */
    if (zone->stats) {
        lock_basic_lock(&zone->stats->stats_lock);
        zone->stats->end_time = time(NULL);
        ods_log_debug("[%s] log stats for zone %s", tools_str,
            zone->name?zone->name:"(null)");
        stats_log(zone->stats, zone->name, zone->signconf->nsec_type);
        stats_clear(zone->stats);
        lock_basic_unlock(&zone->stats->stats_lock);
    }
    return status;
}
