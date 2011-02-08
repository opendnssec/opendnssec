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
#include "daemon/engine.h"
#include "shared/file.h"
#include "shared/locks.h"
#include "shared/log.h"
#include "signer/tools.h"
#include "signer/zone.h"

#include <unistd.h>

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
    char* axfrname = NULL;
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
    ods_log_assert(zone->adinbound->data);
    ods_log_assert(zone->signconf);
    ods_log_assert(zone->stats);

    zone->stats->sort_done = 0;
    zone->stats->sort_count = 0;
    zone->stats->sort_time = 0;

    if (zone->adinbound->type == ADAPTER_FILE) {
        ods_log_assert(zone->adinbound->data->file);
        ods_log_assert(zone->adinbound->data->file->filename);

        if (zone->fetch) {
            ods_log_verbose("fetch zone %s",
                zone->name?zone->name:"(null)");
            axfrname = ods_build_path(
                zone->adinbound->data->file->filename, ".axfr", 0);
            error = ods_file_copy(axfrname,
                zone->adinbound->data->file->filename);
            if (error) {
                ods_log_error("[%s] unable to copy axfr file %s to %s",
                    tools_str, axfrname,
                    zone->adinbound->data->file->filename);
                free((void*)axfrname);
                return ODS_STATUS_ERR;
            }
            free((void*)axfrname);
        }
    }

    ods_log_verbose("[%s] read zone %s", tools_str,
        zone->name?zone->name:"(null)");

    start = time(NULL);
    status = adapter_read(zone);
    end = time(NULL);
    if (status != ODS_STATUS_OK) {
        zonedata_rollback(zone->zonedata);
    }
    else {
        zone_backup_state(zone);
        zone->stats->start_time = start;
        zone->stats->sort_time = (end-start);
    }
    return status;
}


/**
 * Examine and commit updates.
 *
 */
ods_status
tools_commit(zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    char* inbound = NULL;
    char* unsorted = NULL;

    if (!zone) {
        ods_log_error("[%s] unable to commit updates to zone: no zone",
            tools_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);

    if (!zone->zonedata) {
        ods_log_error("[%s] unable to commit updates to zone %s: no zonedata",
            tools_str, zone->name?zone->name:"(null)");
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->zonedata);

    /* examine */
    ods_log_verbose("[%s] examine updates to zone %s", tools_str,
        zone->name?zone->name:"(null)");
    status = zonedata_examine(zone->zonedata, zone->dname,
        zone->adinbound->type==ADAPTER_FILE);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] commit updates zone %s failed: zone data "
            "contains errors", tools_str, zone->name);
        zonedata_rollback(zone->zonedata);
        return status;
    }

    /* commit */
    ods_log_verbose("[%s] commit updates to zone %s", tools_str,
        zone->name?zone->name:"(null)");
    status = zonedata_commit(zone->zonedata);
    if (status != ODS_STATUS_OK) {
        inbound = ods_build_path(zone->name, ".inbound", 0);
        unsorted = ods_build_path(zone->name, ".unsorted", 0);
        status = ods_file_copy(inbound, unsorted);
        if (status != ODS_STATUS_OK) {
            zone->stats->sort_done = 1;
            unlink(inbound);
        }
        free((void*)inbound);
        free((void*)unsorted);
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

    ods_log_assert(zone->stats);

    ods_log_verbose("[%s] nsecify zone %s", tools_str,
        zone->name?zone->name:"(null)");
    start = time(NULL);

    /* add missing empty non-terminals */
    status = zonedata_entize(zone->zonedata, zone->dname);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to nsecify zone %s: failed to add empty ",
            "non-terminals", tools_str, zone->name);
        return status;
    }

    /* NSEC or NSEC3? */
    if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC) {
        status = zonedata_nsecify(zone->zonedata, zone->klass);
    } else if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
        if (zone->signconf->nsec3_optout) {
            ods_log_debug("[%s] OptOut is being used for zone %s",
                tools_str, zone->name);
        }
        ods_log_assert(zone->nsec3params);
        status = zonedata_nsecify3(zone->zonedata, zone->klass,
            zone->nsec3params);
    } else {
        ods_log_error("[%s] unable to nsecify zone %s: unknown RRtype %u for ",
            "denial of existence", tools_str, zone->name,
            (unsigned) zone->signconf->nsec_type);
        return ODS_STATUS_ERR;
    }
    end = time(NULL);
    if (status == ODS_STATUS_OK) {
        if (!zone->stats->start_time) {
            zone->stats->start_time = start;
        }
        zone->stats->nsec_time = (end-start);
    }
    return status;
}


/**
 * Add RRSIG records to zone.
 *
 */
int
tools_sign(zone_type* zone)
{
    int error = 0;
    time_t start = 0;
    time_t end = 0;
    ods_log_assert(zone);
    ods_log_assert(zone->signconf);
    ods_log_assert(zone->stats);
    ods_log_verbose("[%s] sign zone %s", tools_str,
        zone->name?zone->name:"(null)");
    start = time(NULL);
    error = zone_sign(zone);
    end = time(NULL);
    if (!error) {
        ods_log_verbose("[%s] zone %s signed, new serial %u", tools_str,
            zone->name?zone->name:"(null)", zone->zonedata->internal_serial);
        if (!zone->stats->start_time) {
            zone->stats->start_time = start;
        }
        zone->stats->sig_time = (end-start);
        zone_backup_state(zone);
    }
    return error;
}


/**
 * Audit zone.
 *
 */
ods_status
tools_audit(zone_type* zone, char* working_dir, char* cfg_filename)
{
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

    if (zone->stats->sort_done == 0 &&
        (zone->stats->sig_count <= zone->stats->sig_soa_count)) {
        return ODS_STATUS_OK;
    }
    if (zone->signconf->audit) {
        ods_log_verbose("[%s] audit zone %s", tools_str,
            zone->name?zone->name:"(null)");
        finalized = ods_build_path(zone->name, ".finalized", 0);
        status = adfile_write(zone, finalized);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] audit zone %s failed: unable to write zone",
                tools_str, zone->name?zone->name:"(null)");
            free((void*)finalized);
            return status;
        }

        snprintf(str, SYSTEM_MAXLEN, "%s -c %s -s %s/%s -z %s > /dev/null",
            ODS_SE_AUDITOR,
            cfg_filename?cfg_filename:ODS_SE_CFGFILE,
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
        if (error) {
            status = ODS_STATUS_ERR;
        }
        end = time(NULL);
        zone->stats->audit_time = (end-start);
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
    ods_log_assert(zone->adinbound->data);

    ods_log_assert(zone->stats);

    if (zone->stats->sort_done == 0 &&
        (zone->stats->sig_count <= zone->stats->sig_soa_count)) {
        ods_log_verbose("skip write zone %s serial %u (zone not changed)",
            zone->name?zone->name:"(null)", zone->zonedata->internal_serial);
        stats_clear(zone->stats);
        return 0;
    }

    zone->zonedata->outbound_serial = zone->zonedata->internal_serial;
    ods_log_verbose("[%s] write zone %s serial %u", tools_str,
        zone->name?zone->name:"(null)", zone->zonedata->outbound_serial);

    status = adapter_write(zone);
    if (status != ODS_STATUS_OK) {
        return status;
    }

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
    zone->stats->end_time = time(NULL);
    ods_log_debug("[%s] log stats for zone %s", tools_str,
        zone->name?zone->name:"(null)");
    stats_log(zone->stats, zone->name, zone->signconf->nsec_type);
    stats_clear(zone->stats);

    return status;
}
