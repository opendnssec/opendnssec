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
#include "scheduler/locks.h"
#include "signer/tools.h"
#include "signer/zone.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <unistd.h> /* unlink() */


/**
 * Read zone's input adapter.
 *
 */
int
tools_read_input(zone_type* zone)
{
    char* tmpname = NULL;
    int error = 0;
    time_t start = 0;
    time_t end = 0;

    se_log_assert(zone);
    se_log_assert(zone->inbound_adapter);
    se_log_assert(zone->signconf);
    se_log_assert(zone->stats);

    zone->stats->sort_count = 0;
    zone->stats->sort_time = 0;
    start = time(NULL);
    zone->stats->start_time = start;

    switch (zone->inbound_adapter->type) {
        case ADAPTER_FILE:
            se_log_verbose("read zone %s from input file adapter %s",
                zone->name?zone->name:"(null)",
                zone->inbound_adapter->filename?zone->inbound_adapter->filename:"(null)");

            tmpname = se_build_path(zone->name, ".unsorted", 0);
            error = se_file_copy(zone->inbound_adapter->filename, tmpname);
            if (!error) {
                error = adfile_read(zone, tmpname, 0);
            }
            se_free((void*)tmpname);
            break;
        case ADAPTER_UNKNOWN:
        default:
            se_log_error("read zone %s failed: unknown inbound adapter type %i",
                zone->name?zone->name:"(null)",
                (int) zone->inbound_adapter->type);
            error = 1;
            break;
    }
    end = time(NULL);
    zone->stats->sort_time = (end-start);

    if (!error) {
        zone_backup_state(zone);
    }
    return error;
}


/**
 * Add DNSKEY (and NSEC3PARAM) records to zone.
 *
 */
int
tools_add_dnskeys(zone_type* zone)
{
    se_log_assert(zone);
    se_log_assert(zone->signconf);
    se_log_verbose("publish dnskeys to zone %s",
        zone->name?zone->name:"(null)");
    return zone_add_dnskeys(zone);
}

/**
 * Update zone with pending changes.
 *
 */
int
tools_update(zone_type* zone)
{
    int error = 0;

    se_log_assert(zone);
    se_log_assert(zone->signconf);
    se_log_verbose("update zone %s", zone->name?zone->name:"(null)");
    error = zone_update_zonedata(zone);
    if (!error) {
        zone_backup_state(zone);
    }
    return error;
}


/**
 * Add NSEC(3) records to zone.
 *
 */
int
tools_nsecify(zone_type* zone)
{
    int error = 0;
    time_t start = 0;
    time_t end = 0;

    se_log_assert(zone);
    se_log_assert(zone->signconf);
    se_log_assert(zone->stats);
    se_log_verbose("nsecify zone %s", zone->name?zone->name:"(null)");
    start = time(NULL);
    if (!zone->stats->start_time) {
        zone->stats->start_time = start;
    }

    error = zone_nsecify(zone);
    end = time(NULL);
    zone->stats->nsec_time = (end-start);
    return error;
}


/**
 * Add NSEC(3) records to zone.
 *
 */
int
tools_sign(zone_type* zone)
{
    int error = 0;
    time_t start = 0;
    time_t end = 0;

    se_log_assert(zone);
    se_log_assert(zone->signconf);
    se_log_assert(zone->stats);
    se_log_verbose("sign zone %s", zone->name?zone->name:"(null)");
    start = time(NULL);
    if (!zone->stats->start_time) {
        zone->stats->start_time = start;
    }
    error = zone_sign(zone);
    end = time(NULL);
    zone->stats->sig_time = (end-start);
    if (!error) {
        zone_backup_state(zone);
    }
    return error;
}


/**
 * Audit zone.
 *
 */
int
tools_audit(zone_type* zone, char* working_dir, char* cfg_filename)
{
    char* finalized = NULL;
    char str[SYSTEM_MAXLEN];
    int error = 0;
    time_t start = 0;
    time_t end = 0;

    se_log_assert(zone);
    se_log_assert(zone->signconf);

    if (zone->stats->sig_count <= 0) {
        se_log_verbose("skip audit zone %s, zone not changed",
            zone->name?zone->name:"(null)");
        return 0;
    }

    if (zone->signconf->audit) {
        se_log_verbose("audit zone %s", zone->name?zone->name:"(null)");
        finalized = se_build_path(zone->name, ".finalized", 0);
        error = adfile_write(zone, finalized);
        if (error != 0) {
            se_log_error("audit zone %s failed: unable to write zone",
                zone->name?zone->name:"(null)");
            se_free((void*)finalized);
            return 1;
        }

        snprintf(str, SYSTEM_MAXLEN, "%s -c %s -s %s/%s -z %s > /dev/null",
            ODS_SE_AUDITOR,
            cfg_filename?cfg_filename:ODS_SE_CFGFILE,
            working_dir?working_dir:"",
            finalized?finalized:"(null)",
            zone->name?zone->name:"(null)");

        start = time(NULL);
        se_log_debug("system call: %s", str);
        error = system(str);
        if (finalized) {
            if (!error) {
                unlink(finalized);
            }
            se_free((void*)finalized);
        }
        end = time(NULL);
        zone->stats->audit_time = (end-start);
    }
    return error;
}


/**
 * Write zone to output adapter.
 * \param[in] zone zone
 * \return int 0 on success, 1 on fail
 *
 */
int tools_write_output(zone_type* zone)
{
    int error = 0;

    se_log_assert(zone);
    se_log_assert(zone->signconf);
    se_log_assert(zone->outbound_adapter);
    se_log_assert(zone->stats);;

    if (zone->stats->sig_count <= 0) {
        se_log_verbose("skip write zone %s, zone not changed",
            zone->name?zone->name:"(null)");
        stats_clear(zone->stats);
        return 0;
    }

    se_log_verbose("write zone %s", zone->name?zone->name:"(null)");

    switch (zone->outbound_adapter->type) {
        case ADAPTER_FILE:
            error = adfile_write(zone, NULL);
            break;
        case ADAPTER_UNKNOWN:
        default:
            se_log_error("write zone %s failed: unknown outbound adapter "
                "type %i", zone->name?zone->name:"(null)",
                (int) zone->inbound_adapter->type);
            error = 1;
            break;
    }

    /* kick the nameserver */
    if (zone->notify_ns) {
        se_log_verbose("notify nameserver: %s", zone->notify_ns);
        error = system(zone->notify_ns);
        if (error) {
           se_log_error("failed to notify nameserver");
        }
    }

    /* log stats */
    zone->stats->end_time = time(NULL);
    se_log_debug("log stats for zone %s", zone->name?zone->name:"(null)");
    stats_log(zone->stats, zone->name, zone->signconf->nsec_type);
    stats_clear(zone->stats);

    return error;
}
