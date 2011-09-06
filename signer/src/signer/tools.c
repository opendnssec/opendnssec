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
 * Load zone signconf.
 *
 */
ods_status
tools_signconf(zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    signconf_type* new_signconf = NULL;
    task_id denial_what = TASK_NONE;

    ods_log_assert(zone);
    ods_log_assert(zone->name);
    status = zone_load_signconf(zone, &new_signconf);
    if (status == ODS_STATUS_OK) {
        ods_log_assert(new_signconf);
        /* Denial of Existence Rollover? */
        denial_what = signconf_compare_denial(zone->signconf, new_signconf);
        if (denial_what == TASK_NSECIFY) {
            /* or NSEC -> NSEC3, or NSEC3 -> NSEC, or NSEC3PARAM changed */
            namedb_wipe_denial(zone->db);
            namedb_cleanup_denials(zone->db);
            namedb_init_denials(zone->db);
        }
        /* all ok, switch signer configuration */
        signconf_cleanup(zone->signconf);
        ods_log_debug("[%s] zone %s switch to new signconf", tools_str,
            zone->name);
        zone->signconf = new_signconf;
        signconf_log(zone->signconf, zone->name);
        zone->default_ttl = (uint32_t) duration2time(zone->signconf->soa_min);
    } else {
        ods_log_error("[%s] unable to load signconf for zone %s: %s",
            tools_str, zone->name, ods_status2str(status));
    }
    return status;
}


/**
 * Read zone from input adapter.
 *
 */
ods_status
tools_input(zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    char* tmpname = NULL;
    char* lockname = NULL;
    time_t start = 0;
    time_t end = 0;
    FILE* fd = NULL;

    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->adinbound);
    ods_log_assert(zone->signconf);
    /* Key Rollover? */
    status = zone_publish_dnskeys(zone);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read zone %s: failed to "
            "publish dnskeys (%s)", tools_str, zone->name,
            ods_status2str(status));
        zone_rollback_dnskeys(zone);
        zone_rollback_nsec3param(zone);
        namedb_rollback(zone->db);
        return status;
    }
    /* Denial of Existence Rollover? */
    status = zone_publish_nsec3param(zone);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read zone %s: failed to "
            "publish nsec3param (%s)", tools_str, zone->name,
            ods_status2str(status));
        zone_rollback_dnskeys(zone);
        zone_rollback_nsec3param(zone);
        namedb_rollback(zone->db);
        return status;
    }

    if (zone->stats) {
        lock_basic_lock(&zone->stats->stats_lock);
        zone->stats->sort_done = 0;
        zone->stats->sort_count = 0;
        zone->stats->sort_time = 0;
        lock_basic_unlock(&zone->stats->stats_lock);
    }
    if (zone->adinbound->type == ADAPTER_FILE) {
        if (zone->fetch) {
            ods_log_verbose("[%s] fetch zone %s", tools_str,
                zone->name?zone->name:"(null)");
            tmpname = ods_build_path(
                zone->adinbound->configstr, ".axfr", 0);
            lockname = ods_build_path(
                zone->adinbound->configstr, ".lock", 0);

lock_fetch:
            if (access(lockname, F_OK) == 0) {
                ods_log_deeebug("[%s] axfr file %s is locked, "
                    "waiting...", tools_str, tmpname);
                sleep(1);
                goto lock_fetch;
            } else {
                fd = fopen(lockname, "w");
                if (!fd) {
                    ods_log_error("[%s] cannot lock AXFR file %s",
                        tools_str, lockname);
                    free((void*)tmpname);
                    free((void*)lockname);
                    return ODS_STATUS_ERR;
                }
            }
            ods_log_assert(fd); /* locked */

            status = ods_file_copy(tmpname, zone->adinbound->configstr);

            fclose(fd);
            (void) unlink(lockname); /* unlocked */

            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to copy axfr file %s to %s: %s",
                    tools_str, tmpname, zone->adinbound->configstr,
                    ods_status2str(status));
                free((void*)tmpname);
                free((void*)lockname);
                return status;
            }
            free((void*)tmpname);
            free((void*)lockname);
        }
    }
    /* Input Adapter */
    start = time(NULL);
    status = adapter_read((void*)zone);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read zone %s: adapter failed (%s)",
            tools_str, zone->name, ods_status2str(status));
        zone_rollback_dnskeys(zone);
        zone_rollback_nsec3param(zone);
        namedb_rollback(zone->db);
    } else {
        tmpname = ods_build_path(zone->name, ".inbound", 0);
        status = ods_file_copy(zone->adinbound->configstr, tmpname);
        free((void*)tmpname);
        tmpname = NULL;
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to copy zone input file %s: %s",
                tools_str, zone->name?zone->name:"(null)",
                ods_status2str(status));
        }
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
 * Audit zone.
 *
 */
static ods_status
tools_audit(zone_type* zone, const char* working_dir, const char* cfg_filename)
{
    char* inbound = NULL;
    char* finalized = NULL;
    char str[SYSTEM_MAXLEN];
    ods_status status = ODS_STATUS_OK;
    int error = 0;
    time_t start = 0;
    time_t end = 0;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);
    ods_log_assert(working_dir);
    ods_log_assert(cfg_filename);
    if (zone->stats) {
        lock_basic_lock(&zone->stats->stats_lock);
        if (zone->stats->sort_done == 0 &&
            (zone->stats->sig_count <= zone->stats->sig_soa_count)) {
            lock_basic_unlock(&zone->stats->stats_lock);
            return ODS_STATUS_OK;
        }
        lock_basic_unlock(&zone->stats->stats_lock);
    }
    ods_log_verbose("[%s] audit zone %s", tools_str, zone->name);
    inbound = ods_build_path(zone->name, ".inbound", 0);
    finalized = ods_build_path(zone->name, ".finalized", 0);
    status = adfile_write(zone, finalized);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to audit zone %s: failed to write zone",
            tools_str, zone->name);
        free((void*)inbound);
        free((void*)finalized);
        return status;
    }
    snprintf(str, SYSTEM_MAXLEN, "%s -c %s -u %s/%s -s %s/%s -z %s "
        "> /dev/null", ODS_SE_AUDITOR, cfg_filename, working_dir,
        inbound, working_dir, finalized, zone->name);
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
    return status;
}


/**
 * Write zone to output adapter.
 *
 */
ods_status
tools_output(zone_type* zone, const char* dir, const char* cfgfile)
{
    ods_status status = ODS_STATUS_OK;
    char str[SYSTEM_MAXLEN];
    int error = 0;
    ods_log_assert(zone);
    ods_log_assert(zone->db);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);
    ods_log_assert(zone->adoutbound);
    /* Auditor? */
    if (zone->signconf->audit) {
        status = tools_audit(zone, dir, cfgfile);
    }
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to write zone %s: audit failed",
            tools_str, zone->name);
        return ODS_STATUS_CONFLICT_ERR;
    }

    if (zone->stats) {
        lock_basic_lock(&zone->stats->stats_lock);
        if (zone->stats->sort_done == 0 &&
            (zone->stats->sig_count <= zone->stats->sig_soa_count)) {
            ods_log_verbose("[%s] skip write zone %s serial %u (zone not "
                "changed)", tools_str, zone->name?zone->name:"(null)",
                zone->db->intserial);
            stats_clear(zone->stats);
            lock_basic_unlock(&zone->stats->stats_lock);
            zone->db->intserial =
                zone->db->outserial;
            return ODS_STATUS_OK;
        }
        lock_basic_unlock(&zone->stats->stats_lock);
    }
    /* Output Adapter */
    status = adapter_write((void*)zone);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to write zone %s: adapter failed",
            tools_str, zone->name);
        return status;
    }
    zone->db->outserial = zone->db->intserial;
    zone->db->is_initialized = 1;
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
