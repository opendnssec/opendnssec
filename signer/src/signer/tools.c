/*
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
#include "daemon/dnshandler.h"
#include "adapter/adapter.h"
#include "log.h"
#include "signer/tools.h"
#include "signer/zone.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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

    ods_log_assert(zone);
    ods_log_assert(zone->name);
    status = zone_load_signconf(zone, &new_signconf);
    if (status == ODS_STATUS_OK) {
        ods_log_assert(new_signconf);
        /* Denial of Existence Rollover? */
        if (signconf_compare_denial(zone->signconf, new_signconf)
            == TASK_NSECIFY) {
            /**
             * Or NSEC -> NSEC3, or NSEC3 -> NSEC, or NSEC3 params changed.
             * All NSEC(3)s become invalid.
             */
            /* BERRY namedb_wipe_denial(zone, NULL); */
        }
        /* all ok, switch signer configuration */
        signconf_cleanup(zone->signconf);
        ods_log_debug("[%s] zone %s switch to new signconf", tools_str,
            zone->name);
        zone->signconf = new_signconf;
        signconf_log(zone->signconf, zone->name);
        zone->default_ttl = (uint32_t) duration2time(zone->signconf->soa_min);
    } else if (status != ODS_STATUS_UNCHANGED) {
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
    time_t start = 0;
    time_t end = 0;

    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->adinbound);
    ods_log_assert(zone->signconf);
    
    names_view_type view;
    names_viewobtain(zone->namedb, names_INPUTVIEW, &view);
    
    /* Key Rollover? */
    status = zone_publish_dnskeys(zone, view, 0);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read zone %s: failed to "
            "publish dnskeys (%s)", tools_str, zone->name,
            ods_status2str(status));
        return status;
    }
    /* Denial of Existence Rollover? */
    if (!zone->signconf->passthrough)
        status = zone_publish_nsec3param(zone, view);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read zone %s: failed to "
            "publish nsec3param (%s)", tools_str, zone->name,
            ods_status2str(status));
        return status;
    } else {

    if (zone->stats) {
        pthread_mutex_lock(&zone->stats->stats_lock);
        zone->stats->sort_done = 0;
        zone->stats->sort_count = 0;
        zone->stats->sort_time = 0;
        pthread_mutex_unlock(&zone->stats->stats_lock);
    }
    /* Input Adapter */
    start = time(NULL);
    status = adapter_read(zone, view);
    if (status != ODS_STATUS_OK && status != ODS_STATUS_UNCHANGED) {
        if (status == ODS_STATUS_XFRINCOMPLETE) {
            ods_log_info("[%s] read zone %s: xfr in progress",
                tools_str, zone->name);
        } else {
            ods_log_error("[%s] unable to read zone %s: adapter failed (%s)",
                tools_str, zone->name, ods_status2str(status));
        }
    }
    end = time(NULL);
    if ((status == ODS_STATUS_OK || status == ODS_STATUS_UNCHANGED)
        && zone->stats) {
        pthread_mutex_lock(&zone->stats->stats_lock);
        zone->stats->start_time = start;
        zone->stats->sort_time = (end-start);
        zone->stats->sort_done = 1;
        pthread_mutex_unlock(&zone->stats->stats_lock);
    }
    }
    switch(status) {
        case ODS_STATUS_OK:
            names_commit(view);
            break;
        case ODS_STATUS_UNCHANGED:
            names_dispose(view);
            break;
        default:
            names_rollback(view);
    }
    return status;
}


/**
 * Close file descriptors.
 *
 */
static void
ods_closeall(int fd)
{
    int fdlimit = sysconf(_SC_OPEN_MAX);
    while (fd < fdlimit) {
        close(fd++);
    }
}


/**
 * Write zone to output adapter.
 *
 */
ods_status
tools_output(zone_type* zone, engine_type* engine)
{
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);
    ods_log_assert(zone->adoutbound);
    /* Output Adapter */
    status = adapter_write(zone);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to write zone %s: adapter failed (%s)",
            tools_str, zone->name, ods_status2str(status));
        return status;
    }
    /* kick the nameserver */
    if (zone->notify_ns) {
	int pid_status;
        pid_t pid, wpid;
        ods_log_verbose("[%s] notify nameserver: %s", tools_str,
            zone->notify_ns);
	/** fork */
        switch ((pid = fork())) {
            case -1: /* error */
                ods_log_error("[%s] notify nameserver failed: unable to fork "
                    "(%s)", tools_str, strerror(errno));
                return ODS_STATUS_FORK_ERR;
            case 0: /* child */
                /** close fds */
		ods_closeall(0);
                /** execv */
                execvp(zone->notify_ns, zone->notify_args);
                /** error */
                ods_log_error("[%s] notify nameserver failed: execv() failed "
                    "(%s)", tools_str, strerror(errno));
                exit(1);
                break;
            default: /* parent */
                ods_log_debug("[%s] notify nameserver process forked",
                    tools_str);
                /** wait for completion  */
                while((wpid = waitpid(pid, &pid_status, 0)) <= 0) {
                    if (errno != EINTR) {
                        break;
                    }
                }
                if (wpid == -1) {
                    ods_log_error("[%s] notify nameserver failed: waitpid() "
                        "failed (%s)", tools_str, strerror(errno));
                } else if (!WIFEXITED(pid_status)) {
                    ods_log_error("[%s] notify nameserver failed: notify "
                        "command did not terminate normally", tools_str);
                } else {
                    ods_log_verbose("[%s] notify nameserver ok", tools_str);
                }
                break;
        }
    }
    /* log stats */
    if (zone->stats) {
        pthread_mutex_lock(&zone->stats->stats_lock);
        zone->stats->end_time = time(NULL);
        ods_log_debug("[%s] log stats for zone %s serial %u", tools_str,
            zone->name?zone->name:"(null)", (unsigned) *zone->outboundserial);
        stats_log(zone->stats, zone->name, *zone->outboundserial,
            zone->signconf->nsec_type);
        stats_clear(zone->stats);
        pthread_mutex_unlock(&zone->stats->stats_lock);
    }
    if (engine->dnshandler) {
        ods_log_debug("[%s] forward a notify", tools_str);
        dnshandler_fwd_notify(engine->dnshandler, (uint8_t*) ODS_SE_NOTIFY_CMD,
            strlen(ODS_SE_NOTIFY_CMD));
    }
    return status;
}
