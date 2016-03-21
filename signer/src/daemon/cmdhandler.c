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
 * Command handler.
 *
 */

#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "file.h"
#include "str.h"
#include "locks.h"
#include "log.h"
#include "status.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <ldns/ldns.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <unistd.h>
/* According to earlier standards: select() sys/time.h sys/types.h unistd.h */
#include <sys/time.h>
#include <sys/types.h>

#define SE_CMDH_CMDLEN 7

#ifndef SUN_LEN
#define SUN_LEN(su)  (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

static int count = 0;
static char const * cmdh_str = "cmdhandler";


/**
 * Handle the 'help' command.
 *
 */
static void
cmdhandler_handle_cmd_help(int sockfd)
{
    char buf[ODS_SE_MAXLINE];

    (void) snprintf(buf, ODS_SE_MAXLINE,
        "Commands:\n"
        "zones                       Show the currently known zones.\n"
        "sign <zone> [--serial <nr>] Read zone and schedule for immediate "
                                    "(re-)sign.\n"
        "                            If a serial is given, that serial is used "
                                    "in the output zone.\n"
        "sign --all                  Read all zones and schedule all for "
                                    "immediate (re-)sign.\n"
    );
    ods_writen(sockfd, buf, strlen(buf));

    (void) snprintf(buf, ODS_SE_MAXLINE,
        "clear <zone>                Delete the internal storage of this "
                                    "zone.\n"
        "                            All signatures will be regenerated "
                                    "on the next re-sign.\n"
        "queue                       Show the current task queue.\n"
        "flush                       Execute all scheduled tasks "
                                    "immediately.\n"
    );
    ods_writen(sockfd, buf, strlen(buf));

    (void) snprintf(buf, ODS_SE_MAXLINE,
        "update <zone>               Update this zone signer "
                                    "configurations.\n"
        "update [--all]              Update zone list and all signer "
                                    "configurations.\n"
        "retransfer <zone>           Retransfer the zone from the master.\n"
        "start                       Start the engine.\n"
        "running                     Check if the engine is running.\n"
        "reload                      Reload the engine.\n"
        "stop                        Stop the engine.\n"
        "verbosity <nr>              Set verbosity.\n"
    );
    ods_writen(sockfd, buf, strlen(buf));
}


/**
 * Handle the 'zones' command.
 *
 */
static void
cmdhandler_handle_cmd_zones(int sockfd, cmdhandler_type* cmdc)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    size_t i;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = cmdc->engine;
    if (!engine->zonelist || !engine->zonelist->zones) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "There are no zones configured\n");
        ods_writen(sockfd, buf, strlen(buf));
        return;
    }
    /* how many zones */
    lock_basic_lock(&engine->zonelist->zl_lock);
    (void)snprintf(buf, ODS_SE_MAXLINE, "There are %i zones configured\n",
        (int) engine->zonelist->zones->count);
    ods_writen(sockfd, buf, strlen(buf));
    /* list zones */
    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->data;
        for (i=0; i < ODS_SE_MAXLINE; i++) {
            buf[i] = 0;
        }
        (void)snprintf(buf, ODS_SE_MAXLINE, "- %s\n", zone->name);
        ods_writen(sockfd, buf, strlen(buf));
        node = ldns_rbtree_next(node);
    }
    lock_basic_unlock(&engine->zonelist->zl_lock);
}


/**
 * Handle the 'update' command.
 *
 */
static void
cmdhandler_handle_cmd_update(int sockfd, cmdhandler_type* cmdc,
    const char* tbd)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    ods_status status = ODS_STATUS_OK;
    zone_type* zone = NULL;
    ods_status zl_changed = ODS_STATUS_OK;
    ods_log_assert(tbd);
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = cmdc->engine;
    ods_log_assert(engine->taskq);
    if (ods_strcmp(tbd, "--all") == 0) {
        lock_basic_lock(&engine->zonelist->zl_lock);
        zl_changed = zonelist_update(engine->zonelist,
            engine->config->zonelist_filename);
        if (zl_changed == ODS_STATUS_UNCHANGED) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone list has not changed."
                " Signer configurations updated.\n");
            ods_writen(sockfd, buf, strlen(buf));
        } else if (zl_changed == ODS_STATUS_OK) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone list updated: %i "
            "removed, %i added, %i updated.\n",
                engine->zonelist->just_removed,
                engine->zonelist->just_added,
                engine->zonelist->just_updated);
            ods_writen(sockfd, buf, strlen(buf));
        } else {
            lock_basic_unlock(&engine->zonelist->zl_lock);
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone list has errors.\n");
            ods_writen(sockfd, buf, strlen(buf));
        }
        if (zl_changed == ODS_STATUS_OK ||
            zl_changed == ODS_STATUS_UNCHANGED) {
            engine->zonelist->just_removed = 0;
            engine->zonelist->just_added = 0;
            engine->zonelist->just_updated = 0;
            lock_basic_unlock(&engine->zonelist->zl_lock);
            /**
              * Always update the signconf for zones, even if zonelist has
              * not changed: ODS_STATUS_OK.
              */
            engine_update_zones(engine, ODS_STATUS_OK);
        }
    } else {
        /* look up zone */
        lock_basic_lock(&engine->zonelist->zl_lock);
        zone = zonelist_lookup_zone_by_name(engine->zonelist, tbd,
            LDNS_RR_CLASS_IN);
        /* If this zone is just added, don't update (it might not have a
         * task yet) */
        if (zone && zone->zl_status == ZONE_ZL_ADDED) {
            zone = NULL;
        }
        lock_basic_unlock(&engine->zonelist->zl_lock);

        if (!zone) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Error: Zone %s not found.\n",
                tbd);
            ods_writen(sockfd, buf, strlen(buf));
            /* update all */
            cmdhandler_handle_cmd_update(sockfd, cmdc, "--all");
            return;
        }

        lock_basic_lock(&zone->zone_lock);
        status = zone_reschedule_task(zone, engine->taskq, TASK_SIGNCONF);
        lock_basic_unlock(&zone->zone_lock);

        if (status != ODS_STATUS_OK) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Error: Unable to reschedule "
                "task for zone %s.\n", tbd);
            ods_writen(sockfd, buf, strlen(buf));
            ods_log_crit("[%s] unable to reschedule task for zone %s: %s",
                cmdh_str, zone->name, ods_status2str(status));
        } else {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s config being updated.\n",
            tbd);
            ods_writen(sockfd, buf, strlen(buf));
            ods_log_verbose("[%s] zone %s scheduled for immediate update signconf",
                cmdh_str, tbd);
            engine_wakeup_workers(engine);
        }
    }
}


/**
 * Handle the 'retransfer' command.
 *
 */
static void
cmdhandler_handle_cmd_retransfer(int sockfd, cmdhandler_type* cmdc, char* tbd)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    zone_type* zone = NULL;
    ods_log_assert(tbd);
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;
    ods_log_assert(engine->taskq);
    /* look up zone */
    lock_basic_lock(&engine->zonelist->zl_lock);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, tbd,
        LDNS_RR_CLASS_IN);
    /* If this zone is just added, don't retransfer (it might not have a
     * task yet) */
    if (zone && zone->zl_status == ZONE_ZL_ADDED) {
        zone = NULL;
    }
    lock_basic_unlock(&engine->zonelist->zl_lock);

    if (!zone) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "Error: Zone %s not found.\n",
            tbd);
        ods_writen(sockfd, buf, strlen(buf));
    } else if (zone->adinbound->type != ADAPTER_DNS) {
        (void)snprintf(buf, ODS_SE_MAXLINE,
            "Error: Zone %s not configured to use DNS input adapter.\n",
            tbd);
        ods_writen(sockfd, buf, strlen(buf));
    } else {
        zone->xfrd->serial_retransfer = 1;
        xfrd_set_timer_now(zone->xfrd);
        ods_log_debug("[%s] forward a notify", cmdh_str);
        dnshandler_fwd_notify(engine->dnshandler,
            (uint8_t*) ODS_SE_NOTIFY_CMD, strlen(ODS_SE_NOTIFY_CMD));
        (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s being retransferred.\n", tbd);
        ods_writen(sockfd, buf, strlen(buf));
        ods_log_verbose("[%s] zone %s being retransferred", cmdh_str, tbd);
    }
}


static uint32_t
max(uint32_t a, uint32_t b)
{
    return (a<b?b:a);
}


/**
 * Handle the 'sign' command.
 *
 */
static void
cmdhandler_handle_cmd_sign(int sockfd, cmdhandler_type* cmdc, const char* tbd)
{
    engine_type* engine = NULL;
    zone_type* zone = NULL;
    ods_status status = ODS_STATUS_OK;
    char buf[ODS_SE_MAXLINE];

    ods_log_assert(tbd);
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;
    ods_log_assert(engine->taskq);
    if (ods_strcmp(tbd, "--all") == 0) {
        lock_basic_lock(&engine->taskq->schedule_lock);
        schedule_flush(engine->taskq, TASK_READ);
        lock_basic_unlock(&engine->taskq->schedule_lock);
        engine_wakeup_workers(engine);
        (void)snprintf(buf, ODS_SE_MAXLINE, "All zones scheduled for "
            "immediate re-sign.\n");
        ods_writen(sockfd, buf, strlen(buf));
        ods_log_verbose("[%s] all zones scheduled for immediate re-sign",
            cmdh_str);
    } else {
        char* delim1 = strchr(tbd, ' ');
        char* delim2 = NULL;
        int force_serial = 0;
        uint32_t serial = 0;
        if (delim1) {
            char* end = NULL;
            /** Some trailing text, could it be --serial? */
            if (strncmp(delim1+1, "--serial ", 9) != 0) {
                (void)snprintf(buf, ODS_SE_MAXLINE, "Error: Expecting <zone> "
                    "--serial <nr>, got %s.\n", tbd);
                ods_writen(sockfd, buf, strlen(buf));
                return;
            }
            delim2 = strchr(delim1+1, ' ');
            if (!delim2) {
                (void)snprintf(buf, ODS_SE_MAXLINE, "Error: Expecting serial.\n");
                ods_writen(sockfd, buf, strlen(buf));
                return;
            }
            serial = (uint32_t) strtol(delim2+1, &end, 10);
            if (*end != '\0') {
                (void)snprintf(buf, ODS_SE_MAXLINE, "Error: Expecting serial, "
                    "got %s.\n", delim2+1);
                ods_writen(sockfd, buf, strlen(buf));
                return;
            }
            force_serial = 1;
            *delim1 = '\0';
        }
        lock_basic_lock(&engine->zonelist->zl_lock);
        zone = zonelist_lookup_zone_by_name(engine->zonelist, tbd,
            LDNS_RR_CLASS_IN);
        /* If this zone is just added, don't update (it might not have a task
         * yet).
         */
        if (zone && zone->zl_status == ZONE_ZL_ADDED) {
            zone = NULL;
        }
        lock_basic_unlock(&engine->zonelist->zl_lock);

        if (!zone) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Error: Zone %s not found.\n",
                tbd);
            ods_writen(sockfd, buf, strlen(buf));
            return;
        }

        lock_basic_lock(&zone->zone_lock);
        if (force_serial) {
            ods_log_assert(zone->db);
            if (!util_serial_gt(serial, max(zone->db->outserial,
                zone->db->inbserial))) {
                lock_basic_unlock(&zone->zone_lock);
                (void)snprintf(buf, ODS_SE_MAXLINE, "Error: Unable to enforce "
                    "serial %u for zone %s.\n", serial, tbd);
                ods_writen(sockfd, buf, strlen(buf));
                return;
            }
            zone->db->altserial = serial;
            zone->db->force_serial = 1;
        }
        status = zone_reschedule_task(zone, engine->taskq, TASK_READ);
        lock_basic_unlock(&zone->zone_lock);

        if (status != ODS_STATUS_OK) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Error: Unable to reschedule "
                "task for zone %s.\n", tbd);
            ods_writen(sockfd, buf, strlen(buf));
            ods_log_crit("[%s] unable to reschedule task for zone %s: %s",
                cmdh_str, zone->name, ods_status2str(status));
        } else {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s scheduled for "
                "immediate re-sign.\n", tbd);
            ods_writen(sockfd, buf, strlen(buf));
            ods_log_verbose("[%s] zone %s scheduled for immediate re-sign",
                cmdh_str, tbd);
            engine_wakeup_workers(engine);
        }
    }
}


/**
 * Unlink backup file.
 *
 */
static void
unlink_backup_file(const char* filename, const char* extension)
{
    char* tmpname = ods_build_path(filename, extension, 0, 1);
    if (tmpname) {
        ods_log_debug("[%s] unlink file %s", cmdh_str, tmpname);
        unlink(tmpname);
        free((void*)tmpname);
    }
}

/**
 * Handle the 'clear' command.
 *
 */
static void
cmdhandler_handle_cmd_clear(int sockfd, cmdhandler_type* cmdc, const char* tbd)
{
    ods_status status = ODS_STATUS_OK;
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    zone_type* zone = NULL;
    uint32_t inbserial = 0;
    uint32_t intserial = 0;
    uint32_t outserial = 0;
    ods_log_assert(tbd);
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;
    unlink_backup_file(tbd, ".inbound");
    unlink_backup_file(tbd, ".backup");
    unlink_backup_file(tbd, ".axfr");
    unlink_backup_file(tbd, ".ixfr");
    lock_basic_lock(&engine->zonelist->zl_lock);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, tbd,
        LDNS_RR_CLASS_IN);
    lock_basic_unlock(&engine->zonelist->zl_lock);
    if (zone) {
        lock_basic_lock(&zone->zone_lock);
        inbserial = zone->db->inbserial;
        intserial = zone->db->intserial;
        outserial = zone->db->outserial;
        namedb_cleanup(zone->db);
        ixfr_cleanup(zone->ixfr);
        signconf_cleanup(zone->signconf);

        zone->db = namedb_create((void*)zone);
        zone->ixfr = ixfr_create((void*)zone);
        zone->signconf = signconf_create();

        if (!zone->signconf || !zone->ixfr || !zone->db) {
            ods_fatal_exit("[%s] unable to clear zone %s: failed to recreate"
            "signconf, ixfr of db structure (out of memory?)", cmdh_str, tbd);
            return;
        }
        /* restore serial management */
        zone->db->inbserial = inbserial;
        zone->db->intserial = intserial;
        zone->db->outserial = outserial;
        zone->db->have_serial = 1;

        status = zone_reschedule_task(zone, engine->taskq, TASK_SIGNCONF);
        lock_basic_unlock(&zone->zone_lock);

        if (status != ODS_STATUS_OK) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Error: Unable to reschedule "
                "task for zone %s.\n", tbd);
            ods_log_crit("[%s] unable to reschedule task for zone %s: %s",
                cmdh_str, zone->name, ods_status2str(status));
        } else {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Internal zone information about "
                "%s cleared", tbd?tbd:"(null)");
            ods_log_info("[%s] internal zone information about %s cleared",
                cmdh_str, tbd?tbd:"(null)");
        }
    } else {
        (void)snprintf(buf, ODS_SE_MAXLINE, "Cannot clear zone %s, zone not "
            "found", tbd?tbd:"(null)");
        ods_log_warning("[%s] cannot clear zone %s, zone not found",
            cmdh_str, tbd?tbd:"(null)");
    }
    ods_writen(sockfd, buf, strlen(buf));
}


/**
 * Handle the 'queue' command.
 *
 */
static void
cmdhandler_handle_cmd_queue(int sockfd, cmdhandler_type* cmdc)
{
    engine_type* engine = NULL;
    char* strtime = NULL;
    char buf[ODS_SE_MAXLINE];
    size_t i = 0;
    time_t now = 0;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    task_type* task = NULL;
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;
    if (!engine->taskq || !engine->taskq->tasks) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "There are no tasks scheduled.\n");
        ods_writen(sockfd, buf, strlen(buf));
        return;
    }
    /* current time */
    now = time_now();
    strtime = ctime(&now);
    (void)snprintf(buf, ODS_SE_MAXLINE, "It is now %s",
        strtime?strtime:"(null)");
    ods_writen(sockfd, buf, strlen(buf));
    /* current work */
    lock_basic_lock(&engine->taskq->schedule_lock);
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        task = engine->workers[i]->task;
        if (task) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Working with task %s on "
                "zone %s\n",
                task_what2str(engine->workers[i]->working_with),
                task_who2str(task));
            ods_writen(sockfd, buf, strlen(buf));
        }
    }
    /* how many tasks */
    (void)snprintf(buf, ODS_SE_MAXLINE, "\nThere are %i tasks scheduled.\n",
        (int) engine->taskq->tasks->count);
    ods_writen(sockfd, buf, strlen(buf));
    /* list tasks */
    node = ldns_rbtree_first(engine->taskq->tasks);
    while (node && node != LDNS_RBTREE_NULL) {
        task = (task_type*) node->data;
        for (i=0; i < ODS_SE_MAXLINE; i++) {
            buf[i] = 0;
        }
        (void)task2str(task, (char*) &buf[0]);
        ods_writen(sockfd, buf, strlen(buf));
        node = ldns_rbtree_next(node);
    }
    lock_basic_unlock(&engine->taskq->schedule_lock);
}


/**
 * Handle the 'flush' command.
 *
 */
static void
cmdhandler_handle_cmd_flush(int sockfd, cmdhandler_type* cmdc)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;
    ods_log_assert(engine->taskq);
    lock_basic_lock(&engine->taskq->schedule_lock);
    schedule_flush(engine->taskq, TASK_NONE);
    lock_basic_unlock(&engine->taskq->schedule_lock);
    engine_wakeup_workers(engine);
    (void)snprintf(buf, ODS_SE_MAXLINE, "All tasks scheduled immediately.\n");
    ods_writen(sockfd, buf, strlen(buf));
    ods_log_verbose("[%s] all tasks scheduled immediately", cmdh_str);
}


/**
 * Handle the 'reload' command.
 *
 */
static void
cmdhandler_handle_cmd_reload(int sockfd, cmdhandler_type* cmdc)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;
    engine->need_to_reload = 1;
    lock_basic_lock(&engine->signal_lock);
    lock_basic_alarm(&engine->signal_cond);
    lock_basic_unlock(&engine->signal_lock);
    (void)snprintf(buf, ODS_SE_MAXLINE, "Reloading engine.\n");
    ods_writen(sockfd, buf, strlen(buf));
}


/**
 * Handle the 'stop' command.
 *
 */
static void
cmdhandler_handle_cmd_stop(int sockfd, cmdhandler_type* cmdc)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;
    engine->need_to_exit = 1;
    lock_basic_lock(&engine->signal_lock);
    lock_basic_alarm(&engine->signal_cond);
    lock_basic_unlock(&engine->signal_lock);
    (void)snprintf(buf, ODS_SE_MAXLINE, ODS_SE_STOP_RESPONSE);
    ods_writen(sockfd, buf, strlen(buf));
}


/**
 * Handle the 'start' command.
 *
 */
static void
cmdhandler_handle_cmd_start(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, "Engine already running.\n");
    ods_writen(sockfd, buf, strlen(buf));
}


/**
 * Handle the 'running' command.
 *
 */
static void
cmdhandler_handle_cmd_running(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, "Engine running.\n");
    ods_writen(sockfd, buf, strlen(buf));
}


/**
 * Handle the 'verbosity' command.
 *
 */
static void
cmdhandler_handle_cmd_verbosity(int sockfd, cmdhandler_type* cmdc, int val)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;
    ods_log_assert(engine->config);
    ods_log_init("ods-signerd", engine->config->use_syslog, engine->config->log_filename, val);
    (void)snprintf(buf, ODS_SE_MAXLINE, "Verbosity level set to %i.\n", val);
    ods_writen(sockfd, buf, strlen(buf));
}


/**
 * Handle erroneous command.
 *
 */
static void
cmdhandler_handle_cmd_error(int sockfd, const char* str)
{
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, "Error: %s.\n", str?str:"(null)");
    ods_writen(sockfd, buf, strlen(buf));
}


/**
 * Handle unknown command.
 *
 */
static void
cmdhandler_handle_cmd_unknown(int sockfd, const char* str)
{
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, "Unknown command %s.\n",
        str?str:"(null)");
    ods_writen(sockfd, buf, strlen(buf));
}


/**
 * Handle not implemented.
 *
static void
cmdhandler_handle_cmd_notimpl(int sockfd, const char* str)
{
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, "Command %s not implemented.\n", str);
    ods_writen(sockfd, buf, strlen(buf));
}
 */


/**
 * Handle client command.
 *
 */
static void
cmdhandler_handle_cmd(cmdhandler_type* cmdc)
{
    ssize_t n = 0;
    int sockfd = 0;
    char buf[ODS_SE_MAXLINE];

    ods_log_assert(cmdc);
    sockfd = cmdc->client_fd;

again:
    while ((n = read(sockfd, buf, ODS_SE_MAXLINE)) > 0) {
        /* what if this number is smaller than the number of bytes requested? */
        buf[n-1] = '\0';
        n--;
        ods_log_verbose("[%s] received command %s[%ld]", cmdh_str, buf, (long)n);
        ods_str_trim(buf,1);
        n = strlen(buf);

        if (n == 4 && strncmp(buf, "help", n) == 0) {
            ods_log_debug("[%s] help command", cmdh_str);
            cmdhandler_handle_cmd_help(sockfd);
        } else if (n == 5 && strncmp(buf, "zones", n) == 0) {
            ods_log_debug("[%s] list zones command", cmdh_str);
            cmdhandler_handle_cmd_zones(sockfd, cmdc);
        } else if (n >= 4 && strncmp(buf, "sign", 4) == 0) {
            ods_log_debug("[%s] sign zone command", cmdh_str);
            if (n == 4 || buf[4] == '\0') {
                /* NOTE: wouldn't it be nice that we default to --all? */
                cmdhandler_handle_cmd_error(sockfd, "sign command needs "
                    "an argument (either '--all' or a zone name)");
            } else if (buf[4] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_sign(sockfd, cmdc, &buf[5]);
            }
        } else if (n >= 5 && strncmp(buf, "clear", 5) == 0) {
            ods_log_debug("[%s] clear zone command", cmdh_str);
            if (n == 5 || buf[5] == '\0') {
                cmdhandler_handle_cmd_error(sockfd, "clear command needs "
                    "a zone name");
            } else if (buf[5] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_clear(sockfd, cmdc, &buf[6]);
            }
        } else if (n == 5 && strncmp(buf, "queue", n) == 0) {
            ods_log_debug("[%s] list tasks command", cmdh_str);
            cmdhandler_handle_cmd_queue(sockfd, cmdc);
        } else if (n == 5 && strncmp(buf, "flush", n) == 0) {
            ods_log_debug("[%s] flush tasks command", cmdh_str);
            cmdhandler_handle_cmd_flush(sockfd, cmdc);
        } else if (n >= 6 && strncmp(buf, "update", 6) == 0) {
            ods_log_debug("[%s] update command", cmdh_str);
            if (n == 6 || buf[6] == '\0') {
                cmdhandler_handle_cmd_update(sockfd, cmdc, "--all");
            } else if (buf[6] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_update(sockfd, cmdc, &buf[7]);
            }
        } else if (n == 4 && strncmp(buf, "stop", n) == 0) {
            ods_log_debug("[%s] shutdown command", cmdh_str);
            cmdhandler_handle_cmd_stop(sockfd, cmdc);
            return;
        } else if (n == 5 && strncmp(buf, "start", n) == 0) {
            ods_log_debug("[%s] start command", cmdh_str);
            cmdhandler_handle_cmd_start(sockfd);
        } else if (n == 6 && strncmp(buf, "reload", n) == 0) {
            ods_log_debug("[%s] reload command", cmdh_str);
            cmdhandler_handle_cmd_reload(sockfd, cmdc);
        } else if (n == 7 && strncmp(buf, "running", n) == 0) {
            ods_log_debug("[%s] running command", cmdh_str);
            cmdhandler_handle_cmd_running(sockfd);
        } else if (n >= 9 && strncmp(buf, "verbosity", 9) == 0) {
            ods_log_debug("[%s] verbosity command", cmdh_str);
            if (n == 9 || buf[9] == '\0') {
                cmdhandler_handle_cmd_error(sockfd, "verbosity command "
                    "an argument (verbosity level)");
            } else if (buf[9] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_verbosity(sockfd, cmdc, atoi(&buf[10]));
            }
        } else if (n >= 10 && strncmp(buf, "retransfer", 10) == 0) {
            ods_log_debug("[%s] retransfer zone command", cmdh_str);
            if (n == 10 || buf[10] == '\0') {
                cmdhandler_handle_cmd_error(sockfd, "retransfer command needs "
                    "an argument (a zone name)");
            } else if (buf[10] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_retransfer(sockfd, cmdc, &buf[11]);
            }
        } else if (n > 0) {
            ods_log_debug("[%s] unknown command", cmdh_str);
            cmdhandler_handle_cmd_unknown(sockfd, buf);
        }
        ods_log_debug("[%s] done handling command %s[%ld]", cmdh_str, buf, (long)n);
        (void)snprintf(buf, SE_CMDH_CMDLEN, "\ncmd> ");
        ods_writen(sockfd, buf, strlen(buf));
    }

    if (n < 0 && (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) ) {
        goto again;
    } else if (n < 0 && errno == ECONNRESET) {
        ods_log_debug("[%s] done handling client: %s", cmdh_str,
            strerror(errno));
    } else if (n < 0 ) {
        ods_log_error("[%s] read error: %s", cmdh_str, strerror(errno));
    }
}


/**
 * Accept client.
 *
 */
static void*
cmdhandler_accept_client(void* arg)
{
    cmdhandler_type* cmdc = (cmdhandler_type*) arg;

    ods_thread_blocksigs();
    ods_thread_detach(cmdc->thread_id);

    ods_log_debug("[%s] accept client %i", cmdh_str, cmdc->client_fd);
    cmdhandler_handle_cmd(cmdc);
    if (cmdc->client_fd) {
        shutdown(cmdc->client_fd, SHUT_RDWR);
        close(cmdc->client_fd);
    }
    free(cmdc);
    count--;
    return NULL;
}


/**
 * Create command handler.
 *
 */
cmdhandler_type*
cmdhandler_create(const char* filename)
{
    cmdhandler_type* cmdh = NULL;
    struct sockaddr_un servaddr;
    int listenfd = 0;
    int flags = 0;
    int ret = 0;

    if (!filename) {
        return NULL;
    }
    /* new socket */
    ods_log_debug("[%s] create socket %s", cmdh_str, filename);
    listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenfd < 0) {
        ods_log_error("[%s] unable to create cmdhandler: "
            "socket() failed (%s)", cmdh_str, strerror(errno));
        return NULL;
    }
    /* set it to non-blocking */
    flags = fcntl(listenfd, F_GETFL, 0);
    if (flags < 0) {
        ods_log_error("[%s] unable to create cmdhandler: "
            "fcntl(F_GETFL) failed (%s)", cmdh_str, strerror(errno));
        close(listenfd);
        return NULL;
    }
    flags |= O_NONBLOCK;
    if (fcntl(listenfd, F_SETFL, flags) < 0) {
        ods_log_error("[%s] unable to create cmdhandler: "
            "fcntl(F_SETFL) failed (%s)", cmdh_str, strerror(errno));
        close(listenfd);
        return NULL;
    }
    /* no surprises so far */
    if (filename) {
        (void)unlink(filename);
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strncpy(servaddr.sun_path, filename, sizeof(servaddr.sun_path) - 1);
#ifdef HAVE_SOCKADDR_SUN_LEN
    servaddr.sun_len = strlen(servaddr.sun_path);
#endif
    /* bind and listen... */
    ret = bind(listenfd, (const struct sockaddr*) &servaddr,
        SUN_LEN(&servaddr));
    if (ret != 0) {
        ods_log_error("[%s] unable to create cmdhandler: "
            "bind() failed (%s)", cmdh_str, strerror(errno));
        close(listenfd);
        return NULL;
    }
    ret = listen(listenfd, ODS_SE_MAX_HANDLERS);
    if (ret != 0) {
        ods_log_error("[%s] unable to create cmdhandler: "
            "listen() failed (%s)", cmdh_str, strerror(errno));
        close(listenfd);
        return NULL;
    }
    /* all ok */
    CHECKALLOC(cmdh = (cmdhandler_type*) malloc(sizeof(cmdhandler_type)));
    cmdh->listen_fd = listenfd;
    cmdh->listen_addr = servaddr;
    cmdh->need_to_exit = 0;
    return cmdh;
}


/**
 * Start command handler.
 *
 */
void
cmdhandler_start(cmdhandler_type* cmdhandler)
{
    struct sockaddr_un cliaddr;
    socklen_t clilen;
    cmdhandler_type* cmdc = NULL;
    engine_type* engine = NULL;
    fd_set rset;
    int connfd = 0;
    int ret = 0;
    ods_log_assert(cmdhandler);
    ods_log_assert(cmdhandler->engine);
    ods_log_debug("[%s] start", cmdh_str);
    engine = cmdhandler->engine;
    ods_thread_detach(cmdhandler->thread_id);
    FD_ZERO(&rset);
    while (cmdhandler->need_to_exit == 0) {
        clilen = sizeof(cliaddr);
        FD_SET(cmdhandler->listen_fd, &rset);
        ret = select(cmdhandler->listen_fd+1, &rset, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                ods_log_warning("[%s] select() error: %s", cmdh_str,
                   strerror(errno));
            }
            continue;
        }
        if (FD_ISSET(cmdhandler->listen_fd, &rset)) {
            connfd = accept(cmdhandler->listen_fd,
                (struct sockaddr *) &cliaddr, &clilen);
            if (connfd < 0) {
                if (errno != EINTR && errno != EWOULDBLOCK) {
                    ods_log_warning("[%s] accept() error: %s", cmdh_str,
                        strerror(errno));
                }
                continue;
            }
            /* client accepted, create new thread */
            cmdc = (cmdhandler_type*) malloc(sizeof(cmdhandler_type));
            if (!cmdc) {
                ods_log_crit("[%s] unable to create thread for client: "
                    "malloc() failed", cmdh_str);
                cmdhandler->need_to_exit = 1;
                break;
            }
            cmdc->listen_fd = cmdhandler->listen_fd;
            cmdc->client_fd = connfd;
            cmdc->listen_addr = cmdhandler->listen_addr;
            cmdc->engine = cmdhandler->engine;
            cmdc->need_to_exit = cmdhandler->need_to_exit;
            ods_thread_create(&cmdc->thread_id, &cmdhandler_accept_client,
                (void*) cmdc);
            count++;
            ods_log_debug("[%s] %i clients in progress...", cmdh_str, count);
        }
    }
    ods_log_debug("[%s] shutdown", cmdh_str);
    engine = cmdhandler->engine;
    engine->cmdhandler_done = 1;
}


/**
 * Cleanup command handler.
 *
 */
void
cmdhandler_cleanup(cmdhandler_type* cmdhandler)
{
    free(cmdhandler);
}

