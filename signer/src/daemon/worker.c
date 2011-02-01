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
 * The hard workers.
 *
 */

#include "daemon/engine.h"
#include "daemon/worker.h"
#include "shared/allocator.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "shared/locks.h"
#include "shared/log.h"
#include "signer/tools.h"
#include "signer/zone.h"

#include <time.h> /* time() */

ods_lookup_table worker_str[] = {
    { WORKER_WORKER, "worker" },
    { 0, NULL }
};


/**
 * Create worker.
 *
 */
worker_type*
worker_create(allocator_type* allocator, int num, worker_id type)
{
    worker_type* worker;

    if (!allocator) {
        return NULL;
    }
    ods_log_assert(allocator);

    worker = (worker_type*) allocator_alloc(allocator, sizeof(worker_type));
    if (!worker) {
        return NULL;
    }

    ods_log_debug("create worker[%i]", num +1);
    worker->thread_num = num +1;
    worker->engine = NULL;
    worker->task = NULL;
    worker->need_to_exit = 0;
    worker->type = type;
    worker->sleeping = 0;
    worker->waiting = 0;
    lock_basic_init(&worker->worker_lock);
    lock_basic_set(&worker->worker_alarm);
    return worker;
}


/**
 * Convert worker type to string.
 *
 */
static const char*
worker2str(worker_id type)
{
    ods_lookup_table *lt = ods_lookup_by_id(worker_str, type);
    if (lt) {
        return lt->name;
    }
    return NULL;
}


/**
 * Worker perform task.
 *
 */
static void
worker_perform_task(worker_type* worker)
{
    engine_type* engine = NULL;
    zone_type* zone = NULL;
    task_type* task = NULL;

    char* working_dir = NULL;
    char* cfg_filename = NULL;
    int error = 0;

    if (!worker || !worker->task || !worker->task->zone || !worker->engine) {
        return;
    }
    ods_log_assert(worker);
    ods_log_assert(worker->task);
    ods_log_assert(worker->task->zone);

    engine = (engine_type*) worker->engine;
    task = (task_type*) worker->task;
    zone = (zone_type*) worker->task->zone;

    switch (task->what) {
        case TASK_NONE:
            ods_log_warning("[%s[%i]] no task for zone %s", worker2str(worker->type),
                task->who?task->who:"(null)");
            break;
        case TASK_READ:
            if (tools_read_input(zone) != 0) {
                ods_log_error("task [read zone %s] failed",
                    task->who?task->who:"(null)");
                task->what = TASK_SIGN;
                task->when = time_now() +
                    duration2time(zone->signconf->sig_resign_interval);
                goto task_perform_continue;
                break;
            }
            task->what = TASK_ADDKEYS;
        case TASK_ADDKEYS:
            if (tools_add_dnskeys(zone) != 0) {
                ods_log_error("task [add dnskeys to zone %s] failed",
                    task->who?task->who:"(null)");
                task->what = TASK_SIGN;
                task->when = time_now() +
                    duration2time(zone->signconf->sig_resign_interval);
                goto task_perform_continue;
                break;
            }
            task->what = TASK_UPDATE;
        case TASK_UPDATE:
            if (tools_update(zone) != 0) {
                ods_log_error("task [update zone %s] failed",
                    task->who?task->who:"(null)");
                task->what = TASK_SIGN;
                task->when = time_now() +
                    duration2time(zone->signconf->sig_resign_interval);
                goto task_perform_continue;
                break;
            }
            task->what = TASK_NSECIFY;
        case TASK_NSECIFY:
            if (tools_nsecify(zone) != 0) {
                ods_log_error("task [nsecify zone %s] failed",
                    task->who?task->who:"(null)");
                goto task_perform_fail;
                break;
            }
            task->what = TASK_SIGN;
        case TASK_SIGN:
            if (tools_sign(zone) != 0) {
                ods_log_error("task [sign zone %s] failed",
                    task->who?task->who:"(null)");
                goto task_perform_fail;
                break;
            }
            task->what = TASK_AUDIT;
        case TASK_AUDIT:
            working_dir = strdup(engine->config->working_dir);
            cfg_filename = strdup(engine->config->cfg_filename);
            error = tools_audit(zone, working_dir, cfg_filename);
            if (working_dir)  { free((void*)working_dir); }
            if (cfg_filename) { free((void*)cfg_filename); }
            working_dir = NULL;
            cfg_filename = NULL;
            if (error) {
                ods_log_error("task [audit zone %s] failed",
                    task->who?task->who:"(null)");
                task->what = TASK_SIGN;
                goto task_perform_fail;
                break;
            }
            task->what = TASK_WRITE;
        case TASK_WRITE:
            if (tools_write_output(zone) != 0) {
                ods_log_error("task [write zone %s] failed",
                    task->who?task->who:"(null)");
                task->what = TASK_SIGN;
                goto task_perform_fail;
                break;
            }
            task->what = TASK_SIGN;
            task->when = time_now() +
                duration2time(zone->signconf->sig_resign_interval);
            break;
        default:
            ods_log_warning("unknown task[id %i zone %s], "
                "trying full sign", task->what, task->who?task->who:"(null)");
            task->what = TASK_READ;
            task->when = time_now();
            break;
    }
    return;

task_perform_fail:
    if (zone->backoff) {
        zone->backoff *= 2;
        if (zone->backoff > ODS_SE_MAX_BACKOFF) {
            zone->backoff = ODS_SE_MAX_BACKOFF;
        }
    } else {
        zone->backoff = 60;
    }
    task->when += zone->backoff;

task_perform_continue:
    return;
}


/**
 * Start worker.
 *
 */
void
worker_start(worker_type* worker)
{
    engine_type* engine = NULL;
    task_type* task = NULL;
    time_t now, timeout = 1;
    zone_type* zone = NULL;
    ods_status status = ODS_STATUS_OK;

    ods_log_assert(worker);
    ods_log_assert(worker->type == WORKER_WORKER);

    engine = (engine_type*) worker->engine;

    while (worker->need_to_exit == 0) {
        ods_log_debug("[%s[%i]]: report for duty", worker2str(worker->type),
            worker->thread_num);
        lock_basic_lock(&engine->taskq->schedule_lock);
        /* [LOCK] schedule */
        worker->task = schedule_pop_task(engine->taskq);
        /* [UNLOCK] schedule */
        if (worker->task) {
            lock_basic_unlock(&engine->taskq->schedule_lock);

            zone = worker->task->zone;
            lock_basic_lock(&zone->zone_lock);
            ods_log_debug("[%s[%i]] start working on zone %s",
                worker2str(worker->type), worker->thread_num, zone->name);
            zone->in_progress = 1;

            worker_perform_task(worker);
            zone->processed = 1;
            lock_basic_unlock(&zone->zone_lock);

            if (worker->task->what == TASK_NONE) {
                zone->in_progress = 0;
                ods_log_debug("[%s[%i]] cleanup task none for zone %s",
                    worker2str(worker->type), worker->thread_num, task->who);
                task_cleanup(worker->task);
            } else {
                lock_basic_lock(&engine->taskq->schedule_lock);
                zone->in_progress = 0;
                status = schedule_task(engine->taskq, worker->task, 1);
                if (status != ODS_STATUS_OK) {
                    ods_log_error("[%s[%i]] failed to schedule task",
                        worker2str(worker->type));
                } else {
                    task_backup(task);
                    task = NULL;
                }
                lock_basic_unlock(&engine->taskq->schedule_lock);
            }
            worker->task = NULL;
            timeout = 1;
        } else {
            ods_log_debug("[%s[%i]] nothing to do", worker2str(worker->type),
                worker->thread_num);

            task = schedule_get_first_task(engine->taskq);
            lock_basic_unlock(&engine->taskq->schedule_lock);

            now = time_now();
            if (task && !engine->taskq->loading) {
                timeout = (task->when - now);
            } else {
                timeout *= 2;
                if (timeout > ODS_SE_MAX_BACKOFF) {
                    timeout = ODS_SE_MAX_BACKOFF;
                }
            }

            worker_sleep(worker, timeout);
        }
    }
    return;
}


/**
 * Clean up worker.
 *
 */
void
worker_cleanup(worker_type* worker)
{
    int num = 0;

    if (worker) {
         num = worker->thread_num;
         lock_basic_destroy(&worker->worker_lock);
         lock_basic_off(&worker->worker_alarm);
         free((void*)worker);
    }
    return;
}


/**
 * Put worker to sleep.
 *
 */
void
worker_sleep(worker_type* worker, time_t timeout)
{
    ods_log_assert(worker);
    lock_basic_lock(&worker->worker_lock);
    worker->sleeping = 1;
    lock_basic_sleep(&worker->worker_alarm, &worker->worker_lock,
        timeout);
    lock_basic_unlock(&worker->worker_lock);
    return;
}


/**
 * Worker waiting.
 *
 */
void
worker_wait(worker_type* worker)
{
    ods_log_assert(worker);
    lock_basic_lock(&worker->worker_lock);
    worker->waiting = 1;
    lock_basic_sleep(&worker->worker_alarm, &worker->worker_lock, 0);
    lock_basic_unlock(&worker->worker_lock);
    return;
}


/**
 * Wake up worker.
 *
 */
void
worker_wakeup(worker_type* worker)
{
    ods_log_assert(worker);
    ods_log_assert(!worker->waiting);
    if (worker && worker->sleeping && !worker->waiting) {
        ods_log_debug("[%s[%i]] wake up", worker2str(worker->type),
           worker->thread_num);
        lock_basic_lock(&worker->worker_lock);
        lock_basic_alarm(&worker->worker_alarm);
        worker->sleeping = 0;
        lock_basic_unlock(&worker->worker_lock);
    }
    return;
}


/**
 * Notify worker.
 *
 */
void
worker_notify(worker_type* worker)
{
    ods_log_assert(worker);
    ods_log_assert(!worker->sleeping);
    if (worker && worker->waiting && !worker->sleeping) {
        ods_log_debug("[%s[%i]] notify", worker2str(worker->type),
           worker->thread_num);
        lock_basic_lock(&worker->worker_lock);
        lock_basic_alarm(&worker->worker_alarm);
        worker->waiting = 0;
        lock_basic_unlock(&worker->worker_lock);
    }
    return;
}
