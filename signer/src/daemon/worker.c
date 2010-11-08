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
#include "scheduler/locks.h"
#include "scheduler/task.h"
#include "signer/tools.h"
#include "signer/zone.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <time.h> /* time() */


/**
 * Create worker.
 *
 */
worker_type*
worker_create(int num, int type)
{
    worker_type* worker = (worker_type*) se_malloc(sizeof(worker_type));
    se_log_debug("create worker[%i]", num +1);
    worker->thread_num = num +1;
    worker->engineptr = NULL;
    worker->tasklist = NULL;
    worker->task = NULL;
    worker->need_to_exit = 0;
    worker->type = type;
    lock_basic_init(&worker->worker_lock);
    lock_basic_set(&worker->worker_alarm);

    lock_basic_lock(&worker->worker_lock);
    worker->sleeping = 0;
    worker->waiting = 0;
    lock_basic_unlock(&worker->worker_lock);
    return worker;
}


/**
 * Start worker.
 *
 */
void
worker_start(worker_type* worker)
{
    task_type* task;
    time_t now, timeout = 1;
    zone_type* zone = NULL;

    se_log_assert(worker);
    se_log_assert(worker->type == WORKER_WORKER);
    se_log_debug("start worker[%i]", worker->thread_num);

    while (worker->need_to_exit == 0) {
        se_log_debug("worker[%i]: report for duty", worker->thread_num);
        se_log_debug("worker[%i]: lock tasklist", worker->thread_num);
        lock_basic_lock(&worker->tasklist->tasklist_lock);
        se_log_debug("worker[%i]: locked tasklist", worker->thread_num);
        task = tasklist_pop_task(worker->tasklist);
        if (task) {
            se_log_debug("worker[%i] perform task for zone %s",
                worker->thread_num, task->who?task->who:"(null)");
            zone = task->zone;
            zone->in_progress = 1;

            se_log_debug("worker[%i]: unlock tasklist", worker->thread_num);
            lock_basic_unlock(&worker->tasklist->tasklist_lock);
            se_log_debug("worker[%i]: unlocked tasklist", worker->thread_num);

            worker->task = task;
            se_log_debug("worker[%i]: lock zone %s", worker->thread_num,
                task->who);
            lock_basic_lock(&zone->zone_lock);
            se_log_debug("worker[%i]: locked zone %s", worker->thread_num,
                task->who);
            worker_perform_task(worker, task);
            zone->processed = 1;
            se_log_debug("worker[%i]: unlock zone %s", worker->thread_num,
                task->who);
            lock_basic_unlock(&zone->zone_lock);
            se_log_debug("worker[%i]: unlocked zone %s", worker->thread_num,
                task->who);
            worker->task = NULL;

            if (task->what == TASK_NONE) {
                zone->in_progress = 0;
                se_log_debug("worker[%i]: cleanup task none for zone %s",
                    worker->thread_num, task->who);
                task_cleanup(task);
            } else {
                se_log_debug("worker[%i]: lock tasklist", worker->thread_num);
                lock_basic_lock(&worker->tasklist->tasklist_lock);
                se_log_debug("worker[%i]: locked tasklist", worker->thread_num);
                zone->in_progress = 0;
                task = tasklist_schedule_task(worker->tasklist, task, 1);
                if (!task) {
                    se_log_error("failed to schedule task");
                } else {
                    task_backup(task);
                }
                se_log_debug("worker[%i]: unlock tasklist", worker->thread_num);
                lock_basic_unlock(&worker->tasklist->tasklist_lock);
                se_log_debug("worker[%i]: unlocked tasklist", worker->thread_num);
            }

            timeout = 1;
        } else {
            se_log_debug("worker[%i] no task ready", worker->thread_num);
            task = tasklist_first_task(worker->tasklist);
            now = time_now();
            if (task && !worker->tasklist->loading) {
                timeout = (task->when - now);
            } else {
                timeout *= 2;
                if (timeout > ODS_SE_MAX_BACKOFF) {
                    timeout = ODS_SE_MAX_BACKOFF;
                }
            }
            se_log_debug("worker[%i]: unlock tasklist", worker->thread_num);
            lock_basic_unlock(&worker->tasklist->tasklist_lock);
            se_log_debug("worker[%i]: unlocked tasklist", worker->thread_num);

            worker_sleep(worker, timeout);
        }
    }
    return;
}


/**
 * Worker perform task.
 *
**/
void
worker_perform_task(worker_type* worker, task_type* task)
{
    zone_type* zone = NULL;
    engine_type* engine = (engine_type*) worker->engineptr;
    char* working_dir = NULL;
    char* cfg_filename = NULL;
    int error = 0;

    se_log_assert(worker);
    se_log_assert(task);

    if (!task->zone) {
        se_log_error("worker[%i] cannot perform task: no corresponding zone",
            worker->thread_num);
        return;
    }
    zone = task->zone;

    switch (task->what) {
        case TASK_NONE:
            se_log_warning("no task for zone %s", task->who?task->who:"(null)");
            break;
        case TASK_READ:
            if (tools_read_input(zone) != 0) {
                se_log_error("task [read zone %s] failed",
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
                se_log_error("task [add dnskeys to zone %s] failed",
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
                se_log_error("task [update zone %s] failed",
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
                se_log_error("task [nsecify zone %s] failed",
                    task->who?task->who:"(null)");
                goto task_perform_fail;
                break;
            }
            task->what = TASK_SIGN;
        case TASK_SIGN:
            if (tools_sign(zone) != 0) {
                se_log_error("task [sign zone %s] failed",
                    task->who?task->who:"(null)");
                goto task_perform_fail;
                break;
            }
            task->what = TASK_AUDIT;
        case TASK_AUDIT:
            working_dir = se_strdup(engine->config->working_dir);
            cfg_filename = se_strdup(engine->config->cfg_filename);
            error = tools_audit(zone, working_dir, cfg_filename);
            if (working_dir)  { se_free((void*)working_dir); }
            if (cfg_filename) { se_free((void*)cfg_filename); }
            working_dir = NULL;
            cfg_filename = NULL;
            if (error) {
                se_log_error("task [audit zone %s] failed",
                    task->who?task->who:"(null)");
                task->what = TASK_SIGN;
                goto task_perform_fail;
                break;
            }
            task->what = TASK_WRITE;
        case TASK_WRITE:
            if (tools_write_output(zone) != 0) {
                se_log_error("task [write zone %s] failed",
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
            se_log_warning("unknown task[id %i zone %s], "
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
         se_free((void*)worker);
    } else {
         se_log_warning("cleanup empty worker");
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
    se_log_assert(worker);
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
    se_log_assert(worker);
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
    se_log_assert(worker);
    se_log_assert(!worker->waiting);
    if (worker && worker->sleeping && !worker->waiting) {
        se_log_debug("wake up worker[%i]", worker->thread_num);
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
    se_log_assert(worker);
    se_log_assert(!worker->sleeping);
    if (worker && worker->waiting && !worker->sleeping) {
        se_log_debug("notify worker[%i]", worker->thread_num);
        lock_basic_lock(&worker->worker_lock);
        lock_basic_alarm(&worker->worker_alarm);
        worker->waiting = 0;
        lock_basic_unlock(&worker->worker_lock);
    }
    return;
}
