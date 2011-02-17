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
#include "shared/status.h"
#include "shared/util.h"
#include "signer/tools.h"
#include "signer/zone.h"

#include <time.h> /* time() */

ods_lookup_table worker_str[] = {
    { WORKER_WORKER, "worker" },
    { WORKER_DRUDGER, "drudger" },
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
 * Perform task.
 *
 */
static void
worker_perform_task(worker_type* worker)
{
    engine_type* engine = NULL;
    zone_type* zone = NULL;
    task_type* task = NULL;
    task_id what = TASK_NONE;
    time_t when = 0;
    time_t never = (3600*24*365);
    ods_status status = ODS_STATUS_OK;
    int fallthrough = 0;
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
    ods_log_debug("[%s[%i]]: perform task %s for zone %s at %u",
       worker2str(worker->type), worker->thread_num, task_what2str(task->what),
       task_who2str(task->who), (uint32_t) time(NULL));

    switch (task->what) {
        case TASK_SIGNCONF:
            /* perform 'load signconf' task */
            ods_log_verbose("[%s[%i]]: load signconf for zone %s",
                worker2str(worker->type), worker->thread_num,
                task_who2str(task->who));
            status = zone_load_signconf(zone, &what);

            /* what to do next */
            when = time_now();
            if (status == ODS_STATUS_UNCHANGED) {
                goto task_perform_continue;
            } else if (status != ODS_STATUS_OK) {
                if (task->halted == TASK_NONE) {
                    goto task_perform_fail;
                }
                goto task_perform_continue;
            } else {
                task->interrupt = TASK_NONE;
                task->halted = TASK_NONE;
                zone->prepared = 0;
            }
            fallthrough = 0;
            break;
        case TASK_READ:
            /* perform 'read input adapter' task */
            ods_log_verbose("[%s[%i]]: read zone %s",
                worker2str(worker->type), worker->thread_num,
                task_who2str(task->who));

            if (!zone->prepared) {
                status = zone_publish_dnskeys(zone);
                if (status == ODS_STATUS_OK) {
                    status = zone_prepare_nsec3(zone);
                }
                if (status == ODS_STATUS_OK) {
                    zone->prepared = 1;
                }
            }

            if (zone->prepared) {
                status = tools_input(zone);
            } else {
                status = ODS_STATUS_ERR;
            }

            /* what to do next */
            what = TASK_NSECIFY;
            when = time_now();
            if (status != ODS_STATUS_OK) {
                if (task->halted == TASK_NONE) {
                    goto task_perform_fail;
                }
                goto task_perform_continue;
            }
            fallthrough = 1;
        case TASK_NSECIFY:
            ods_log_verbose("[%s[%i]]: nsecify zone %s",
                worker2str(worker->type), worker->thread_num,
                task_who2str(task->who));
            status = tools_nsecify(zone);

            /* what to do next */
            what = TASK_SIGN;
            when = time_now();
            if (status != ODS_STATUS_OK) {
                if (task->halted == TASK_NONE) {
                    goto task_perform_fail;
                }
                goto task_perform_continue;
            }
            fallthrough = 1;
        case TASK_SIGN:
            ods_log_verbose("[%s[%i]]: sign zone %s",
                worker2str(worker->type), worker->thread_num,
                task_who2str(task->who));
            error = tools_sign(zone);

            /* what to do next */
            if (error) {
                if (task->halted == TASK_NONE) {
                    goto task_perform_fail;
                }
                goto task_perform_continue;
            } else {
                task->interrupt = TASK_NONE;
                task->halted = TASK_NONE;
            }
            what = TASK_AUDIT;
            when = time_now();
            fallthrough = 1;
        case TASK_AUDIT:
            if (zone->signconf->audit) {
                ods_log_verbose("[%s[%i]]: audit zone %s",
                    worker2str(worker->type), worker->thread_num,
                    task_who2str(task->who));
                working_dir = strdup(engine->config->working_dir);
                cfg_filename = strdup(engine->config->cfg_filename);
                status = tools_audit(zone, working_dir, cfg_filename);
                if (working_dir)  { free((void*)working_dir); }
                if (cfg_filename) { free((void*)cfg_filename); }
                working_dir = NULL;
                cfg_filename = NULL;
            } else {
                status = ODS_STATUS_OK;
            }

            /* what to do next */
            if (status != ODS_STATUS_OK) {
                if (task->halted == TASK_NONE) {
                    goto task_perform_fail;
                }
                goto task_perform_continue;
            }
            what = TASK_WRITE;
            when = time_now();
            fallthrough = 1;
        case TASK_WRITE:
            ods_log_verbose("[%s[%i]]: write zone %s",
                worker2str(worker->type), worker->thread_num,
                task_who2str(task->who));

            status = tools_output(zone);
            zone->processed = 1;

            /* what to do next */
            if (status != ODS_STATUS_OK) {
                if (task->halted == TASK_NONE) {
                    goto task_perform_fail;
                }
                goto task_perform_continue;
            } else {
                task->interrupt = TASK_NONE;
                task->halted = TASK_NONE;
            }
            what = TASK_SIGN;
            when = time_now() +
                duration2time(zone->signconf->sig_resign_interval);
            fallthrough = 0;
            break;
        case TASK_NONE:
            ods_log_warning("[%s[%i]]: none task for zone %s",
                worker2str(worker->type), worker->thread_num,
                task_who2str(task->who));
            when = time_now() + never;
            fallthrough = 0;
            break;
        default:
            ods_log_warning("[%s[%i]]: unknown task, trying full sign zone %s",
                worker2str(worker->type), worker->thread_num,
                task_who2str(task->who));
            what = TASK_SIGNCONF;
            when = time_now();
            fallthrough = 0;
            break;
    }

    /* no error, reset backoff */
    task->backoff = 0;

    /* set next task */
    if (fallthrough == 0 && task->interrupt != TASK_NONE &&
        task->interrupt != what) {
        ods_log_debug("[%s[%i]]: interrupt task %s for zone %s",
            worker2str(worker->type), worker->thread_num,
            task_what2str(what), task_who2str(task->who));

        task->what = task->interrupt;
        task->when = time_now();
        task->halted = what;
    } else {
        ods_log_debug("[%s[%i]]: next task %s for zone %s",
            worker2str(worker->type), worker->thread_num,
            task_what2str(what), task_who2str(task->who));

        task->what = what;
        task->when = when;
        if (!fallthrough) {
            task->interrupt = TASK_NONE;
            task->halted = TASK_NONE;
        }
    }
    return;

task_perform_fail:
    if (task->backoff) {
        task->backoff *= 2;
        if (task->backoff > ODS_SE_MAX_BACKOFF) {
            task->backoff = ODS_SE_MAX_BACKOFF;
        }
    } else {
        task->backoff = 60;
    }
    ods_log_error("[%s[%i]]: backoff task %s for zone %s with %u seconds",
        worker2str(worker->type), worker->thread_num,
        task_what2str(task->what), task_who2str(task->who), task->backoff);

    task->when = time_now() + task->backoff;
    return;

task_perform_continue:
    ods_log_info("[%s[%i]]: continue task %s for zone %s",
        worker2str(worker->type), worker->thread_num,
        task_what2str(task->halted), task_who2str(task->who));

    what = task->halted;
    task->what = what;
    task->when = time_now();
    task->interrupt = TASK_NONE;
    task->halted = TASK_NONE;
    if (zone->processed) {
        task->when += duration2time(zone->signconf->sig_resign_interval);
    }
    return;
}


/**
 * Work.
 *
 */
static void
worker_work(worker_type* worker)
{
    time_t now, timeout = 1;
    zone_type* zone = NULL;
    ods_status status = ODS_STATUS_OK;

    ods_log_assert(worker);
    ods_log_assert(worker->type == WORKER_WORKER);

    while (worker->need_to_exit == 0) {
        ods_log_debug("[%s[%i]]: report for duty", worker2str(worker->type),
            worker->thread_num);
        lock_basic_lock(&worker->engine->taskq->schedule_lock);
        /* [LOCK] schedule */
        worker->task = schedule_pop_task(worker->engine->taskq);
        /* [UNLOCK] schedule */
        if (worker->task) {
            lock_basic_unlock(&worker->engine->taskq->schedule_lock);

            zone = worker->task->zone;
            lock_basic_lock(&zone->zone_lock);
            /* [LOCK] zone */
            ods_log_debug("[%s[%i]] start working on zone %s",
                worker2str(worker->type), worker->thread_num, zone->name);

            worker_perform_task(worker);

            zone->task = worker->task;
            worker->task = NULL;
            zone->processed = 1;

            ods_log_debug("[%s[%i]] finished working on zone %s",
                worker2str(worker->type), worker->thread_num, zone->name);
            /* [UNLOCK] zone */

            lock_basic_lock(&worker->engine->taskq->schedule_lock);
            /* [LOCK] zone, schedule */
            status = schedule_task(worker->engine->taskq, zone->task, 1);
            /* [UNLOCK] zone, schedule */
            lock_basic_unlock(&worker->engine->taskq->schedule_lock);
            lock_basic_unlock(&zone->zone_lock);

            timeout = 1;
        } else {
            ods_log_debug("[%s[%i]] nothing to do", worker2str(worker->type),
                worker->thread_num);

            /* [LOCK] schedule */
            worker->task = schedule_get_first_task(worker->engine->taskq);
            /* [UNLOCK] schedule */
            lock_basic_unlock(&worker->engine->taskq->schedule_lock);

            now = time_now();
            if (worker->task && !worker->engine->taskq->loading) {
                timeout = (worker->task->when - now);
            } else {
                timeout *= 2;
                if (timeout > ODS_SE_MAX_BACKOFF) {
                    timeout = ODS_SE_MAX_BACKOFF;
                }
            }
            worker->task = NULL;
            worker_sleep(worker, timeout);
        }
    }
    return;
}


/**
 * Drudge.
 *
 */
static void
worker_drudge(worker_type* worker)
{
    rrset_type* rrset = NULL;

    ods_log_assert(worker);
    ods_log_assert(worker->type == WORKER_DRUDGER);

    while (worker->need_to_exit == 0) {
        ods_log_debug("[%s[%i]] report for duty", worker2str(worker->type),
            worker->thread_num);

        if (rrset) {
            rrset = NULL;
        } else {
            ods_log_debug("[%s[%i]] nothing to do", worker2str(worker->type),
                worker->thread_num);

            lock_basic_lock(&worker->engine->signq->q_lock);
            lock_basic_sleep(&worker->engine->signq->q_threshold,
                &worker->engine->signq->q_lock, 0);
            lock_basic_unlock(&worker->engine->signq->q_lock);
        }
    }
    return;
}


/**
 * Start worker.
 *
 */
void
worker_start(worker_type* worker)
{
    ods_log_assert(worker);
    switch (worker->type) {
        case WORKER_DRUDGER:
            worker_drudge(worker);
            break;
        case WORKER_WORKER:
            worker_work(worker);
            break;
        default:
            ods_log_error("[worker] illegal worker (id=%i)", worker->type);
            return;
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
    if (!worker) {
        return;
    }
    lock_basic_destroy(&worker->worker_lock);
    lock_basic_off(&worker->worker_alarm);
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
    /* [LOCK] worker */
    worker->sleeping = 1;
    lock_basic_sleep(&worker->worker_alarm, &worker->worker_lock,
        timeout);
    /* [UNLOCK] worker */
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
        /* [LOCK] worker */
        lock_basic_alarm(&worker->worker_alarm);
        worker->sleeping = 0;
        /* [UNLOCK] worker */
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
