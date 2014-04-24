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
#include "shared/hsm.h"
#include "shared/duration.h"

#include <time.h> /* time() */

/**
 * Create worker.
 *
 */
worker_type*
worker_create(allocator_type* allocator, int num)
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
    worker->allocator = allocator;
    worker->thread_num = num +1;
    worker->engine = NULL;
    worker->task = NULL;
    worker->need_to_exit = 0;
    worker->clock_in = 0;
    worker->jobs_appointed = 0;
    worker->jobs_completed = 0;
    worker->jobs_failed = 0;
    worker->sleeping = 0;
    worker->waiting = 0;
    worker->dbconn = NULL;
    lock_basic_init(&worker->worker_lock);
    lock_basic_set(&worker->worker_alarm);
    return worker;
}

/**
 * Has this worker measured up to all appointed jobs?
 *
 */
static int
worker_fulfilled(worker_type* worker)
{
    return (worker->jobs_completed + worker->jobs_failed) ==
        worker->jobs_appointed;
}

/**
 * Perform task.
 *
 */
static void
worker_perform_task(worker_type* worker)
{
    task_type* task = NULL;

    if (!worker || !worker->task || !worker->task->context || !worker->engine) {
        return;
    }
    ods_log_assert(worker);
    ods_log_assert(worker->task);
    ods_log_assert(worker->task->context);

    task = (task_type*) worker->task;
    ods_log_debug("[worker[%i]]: perform task [%s] for %s at %u",
       worker->thread_num, task_what2str(task->what),
       task_who2str(task->who), (uint32_t) worker->clock_in);

	task->dbconn = worker->dbconn;
	worker->task = task_perform(task);
	task->dbconn = NULL;
}


/**
 * Work.
 *
 */
void
worker_start(worker_type* worker)
{
    time_t now, timeout = 1;
    task_type *task_that_was_worked_on;

    ods_log_assert(worker);

    while (worker->need_to_exit == 0) {
        ods_log_debug("[worker[%i]]: report for duty", worker->thread_num);

        lock_basic_lock(&worker->engine->taskq->schedule_lock);
        /* [LOCK] schedule */

        worker->task = schedule_pop_task(worker->engine->taskq);
        if (worker->task) {

            /* [UNLOCK] schedule */
            lock_basic_unlock(&worker->engine->taskq->schedule_lock);

            ods_log_debug("[worker[%i]] start working", worker->thread_num);

            worker->clock_in = time(NULL);
            worker_perform_task(worker);

            task_that_was_worked_on = worker->task;
            worker->task = NULL;
            
            ods_log_debug("[worker[%i]] finished working", worker->thread_num);
            
            if (task_that_was_worked_on)
                (void) lock_and_schedule_task(worker->engine->taskq,
                                                 task_that_was_worked_on, 1);
            
            timeout = 1;
        } else {
            ods_log_debug("[worker[%i]] nothing to do", worker->thread_num);

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
 * Put worker to sleep.
 *
 */
void
worker_sleep(worker_type* worker, time_t timeout)
{
    ods_log_assert(worker);
    lock_basic_lock(&worker->worker_lock);
    /* [LOCK] worker */
    /** need_to_exit may be set after check in worker start
     * and alarm might be fired before worker_lock. This check
     * prevents possible deadlock */
    if (!worker->need_to_exit) {
        worker->sleeping = 1;
        lock_basic_sleep(&worker->worker_alarm, &worker->worker_lock,
            timeout);
    }
    /* [UNLOCK] worker */
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
    if (worker && worker->sleeping && !worker->waiting) {
        ods_log_debug("[worker[%i]] wake up", worker->thread_num);
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
 * Worker waiting.
 *
 */
void
worker_wait(lock_basic_type* lock, cond_basic_type* condition)
{
    lock_basic_lock(lock);
    /* [LOCK] worker */
    lock_basic_sleep(condition, lock, 0);
    /* [UNLOCK] worker */
    lock_basic_unlock(lock);
    return;
}


/**
 * Notify a worker.
 *
 */
void
worker_notify(lock_basic_type* lock, cond_basic_type* condition)
{
    lock_basic_lock(lock);
    /* [LOCK] lock */
    lock_basic_alarm(condition);
    /* [UNLOCK] lock */
    lock_basic_unlock(lock);
    return;
}


/**
 * Notify all workers.
 *
 */
void
worker_notify_all(lock_basic_type* lock, cond_basic_type* condition)
{
    lock_basic_lock(lock);
    /* [LOCK] lock */
    lock_basic_broadcast(condition);
    /* [UNLOCK] lock */
    lock_basic_unlock(lock);
    return;
}


/**
 * Clean up worker.
 *
 */
void
worker_cleanup(worker_type* worker)
{
    allocator_type* allocator;
    cond_basic_type worker_cond;
    lock_basic_type worker_lock;

    if (!worker) {
        return;
    }
    allocator = worker->allocator;
    worker_cond = worker->worker_alarm;
    worker_lock = worker->worker_lock;

    allocator_deallocate(allocator, (void*) worker);
    lock_basic_destroy(&worker_lock);
    lock_basic_off(&worker_cond);
    return;
}
