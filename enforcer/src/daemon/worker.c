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
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "log.h"
#include "status.h"
#include "util.h"
#include "duration.h"

/**
 * Create worker.
 *
 */
worker_type*
worker_create(int num)
{
    worker_type* worker;

    worker = (worker_type*) malloc( sizeof(worker_type) );
    if (!worker) {
        return NULL;
    }

    ods_log_debug("create worker[%i]", num +1);
    worker->thread_num = num +1;
    worker->engine = NULL;
    worker->task = NULL;
    worker->need_to_exit = 0;
    worker->jobs_appointed = 0;
    worker->jobs_completed = 0;
    worker->jobs_failed = 0;
    worker->sleeping = 0;
    worker->waiting = 0;
    worker->dbconn = NULL;
    return worker;
}

/**
 * Perform task.
 *
 */
static void
worker_perform_task(worker_type* worker)
{
    task_type* task;

    if (!worker || !worker->task || !worker->task->context || !worker->engine) {
        return;
    }

    task = (task_type*) worker->task;
    ods_log_debug("[worker[%i]]: perform task [%s] for %s",
       worker->thread_num, task_what2str(task->what),
       task_who2str(task->who));

    /* We temporarily assign the database connection to the task so
     * it is accessable from the task function */
    task->dbconn = worker->dbconn;
    worker->task = task_perform(task);
    if (worker->task) task->dbconn = NULL;
}

/**
 * Work.
 *
 */
void
worker_start(worker_type* worker)
{
    ods_log_assert(worker);

    while (worker->need_to_exit == 0) {
        ods_log_debug("[worker[%i]]: report for duty", worker->thread_num);

        /* When no task available this call blocks and waits for event.
         * Then it will return NULL; */
        worker->task = schedule_pop_task(worker->engine->taskq);
        if (worker->task) {
            ods_log_debug("[worker[%i]] start working", worker->thread_num);
            worker_perform_task(worker);
            ods_log_debug("[worker[%i]] finished working", worker->thread_num);
            if (worker->task) {
                if (schedule_task(worker->engine->taskq, worker->task) !=
                    ODS_STATUS_OK)
                {
                    ods_log_error("[worker[%i]] unable to schedule task",
                        worker->thread_num);
                }
                worker->task = NULL;
            }
        }
    }
}

/**
 * Clean up worker.
 *
 */
void
worker_cleanup(worker_type* worker)
{
    if (!worker) return;
    free(worker);
}
