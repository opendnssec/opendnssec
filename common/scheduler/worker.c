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

#include "scheduler/schedule.h"
#include "scheduler/worker.h"
#include "scheduler/task.h"
#include "log.h"
#include "status.h"
#include "util.h"

/**
 * Create worker.
 *
 */
worker_type*
worker_create(char* name, schedule_type* taskq)
{
    worker_type* worker;
    CHECKALLOC(worker = (worker_type*) malloc(sizeof(worker_type)));
    worker->name = name;
    worker->need_to_exit = 0;
    worker->context = NULL;
    worker->taskq = taskq;
    worker->tasksOutstanding = 0;
    worker->tasksFailed = 0;
    pthread_cond_init(&worker->tasksBlocker, NULL);
    return worker;
}

/**
 * Work.
 *
 */
void
worker_start(worker_type* worker)
{
    task_type *task;
    ods_log_assert(worker);

    while (worker->need_to_exit == 0) {
        ods_log_debug("[%s]: report for duty", worker->name);

        /* When no task available this call blocks and waits for event.
         * Then it will return NULL; */
        task = schedule_pop_task(worker->taskq);
        if (task) {
            ods_log_debug("[%s] start working", worker->name);
            task_perform(worker->taskq, task, worker->context);
            ods_log_debug("[%s] finished working", worker->name);
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
    free(worker->name);
    free(worker);
}
