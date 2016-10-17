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
//~ #include "duration.h"

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
    worker->need_to_exit = 0;
    worker->dbconn = NULL;
    return worker;
}

/**
 * Work.
 *
 */
void
worker_start(worker_type* worker)
{
    ods_log_assert(worker);
    task_type *task;

    while (worker->need_to_exit == 0) {
        ods_log_debug("[worker[%i]]: report for duty", worker->thread_num);

        /* When no task available this call blocks and waits for event.
         * Then it will return NULL; */
        task = schedule_pop_task(worker->engine->taskq);
        if (task) {
            ods_log_debug("[worker[%i]] start working", worker->thread_num);
            task_perform(worker->engine->taskq, task, worker->dbconn);
            ods_log_debug("[worker[%i]] finished working", worker->thread_num);
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
    //What about its db connection?
    free(worker);
}
