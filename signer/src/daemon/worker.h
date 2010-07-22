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

#ifndef DAEMON_WORKER_H
#define DAEMON_WORKER_H

#include "scheduler/task.h"
#include "scheduler/locks.h"
#include "signer/zone.h"

#include <time.h>

#define WORKER_WORKER 1

struct engine_struct;

typedef struct worker_struct worker_type;
struct worker_struct {
    int thread_num;
    se_thread_type thread_id;
    tasklist_type* tasklist;
    struct engine_struct* engineptr;
    int type;
    int sleeping;
    int waiting;
    int need_to_exit;
    cond_basic_type worker_alarm;
    lock_basic_type worker_lock;
};

/**
 * Create worker.
 * \param[in] num thread number
 * \param[in] type type of worker
 * \return worker_type* created worker
 *
 */
worker_type* worker_create(int num, int type);

/**
 * Start worker.
 * \param[in] worker worker to start
 *
 */
void worker_start(worker_type* worker);

/**
 * Worker perform task.
 * \param[in] worker worker that picked up the task
 * \param[in] task task to be performed
 *
 */
void worker_perform_task(worker_type* worker, task_type* task);

/**
 * Clean up worker.
 * \param[in] worker clean up this worker
 *
 */
void worker_cleanup(worker_type* worker);

/**
 * Put worker to sleep.
 * \param[in] worker put this worker to sleep
 * \param[in] timeout time before alarm clock is going off,
 *            0 means no alarm clock is set.
 *
 */
void worker_sleep(worker_type* worker, time_t timeout);

/**
 * Let worker wait.
 * \param[in] worker waiting worker
 *
 */
void worker_wait(worker_type* worker);

/**
 * Wake up worker.
 * \param[in] worker wake up this worker
 *
 */
void worker_wakeup(worker_type* worker);

/**
 * Notify worker.
 * \param[in] worker notify this worker
 *
 */
void worker_notify(worker_type* worker);

#endif /* DAEMON_WORKER_H */
