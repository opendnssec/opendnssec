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

#ifndef DAEMON_WORKER_H
#define DAEMON_WORKER_H

#include "config.h"
#include <time.h>

enum worker_enum {
    WORKER_NONE = 0,
    WORKER_WORKER = 1,
    WORKER_DRUDGER
};
typedef enum worker_enum worker_id;

typedef struct worker_struct worker_type;

#include "scheduler/task.h"
#include "status.h"
#include "locks.h"

struct worker_struct {
    int thread_num;
    ods_thread_type thread_id;
    engine_type* engine;
    task_type* task;
    task_id working_with;
    worker_id type;
    time_t clock_in;
    size_t jobs_appointed;
    size_t jobs_completed;
    size_t jobs_failed;
    cond_basic_type worker_alarm;
    lock_basic_type worker_lock;
    unsigned sleeping : 1;
    unsigned waiting : 1;
    unsigned need_to_exit : 1;
};

/**
 * Create worker.
 * \param[in] allocator memory allocator
 * \param[in] num thread number
 * \param[in] type type of worker
 * \return worker_type* created worker
 *
 */
worker_type* worker_create(int num, worker_id type);

/**
 * Start working.
 * \param[in] worker worker to start working
 *
 */
void worker_start(worker_type* worker);

/**
 * Put worker to sleep.
 * \param[in] worker put this worker to sleep
 * \param[in] timeout time before alarm clock is going off,
 *            0 means no alarm clock is set.
 *
 */
void worker_sleep(worker_type* worker, time_t timeout);

/**
 * Put worker to sleep unless the worker has measured up to all
 * appointed jobs.
 * \param[in] worker put this worker to sleep
 * \param[in] timeout time before alarm clock is going off,
 *            0 means no alarm clock is set.
 *
 */
void worker_sleep_unless(worker_type* worker, time_t timeout);

/**
 * Wake up worker.
 * \param[in] worker wake up this worker
 *
 */
void worker_wakeup(worker_type* worker);

/**
 * Notify all workers.
 * \param[in] lock lock to use
 * \param[in] condition condition that has been met
 *
 */
void worker_notify_all(lock_basic_type* lock, cond_basic_type* condition);

/**
 * Clean up worker.
 * \param[in] worker worker to clean up
 *
 */
void worker_cleanup(worker_type* worker);

#endif /* DAEMON_WORKER_H */
