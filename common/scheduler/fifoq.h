/*
 * Copyright (c) 2011-2018 NLNet Labs.
 * All rights reserved.
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
 */

/**
 * FIFO Queue.
 *
 */

#ifndef SCHEDULER_FIFOQ_H
#define SCHEDULER_FIFOQ_H

#include "config.h"
#include <stdio.h>
#include <time.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <ldns/ldns.h>

typedef struct fifoq_struct fifoq_type;

#include "scheduler/schedule.h"
#include "worker.h"
#include "locks.h"
#include "status.h"

#define FIFOQ_MAX_COUNT 1000
#define FIFOQ_TRIES_COUNT 10

/**
 * FIFO Queue.
 */
struct fifoq_struct {
    void* blob[FIFOQ_MAX_COUNT];
    void* owner[FIFOQ_MAX_COUNT];
    size_t count;
    pthread_mutex_t q_lock;
    pthread_cond_t q_threshold;
    pthread_cond_t q_nonfull;
};

/**
 * Create new FIFO queue.
 * \param[in] allocator memory allocator
 * \return fifoq_type* created queue
 *
 */
fifoq_type* fifoq_create(void);

/**
 * Wipe queue.
 * \param[in] q queue to be wiped
 *
 */
void fifoq_wipe(fifoq_type* q);

/**
 * Pop item from queue.
 * \param[in] q queue
 * \param[out] worker worker that owns the item
 * \return void* popped item
 *
 */
void* fifoq_pop(fifoq_type* q, void** worker);

/**
 * Push item to queue.
 * \param[in] q queue
 * \param[in] item item
 * \param[in] worker owner of item
 * \param[out] tries number of tries
 * \return ods_status status
 *
 */
ods_status fifoq_push(fifoq_type* q, void* item, void* worker, int* tries);

/**
 * Clean up queue.
 * \param[in] q queue to be cleaned up
 *
 */
void fifoq_cleanup(fifoq_type* q);

void fifoq_report(fifoq_type* q, worker_type* superior, ods_status subtaskstatus);
void fifoq_waitfor(fifoq_type* q, worker_type* worker, long nsubtasks, long* nsubtasksfailed);
void fifoq_notifyall(fifoq_type* q);

#endif /* SCHEDULER_FIFOQ_H */
