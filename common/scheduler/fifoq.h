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

struct fifoq_struct;
typedef struct fifoq_struct* fifoq_type;
struct fifoq_item {
    void* rrset;
    time_t jitter;
    struct worker_context* superior;
};

#include "scheduler/schedule.h"
#include "worker.h"
#include "locks.h"
#include "status.h"

/**
 * Create new FIFO queue.
 * \param[in] allocator memory allocator
 * \return fifoq_type* created queue
 *
 */
extern fifoq_type fifoq_create(void);

/**
 * Pop item from queue.
 * \param[in] q queue
 * \param[out] worker worker that owns the item
 * \return void* popped item
 *
 */
extern void fifoq_pop(fifoq_type fifoq, struct fifoq_item* items, int* count);

/**
 * Push item to queue.
 * \param[in] q queue
 * \param[in] item item
 * \param[in] worker owner of item
 * \param[out] tries number of tries
 * \return ods_status status
 *
 */
extern int fifoq_push(fifoq_type fifoq, struct fifoq_item qs);

/**
 * Clean up queue.
 * \param[in] q queue to be cleaned up
 *
 */
extern void fifoq_cleanup(fifoq_type q);

extern void fifoq_report(fifoq_type q, worker_type* superior, ods_status subtaskstatus);
extern void fifoq_waitfor(fifoq_type q, worker_type* worker, long nsubtasks, long* nsubtasksfailed);
extern void fifoq_notifyall(fifoq_type q);
extern void fifoq_terminate(fifoq_type q);

#endif /* SCHEDULER_FIFOQ_H */
