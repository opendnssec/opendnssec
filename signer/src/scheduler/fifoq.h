/*
 * $Id$
 *
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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
 * FIFO Queue.
 *
 */

#ifndef SCHEDULER_FIFOQ_H
#define SCHEDULER_FIFOQ_H

#include "config.h"
#include "daemon/worker.h"
#include "shared/allocator.h"
#include "shared/locks.h"
#include "shared/status.h"

#include <stdio.h>
#include <time.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <ldns/ldns.h>

#define FIFOQ_MAX_COUNT 1000

/**
 * FIFO Queue.
 */
typedef struct fifoq_struct fifoq_type;
struct fifoq_struct {
    void* blob[FIFOQ_MAX_COUNT];
    worker_type* owner[FIFOQ_MAX_COUNT];
    size_t count;
    lock_basic_type q_lock;
    cond_basic_type q_threshold;
};

/**
 * Create new FIFO queue.
 * \param[in] allocator memory allocator
 * \return fifoq_type* created queue
 *
 */
fifoq_type* fifoq_create(allocator_type* allocator);

/**
 * Wipe queue.
 * \param[in] q queue to be wiped
 * \param[out] worker worker that owns the item
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
void* fifoq_pop(fifoq_type* q, worker_type** worker);

/**
 * Push item to queue.
 * \param[in] q queue
 * \param[in] item item
 * \param[in] worker owner of item
 * \return ods_status status
 *
 */
ods_status fifoq_push(fifoq_type* q, void* item, worker_type* worker);

/**
 * Clean up queue.
 * \param[in] q queue to be cleaned up
 *
 */
void fifoq_cleanup(fifoq_type* q);

#endif /* SCHEDULER_FIFOQ_H */
