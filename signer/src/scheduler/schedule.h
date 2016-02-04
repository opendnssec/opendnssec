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
 * Task scheduling.
 *
 */

#ifndef SCHEDULER_SCHEDULE_H
#define SCHEDULER_SCHEDULE_H

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

typedef struct schedule_struct schedule_type;

#include "scheduler/task.h"
#include "locks.h"
#include "status.h"
#include "task.h"

/**
 * Task schedule.
 */
struct schedule_struct {
    ldns_rbtree_t* tasks;
    int flushcount;
    int loading; /* to determine backoff */
    lock_basic_type schedule_lock;
};

/**
 * Create new schedule.
 * \param[in] allocator memory allocator
 * \return schedule_type* created schedule
 *
 */
schedule_type* schedule_create(void);

/**
 * Flush schedule.
 * \param[in] schedule schedule to be flushed
 * \param[in] override override task
 *
 */
void schedule_flush(schedule_type* schedule, task_id override);

/**
 * Look up task.
 * \param[in] schedule schedule
 * \param[in] task task
 * \return task_type* task, if found
 *
 */
task_type* schedule_lookup_task(schedule_type* schedule, task_type* task);

/**
 * Schedule task.
 * \param[in] schedule schedule
 * \param[in] task task
 * \param[in] log add entry in log for this
 * \return ods_status status
 *
 */
ods_status schedule_task(schedule_type* schedule, task_type* task, int log);

/**
 * Unschedule task.
 * \param[in] schedule schedule
 * \param[in] task task to delete
 * \return task_type* task, if it was scheduled
 *
 */
task_type* unschedule_task(schedule_type* schedule, task_type* task);

/**
 * Pop the first scheduled task.
 * \param[in] schedule schedule
 * \return task_type* popped task
 *
 */
task_type* schedule_pop_task(schedule_type* schedule);

/**
 * Get the first scheduled task.
 * \param[in] schedule schedule
 * \return task_type* first scheduled task
 *
 */
task_type* schedule_get_first_task(schedule_type* schedule);

/**
 * Print schedule.
 * \param[in] out file descriptor
 * \param[in] schedule schedule
 *
 */
void schedule_print(FILE* out, schedule_type* schedule);

/**
 * Clean up schedule.
 * \param[in] schedule schedule to be cleaned up
 *
 */
void schedule_cleanup(schedule_type* schedule);

#endif /* SCHEDULER_SCHEDULE_H */
