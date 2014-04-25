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
#include "scheduler/task.h"
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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Task schedule.
 */
typedef struct schedule_struct schedule_type;
struct schedule_struct {
    ldns_rbtree_t* tasks;
    pthread_mutex_t schedule_lock;
    pthread_cond_t schedule_cond;
};

/**
 * Create new schedule.
 * \param[in] allocator memory allocator
 * \return schedule_type* created schedule
 *
 */
schedule_type* schedule_create();

/**
 * Flush schedule.
 * \param[in] schedule schedule to be flushed
 */
void schedule_flush(schedule_type* schedule);

/**
 * purge schedule.
 * \param[in] schedule schedule to be purged
 */
void schedule_purge(schedule_type* schedule);

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
 * Schedule task from thread uses the schedule_lock from schedule to lock the 
 * schedule first before adding the task.
 * \param[in] schedule schedule
 * \param[in] task task
 * \param[in] log add entry in log for this
 * \return ods_status status
 *
 */
ods_status lock_and_schedule_task(schedule_type* schedule, task_type* task,
                                  int log);

/**
 * Pop the first scheduled task that is due.
 * \param[in] schedule schedule
 * \return task_type* popped task, or NULL when no task available or
 * no task due
 */
task_type* schedule_pop_task(schedule_type* schedule);

/**
 * Time of first task in schedule.
 * \param[in] schedule schedule
 * \return Time of first task, 0 if task->flush is set,
 * 		-1 if no task available
 */
time_t schedule_time_first(schedule_type* schedule);

/**
 * Number of task in schedule
 * \param[in] schedule schedule
 * \return task count, 0 on empty or error;
 */
size_t schedule_taskcount(schedule_type* schedule);

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

#ifdef __cplusplus
}
#endif

#endif /* SCHEDULER_SCHEDULE_H */
