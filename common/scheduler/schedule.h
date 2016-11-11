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
#include <ldns/ldns.h>
#include <pthread.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

typedef struct schedule_struct schedule_type;

#include "fifoq.h"
#include "scheduler/task.h"
#include "locks.h"
#include "status.h"
#include "task.h"

struct schedule_struct {
    /* Contains all tasks sorted by due_date so we can quickly find
     * the first task. */
    ldns_rbtree_t* tasks;
    /* Contains all tasks in tasks tree but here sorted by ttuple. */
    ldns_rbtree_t* tasks_by_name;
    /* For every ttuple contains a task structure with an unique lock */
    ldns_rbtree_t* locks_by_name;
    fifoq_type* signq;
    pthread_cond_t schedule_cond;
    pthread_mutex_t schedule_lock;
    /* For testing. So we can verify al workers are waiting and nothing
     * is to be done. Used by enforcer_idle. */
    int num_waiting;
};

/**
 * Create new schedule.
 * \param[in] allocator memory allocator
 * \return schedule_type* created schedule
 */
schedule_type* schedule_create(void);

/**
 * Clean up schedule.
 * \param[in] schedule schedule to be cleaned up
 *
 */
void schedule_cleanup(schedule_type* schedule);

/**
 * purge schedule. All tasks will be thrashed.
 * \param[in] schedule schedule to be purged
 */
void schedule_purge(schedule_type* schedule);

/**
 * Delete and free all tasks from the queue associated with owner for a
 * specific class
 */
void schedule_purge_owner(schedule_type* schedule, char const *class,
    char const *owner);

/**
 * Schedule task. Task is now owned by scheduler and should must no
 * longer be accessed. If a task with the same identifier is scheduled
 * it is updated with this tasks' context and due_time is the minimum
 * of both tasks.
 * On return ERROR caller is responsible for freeing task.
 * 
 * \param[in] schedule schedule
 * \param[in] task task
 * \param[in] log add entry in log for this
 * \return ods_status status
 *
 */
ods_status schedule_task(schedule_type* schedule, task_type* task, int replace, int log);

/**
 * Unschedule task.
 * \param[in] schedule schedule
 * \param[in] task task to delete
 * \return task_type* task, if it was scheduled
 *
 */
task_type* schedule_unschedule(schedule_type* schedule, task_type* task);

/**
 * Pop the first scheduled task that is due. If an item is directly
 * available it will be returned. Else the call will block and return
 * NULL when the caller is awoken. 
 *
 * \param[in] schedule schedule
 * \return task_type* popped task, or NULL when no task available or
 * no task due
 */
task_type* schedule_pop_task(schedule_type* schedule);

/**
 * Pop the first scheduled task. regardless of its due time.
 * Used for timeleap.
 *
 * \param[in] schedule schedule
 * \return task_type* popped task, or NULL when no task available or
 * no task available
 */
task_type* schedule_pop_first_task(schedule_type* schedule);

void sched_flush(schedule_type* schedule, task_id override);

/**
 * Flush schedule for a specific type of task.
 * \param[in] schedule schedule to be flushed
 * \return number of tasks flushed
 */
int schedule_flush_type(schedule_type* schedule, char const *class, char const *type);

int schedule_info(schedule_type* schedule, time_t* firstFireTime, int* idleWorkers, int* taskCount);

/**
 * Wake up all threads waiting for tasks. Useful to on program teardown.
 */
void schedule_release_all(schedule_type* schedule);

void sched_task_destroy(schedule_type* sched, task_type* task);
time_t sched_task_due(task_type* task);
int sched_task_istype(task_type* task, task_id type);
char* sched_describetask(task_type* task);
time_t task_execute(task_type* task, void* context);
void task_perform(schedule_type* sched, task_type* task, void* context);

#endif /* SCHEDULER_SCHEDULE_H */
