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
 * Tasks.
 *
 */

#ifndef SCHEDULER_TASK_H
#define SCHEDULER_TASK_H

#include "config.h"
#include "scheduler/locks.h"

#include <ldns/ldns.h>
#include <stdio.h>
#include <time.h>

struct zone_struct;

enum task_id_enum {
    TASK_NONE = 0,
    TASK_READ,
    TASK_ADDKEYS,
    TASK_UPDATE,
    TASK_NSECIFY,
    TASK_SIGN,
    TASK_AUDIT,
    TASK_WRITE
};
typedef enum task_id_enum task_id;

/**
 * Task.
 */
typedef struct task_struct task_type;
struct task_struct {
    task_id what;
    time_t when;
    time_t backoff;
    const char* who;
    ldns_rdf* dname;
    struct zone_struct* zone;
    int flush;
};

/**
 * Task list.
 */
typedef struct tasklist_struct tasklist_type;
struct tasklist_struct {
    ldns_rbtree_t* tasks;
    int loading;
    lock_basic_type tasklist_lock;
};

/**
 * Create a new task.
 * \param[in] what task identifier
 * \param[in] when scheduled time
 * \param[in] who zone name
 * \param[in] zone pointer to zone structure
 * \return task_type* created task
 *
 */
task_type* task_create(int what, time_t when, const char* who,
    struct zone_struct* zone);

/**
 * Clean up task.
 * \param[in] task task
 *
 */
void task_cleanup(task_type* task);

/**
 * Compare tasks.
 * \param[in] a one task
 * \param[in] b another task
 * \return int -1, 0 or 1
 *
 */
int task_compare(const void* a, const void* b);

/**
 * Convert task to string.
 * \param[in] task task
 * \param[out] buffer to store string-based task in
 * \return string-based task
 *
 */
char* task2str(task_type* task, char* buftask);

/**
 * Print task.
 * \param[in] out file descriptor
 * \param[in] task task
 *
 */
void task_print(FILE* out, task_type* task);

/**
 * New task list.
 *  number of possible tasks
 * \return tasklist_type* created tasklist
 *
 */
tasklist_type* tasklist_create(void);

/**
 * Clean up task list.
 * \param list[in] tasklist to be cleaned up
 *
 */
void tasklist_cleanup(tasklist_type* list);

/**
 * Flush task list.
 * \param list[in] tasklist to be flushed
 *
 */
void tasklist_flush(tasklist_type* list);

/**
 * Schedule a task.
 * \param[in] list task list
 * \param[in] task task to schedule
 * \param[in] log log new task
 * \return task_type* scheduled task
 *
 */
task_type* tasklist_schedule_task(tasklist_type* list, task_type* task, int log);

/**
 * Delete task from task list.
 * \param[in] list task list
 * \param[in] task task to delete
 * \return task_type* deleted task
 *
 */
task_type*
tasklist_delete_task(tasklist_type* list, task_type* task);

/**
 * Pop task from task list.
 * \param[in] list task list
 * \return task_type* popped task
 *
 */
task_type* tasklist_pop_task(tasklist_type* list);

/**
 * First task from task list.
 * \param[in] list task list
 * \return task_type* first task
 *
 */
task_type* tasklist_first_task(tasklist_type* list);

/**
 * Print task list.
 * \param[in] out file descriptor
 * \param[in] list task list
 *
 */
void tasklist_print(FILE* out, tasklist_type* list);

#endif /* SCHEDULER_TASK_H */
