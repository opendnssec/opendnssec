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
#include "shared/allocator.h"

#include <ldns/ldns.h>

enum task_id_enum {
    TASK_NONE = 0,
/* tasks defined by signer */
    TASK_SIGNCONF,
    TASK_READ,
    TASK_NSECIFY,
    TASK_SIGN,
    TASK_AUDIT,
    TASK_WRITE,
/* tasks registerd dynamically return an id starting at TASK_DYNAMIC_FIRST */
    TASK_DYNAMIC_FIRST = 1000
};
typedef enum task_id_enum task_id;

/**
 * Task.
 */
typedef struct task_struct task_type;
struct task_struct {
    allocator_type* allocator;
    task_id what;
    task_id interrupt;
    task_id halted;
    time_t when;
    time_t backoff;
    int flush;
    const char* who;
    ldns_rdf* dname;
    void* context;
	task_type* (*how)(task_type*task);
};

typedef task_type* (*how_type)(task_type*task);

/**
 * Create a new task.
 * \param[in] what task identifier
 * \param[in] when scheduled time
 * \param[in] who context name
 * \param[in] context pointer to context
 * \param[in] how function that implements how this task is performed
 * \return task_type* created task
 *
 */
task_type* task_create(task_id what, time_t when, const char* who, void* context, how_type how);

/**
 * Recover a task from backup.
 * \param[in] filename where the task backup is stored
 * \param[in] context pointer to context structure
 * \return task_type* created task
 *
 */
task_type* task_recover_from_backup(const char* filename, void* context);

/**
 * Backup task.
 * \param[in] task task
 *
 */
void task_backup(task_type* task);

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
 * \return string-format task
 *
 */
char* task2str(task_type* task, char* buftask);

/**
 * String-format of who.
 * \param[in] what task identifier
 * \return const char* string-format of what
 *
 */
const char* task_what2str(int taskid);

/**
 * String-format of who.
 * \param[in] what task owner
 * \return const char* string-format of who
 */
const char* task_who2str(const char* who);

/**
 * Print task.
 * \param[in] out file descriptor
 * \param[in] task task
 *
 */
void task_print(FILE* out, task_type* task);

/**
 * Log task.
 * \param[in] task task
 *
 */
void task_log(task_type* task);

/**
 * Actually perform the task.
 * \param[in] task task
 * \return task_type * task to be scheduled next, usually same as performed task.
 *
 */
task_type *task_perform(task_type *task);

/**
 * Register a named how function for use in tasks. This registry is used 
 * when restoring a task from a backup.
 * \param[in] name name of the how function
 * \param[in] how the function to perform
 * \return task_id dynamically allocated for this how to perform function
 *
 */
task_id task_register_how(const char *name, how_type how);

/**
 * Get the name of the how function associated with the task
 * \param[in] task task
 * \return const char* string format of how
 */
const char *task_how_name(task_type *task);

/**
 * Get the how perform function for a given how name
 * \param[in] name name of the task
 * \return how_type perform function associated with the given name
 *
 */
how_type task_how_type(const char *name);

#endif /* SCHEDULER_TASK_H */
