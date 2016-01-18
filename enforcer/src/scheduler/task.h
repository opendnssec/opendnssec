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
 * Tasks.
 *
 */

#ifndef SCHEDULER_TASK_H
#define SCHEDULER_TASK_H

#include "config.h"
#include "status.h"
#include "db/db_connection.h"

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
    task_id what;
    task_id interrupt;
    task_id halted;
    time_t when;
    time_t backoff;
    int flush;
    char* who;
    ldns_rdf* dname;
    void* context;
    task_type* (*how)(task_type*task);
    task_type* (*clean_context)(task_type*task);
    db_connection_t *dbconn; /* short lived */
};

typedef task_type* (*how_type)(task_type*task);

/**
 * Register a task type with a task name and a named how function.
 * This registry is used when restoring a task from a backup.
 * \param[in] short_name short name for what the task does
 * \param[in] long_name unique name identifying the how function
 * \param[in] how the function that performs the task
 * \return task_id dynamically allocated for this how to perform function
 *
 */
task_id task_register(const char *short_name, const char *long_name, 
    how_type how);

/**
 * Create a new task.
 * \param[in] what task identifier
 * \param[in] when scheduled time
 * \param[in] who context name e.g. a dns name like "example.com"
 * \param[in] context pointer to context
 * \return task_type* created task
 *
 */
task_type* task_create(task_id what_id, time_t when, const char* who,
    const char* what, void* context, how_type clean_context);

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
 * Compare tasks by name.
 * \param[in] a one task
 * \param[in] b another task
 * \return int -1, 0 or 1
 *
 */
int task_compare_name(const void* a, const void* b);

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

bool task_id_from_long_name(const char *long_name, task_id *pwhat);

#endif /* SCHEDULER_TASK_H */
