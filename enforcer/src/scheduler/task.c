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

#include "config.h"

#include <string.h>

#include "scheduler/task.h"
#include "duration.h"
#include "file.h"
#include "log.h"

static const char* task_str = "task";

void task_deepfree(task_t *task)
{
    ods_log_assert(task);
    free(task->owner);
    if (task->free_context)
        task->free_context(task->context);
    free(task);
}

time_t task_execute(task_t *task, db_connection_t *dbconn)
{
    time_t t;
    ods_log_assert(task);
    /* I'll allow a task without callback, just don't reschedule. */
    if (!task->callback) {
        return -1;
    }
    ods_log_assert(task->owner);
    printf("LOCKING %d %s\n", &task->lock, task->owner);
    pthread_mutex_lock(&task->lock);
    printf("LOCKED %d %s\n", &task->lock, task->owner);
        t = task->callback(task->owner, task->context, dbconn);
    printf("UNLOCKING %d %s\n", &task->lock, task->owner);
    pthread_mutex_unlock(&task->lock);
    return t;
}

static int cmp_ttuple(task_t *x, task_t *y)
{
    int cmp;
    cmp = strcmp(x->owner, y->owner);
    if (cmp != 0)
        return cmp;
    cmp = strcmp(x->type, y->type);
    if (cmp != 0)
        return cmp;
    return strcmp(x->class, y->class);
}

int task_compare_ttuple(const void* a, const void* b)
{
    task_t* x = (task_t*)a;
    task_t* y = (task_t*)b;
    ods_log_assert(a);
    ods_log_assert(b);

    return cmp_ttuple(x, y);
}

int task_compare_time_then_ttuple(const void* a, const void* b)
{
    task_t* x = (task_t*)a;
    task_t* y = (task_t*)b;
    ods_log_assert(a);
    ods_log_assert(b);

    if (x->due_date != y->due_date) {
        return (int) x->due_date - y->due_date;
    }
    return cmp_ttuple(x, y);
}


task_t*
task_duplicate_shallow(task_t *task)
{
    task_t *dup;
    dup = (task_t*) calloc(1, sizeof(task_t));
    if (!task) {
        ods_log_error("[%s] cannot create: malloc failed", task_str);
        return NULL;
    }
    dup->owner = strdup(task->owner);
    dup->type = task->type;
    dup->class = task->class;
    return dup;
}

task_t*
task_create(char *owner, char const *class, char const *type,
    time_t (*callback)(char const *owner, void *context, db_connection_t *dbconn),
    void *context, void (*free_context)(void *context), time_t due_date)
{
    task_t *task;
    ods_log_assert(owner);
    ods_log_assert(class);
    ods_log_assert(type);
    
    task = (task_t*) malloc(sizeof(task_t));
    if (!task) {
        ods_log_error("[%s] cannot create: malloc failed", task_str);
        return NULL;
    }
    task->owner = owner;
    task->class = class;
    task->type = type;
    task->callback = callback;
    task->context = context;
    task->free_context = free_context;
    task->due_date = due_date;

    return task;
}
