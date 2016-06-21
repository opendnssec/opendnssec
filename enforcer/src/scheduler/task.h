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
 * Tasks consists of 3 parts: an identifier, due_date, and payload.
 *
 * Identifier: a task is uniquely identified by its ttuple (task-tuple).
 * which consist of a class (enforcer/signer) a type (resalt/sign) and
 * an owner, usually the zone the task is for. This way we can find
 * all tasks belonging to a component so we can later merge signer and
 * enforcer if we so wish.
 *
 * due_date: The time this task should run on. Unix timestamp. Anything
 * smaller than now() should be considered ASAP. Negative values should
 * not be given. They are special and tell the signer not to schedule a
 * task.
 *
 * Payload: the callback, a context passed to the callback and method
 * to free the context.
 * 
 */

#ifndef SCHEDULER_TASK_H
#define SCHEDULER_TASK_H

#include "config.h"

#include <pthread.h>

#include "status.h"
#include "db/db_connection.h"

#define TASK_CLASS_ENFORCER "enforcer"

#define TASK_TYPE_ENFORCE   "enforce"
#define TASK_TYPE_RESALT    "resalt"
#define TASK_TYPE_HSMKEYGEN "hsmkeygen"
#define TASK_TYPE_DSSUBMIT  "ds-submit"
#define TASK_TYPE_DSRETRACT "ds-retract"
#define TASK_TYPE_SIGNCONF  "signconf"

typedef struct _task {
    /* The following span the T-tuple. It is used to uniquely identify
     * a task. */
    char *owner; /* e.g. "example.com". string owned by task */
    char const *class; /* e.g. "enforcer" */
    char const *type; /* e.g. "resalt" */

    /* date and time this task should execute anything. If time is in
     * the past interpret it as *now* */
    time_t due_date;

    /* if returned time >= 0 the task is rescheduled for that time.
     * keeping context. otherwise scheduler will free context, owner,
     * and task. */
    time_t (*callback)(char const *owner, void *context, db_connection_t *dbconn);

    /* Context passed to callback. */
    void *context;

    /* Callback to deepfree task context. Leave NULL to not free the
     * context. The function should accept a NULL argument just like
     * free() does. */
    void (*free_context)(void *context);

    /* Lock specific for this task. It is assigned by the scheduler
     * on scheduler_push_task(). All tasks with the same ttuple will
     * get the same lock. */
    pthread_mutex_t lock;
} task_t;

/* Free task, owner, and context */
void task_deepfree(task_t *task);

/* Execute callback of given task. a return value of < 0 means that
 * this task should not be rescheduled. Feel free to clean it up. */
time_t task_execute(task_t *task, db_connection_t *dbconn);

/* used in our reverse lookup structure. */
int task_compare_ttuple(const void* a, const void* b);

/* This is used for sorting our queue */
int task_compare_time_then_ttuple(const void* a, const void* b);

/* Create new task, copy ttuple from existing task. NULL on malloc
 * failure. */
task_t*
task_duplicate_shallow(task_t *task);

/*
 * owner: string is owned by task.
 * context: also owned by task */
task_t*
task_create(char *owner, char const *class, char const *type,
    time_t (*callback)(char const *owner, void *context, db_connection_t *dbconn),
    void *context, void (*free_context)(void *context), time_t due_date);

#endif /* SCHEDULER_TASK_H */
