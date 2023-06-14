/*
 * Copyright (c) 2009-2018 NLNet Labs.
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
 * Tasks.
 *
 */

#include "config.h"

#include <string.h>
#include <pthread.h>

#include "scheduler/task.h"
#include "scheduler/schedule.h"
#include "status.h"
#include "duration.h"
#include "file.h"
#include "log.h"

static const char* task_str = "task";
static pthread_mutex_t worklock = PTHREAD_MUTEX_INITIALIZER;

const char* TASK_CLASS_ENFORCER = "enforcer";
const char* TASK_CLASS_SIGNER   = "signer";

const char* TASK_NONE           = "[ignore]";

const char* TASK_TYPE_ENFORCE   = "enforce";
const char* TASK_TYPE_RESALT    = "resalt";
const char* TASK_TYPE_HSMKEYGEN = "hsmkeygen";
const char* TASK_TYPE_DSSUBMIT  = "ds-submit";
const char* TASK_TYPE_DSRETRACT = "ds-retract";
const char* TASK_TYPE_SIGNCONF  = "signconf";

const char* TASK_SIGNCONF       = "[configure]";
const char* TASK_READ           = "[read]";
const char* TASK_NSECIFY        = "[???]";
const char* TASK_SIGN           = "[sign]";
const char* TASK_WRITE          = "[write]";
const char* TASK_FORCESIGNCONF  = "[forcesignconf]";
const char* TASK_FORCEREAD      = "[forceread]";

task_type*
task_create(const char *owner, char const *class, char const *type,
    time_t (*callback)(task_type* task, char const *owner, void *userdata, void *context),
    void *userdata, void (*freedata)(void *userdata), time_t due_date)
{
    task_type* task;
    ods_log_assert(owner);
    ods_log_assert(class);
    ods_log_assert(type);

    CHECKALLOC(task = (task_type*) malloc(sizeof(task_type)));;
    task->owner = owner; /* TODO: each call to task_create needs to strdup this, but the free is inside task_destroy */
    task->class = class;
    task->type = type;
    task->callback = callback;
    task->userdata = userdata;
    task->freedata = freedata;
    task->due_date = due_date;
    task->lock = NULL;

    task->backoff = 0;

    return task;
}

void
task_destroy(task_type* task)
{
    ods_log_assert(task);
    free((void*)task->owner);
    if (task->freedata)
        task->freedata((void*)task->userdata);
    free(task);
}

void
task_perform(schedule_type* scheduler, task_type* task, void* context)
{
    time_t rescheduleTime;
    ods_status status;

    if (task->callback) {
        /*
         * It is sad but we need worklock to prevent concurrent database
         * access. Our code is not able to handle that properly. (we can't
         * really tell the difference between an error and nodata.) Once we
         * fixed our database backend this lock can be removed.
         */
        ods_log_assert(task->owner);
        if (!strcmp(task->class, TASK_CLASS_ENFORCER))
            pthread_mutex_lock(&worklock);
        if (task->lock) {
            pthread_mutex_lock(task->lock);
            rescheduleTime = task->callback(task, task->owner, task->userdata, context);
            pthread_mutex_unlock(task->lock);
        } else {
            rescheduleTime = task->callback(task, task->owner, task->userdata, context);
        }
        if (!strcmp(task->class, TASK_CLASS_ENFORCER))
            pthread_mutex_unlock(&worklock);
    } else {
        /* We'll allow a task without callback, just don't reschedule. */
        rescheduleTime = schedule_SUCCESS;
    }
    if (rescheduleTime == schedule_PROMPTLY) {
        rescheduleTime = time_now();
    } else if (rescheduleTime == schedule_IMMEDIATELY) {
        rescheduleTime = 0;
    } else if (rescheduleTime == schedule_DEFER) {
        task->backoff = clamp(task->backoff * 2, 60, ODS_SE_MAX_BACKOFF);
        ods_log_info("back-off task %s for zone %s with %lu seconds", task->type, task->owner, (long) task->backoff);
        rescheduleTime = time_now() + task->backoff;
    }
    if (rescheduleTime >= 0) {
        task->due_date = rescheduleTime;
        status = schedule_task(scheduler, task, (!strcmp(task->class, TASK_CLASS_ENFORCER) ? 1 : 0),
                                                (!strcmp(task->class, TASK_CLASS_SIGNER) ? 1 : 0));
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to schedule task for zone %s: %s", task_str, task->owner, ods_status2str(status));
        }
    } else {
        task_destroy(task);
    }    
}

task_type*
task_duplicate_shallow(task_type *task)
{
    task_type *dup;
    dup = (task_type*) calloc(1, sizeof(task_type));
    if (!dup) {
        ods_log_error("[%s] cannot create: malloc failed", task_str);
        return NULL; /* TODO */
    }
    dup->owner = strdup(task->owner);
    dup->type = task->type;
    dup->class = task->class;
    dup->lock = NULL;
    return dup;
}

static int
cmp_ttuple(task_type *x, task_type *y)
{
    int cmp;
    cmp = strcmp(x->owner, y->owner);
    if (cmp != 0)
        return cmp;
    if (strcmp(x->type, schedule_WHATEVER) && strcmp(y->type, schedule_WHATEVER)) {
        cmp = strcmp(x->type, y->type);
        if (cmp != 0)
            return cmp;
    }
    return strcmp(x->class, y->class);
}

int
task_compare_ttuple(const void* a, const void* b)
{
    task_type* x = (task_type*)a;
    task_type* y = (task_type*)b;
    ods_log_assert(a);
    ods_log_assert(b);

    return cmp_ttuple(x, y);
}

int
task_compare_time_then_ttuple(const void* a, const void* b)
{
    task_type* x = (task_type*)a;
    task_type* y = (task_type*)b;
    ods_log_assert(a);
    ods_log_assert(b);

    if (x->due_date != schedule_WHENEVER && y->due_date != schedule_WHENEVER) {
        if (x->due_date != y->due_date) {
            return x->due_date - y->due_date;
        }
    }
    return cmp_ttuple(x, y);
}

void
task_log(task_type* task)
{
    char* strtime = NULL;

    if (task) {
        strtime = ctime(&task->due_date);
        if (strtime) {
            strtime[strlen(strtime)-1] = '\0';
        }
        ods_log_debug("[%s] On %s I will %s zone %s", task_str,
            strtime?strtime:"(null)", task->type, task->owner);
    }
}
