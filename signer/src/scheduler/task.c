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

#include "config.h"
#include "scheduler/task.h"
#include "shared/allocator.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/log.h"
#include "signer/backup.h"
#include "signer/zone.h"

static const char* task_str = "task";


/**
 * Create a new task.
 *
 */
task_type*
task_create(task_id what, time_t when, void* zone)
{
    allocator_type* allocator = NULL;
    task_type* task = NULL;

    if (!zone) {
        return NULL;
    }
    allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to create task: allocator_create() failed",
            task_str);
        return NULL;
    }
    task = (task_type*) allocator_alloc(allocator, sizeof(task_type));
    if (!task) {
        ods_log_error("[%s] unable to create task: allocator_alloc() failed",
            task_str);
        allocator_cleanup(allocator);
        return NULL;
    }
    task->allocator = allocator;
    task->what = what;
    task->interrupt = TASK_NONE;
    task->halted = TASK_NONE;
    task->when = when;
    task->halted_when = 0;
    task->backoff = 0;
    task->flush = 0;
    task->zone = zone;
    return task;
}


/**
 * Backup task.
 *
 */
void
task_backup(FILE* fd, task_type* task)
{
    if (!fd || !task) {
        return;
    }
    ods_log_assert(fd);
    ods_log_assert(task);

    fprintf(fd, ";;Task: when %u what %i interrupt %i halted %i backoff %i "
        "flush %i\n",
        (unsigned) task->when,
        (int) task->what,
        (int) task->interrupt,
        (int) task->halted,
        (unsigned) task->backoff,
        task->flush);
    return;
}


/**
 * Compare tasks.
 *
 */
int
task_compare(const void* a, const void* b)
{
    task_type* x = (task_type*)a;
    task_type* y = (task_type*)b;
    zone_type* zx = NULL;
    zone_type* zy = NULL;

    ods_log_assert(x);
    ods_log_assert(y);
    zx = (zone_type*) x->zone;
    zy = (zone_type*) y->zone;
    if (!ldns_dname_compare((const void*) zx->apex,
        (const void*) zy->apex)) {
        /* if dname is the same, consider the same task */
        return 0;
    }
    /* order task on time, what to do, dname */
    if (x->when != y->when) {
        return (int) x->when - y->when;
    }
    if (x->what != y->what) {
        return (int) x->what - y->what;
    }
    /* this is unfair, it prioritizes zones that are first in canonical line */
    return ldns_dname_compare((const void*) zx->apex,
        (const void*) zy->apex);
}


/**
 * String-format of what.
 *
 */
const char*
task_what2str(task_id what)
{
    switch (what) {
        case TASK_NONE:
            return "[ignore]";
            break;
        case TASK_SIGNCONF:
            return "[configure]";
            break;
        case TASK_READ:
            return "[read]";
            break;
        case TASK_SIGN:
            return "[sign]";
            break;
        case TASK_WRITE:
            return "[write]";
            break;
        default:
            break;
    }
    return "[???]";
}


/**
 * String-format of who.
 *
 */
const char*
task_who2str(task_type* task)
{
    zone_type* zone = NULL;
    if (task) {
        zone = (zone_type*) task->zone;
    }
    if (zone && zone->name) {
        return zone->name;
    }
    return "(null)";
}


/**
 * Convert task to string.
 *
 */
char*
task2str(task_type* task, char* buftask)
{
    char* strtime = NULL;
    char* strtask = NULL;

    if (task) {
        strtime = ctime(&task->when);
        if (strtime) {
            strtime[strlen(strtime)-1] = '\0';
        }
        if (buftask) {
            (void)snprintf(buftask, ODS_SE_MAXLINE, "%s %s I will %s zone %s"
                "\n", task->flush?"Flush":"On", strtime?strtime:"(null)",
                task_what2str(task->what), task_who2str(task));
            return buftask;
        } else {
            strtask = (char*) calloc(ODS_SE_MAXLINE, sizeof(char));
            snprintf(strtask, ODS_SE_MAXLINE, "%s %s I will %s zone %s\n",
                task->flush?"Flush":"On", strtime?strtime:"(null)",
                task_what2str(task->what), task_who2str(task));
            return strtask;
        }
    }
    return NULL;
}


/**
 * Print task.
 *
 */
void
task_print(FILE* out, task_type* task)
{
    char* strtime = NULL;

    if (out && task) {
        strtime = ctime(&task->when);
        if (strtime) {
            strtime[strlen(strtime)-1] = '\0';
        }
        fprintf(out, "%s %s I will %s zone %s\n",
            task->flush?"Flush":"On", strtime?strtime:"(null)",
            task_what2str(task->what), task_who2str(task));
    }
    return;
}


/**
 * Log task.
 *
 */
void
task_log(task_type* task)
{
    char* strtime = NULL;

    if (task) {
        strtime = ctime(&task->when);
        if (strtime) {
            strtime[strlen(strtime)-1] = '\0';
        }
        ods_log_debug("[%s] %s %s I will %s zone %s", task_str,
            task->flush?"Flush":"On", strtime?strtime:"(null)",
            task_what2str(task->what), task_who2str(task));
    }
    return;
}


/**
 * Clean up task.
 *
 */
void
task_cleanup(task_type* task)
{
    allocator_type* allocator;
    if (!task) {
        return;
    }
    allocator = task->allocator;
    allocator_deallocate(allocator, (void*) task);
    allocator_cleanup(allocator);
    return;
}
