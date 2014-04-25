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

#include "config.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "shared/duration.h"
#include "shared/log.h"

#include <ldns/ldns.h>

static const char* schedule_str = "scheduler";

/**
 * Convert task to a tree node.
 *
 */
static ldns_rbnode_t*
task2node(task_type* task)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) malloc(sizeof(ldns_rbnode_t));
    node->key = task;
    node->data = task;
    return node;
}


/**
 * Look up task.
 *
 */
task_type*
schedule_lookup_task(schedule_type* schedule, task_type* task)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    task_type* lookup = NULL;

    if (!schedule || !task) {
        return NULL;
    }
    ods_log_assert(task);
    ods_log_assert(schedule);
    ods_log_assert(schedule->tasks);

    node = ldns_rbtree_search(schedule->tasks, task);
    if (node && node != LDNS_RBTREE_NULL) {
        lookup = (task_type*) node->data;
    }
    return lookup;
}


/**
 * Schedule task.
 *
 */
ods_status
schedule_task(schedule_type* schedule, task_type* task, int log)
{
    ldns_rbnode_t* new_node = NULL;
    ldns_rbnode_t* ins_node = NULL;

    if (!task) {
        ods_log_error("[%s] unable to schedule task: no task", schedule_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    task->flush = 0;
    ods_log_assert(task);
    if (!schedule) {
        ods_log_error("[%s] unable to schedule task: no schedule",
            schedule_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(schedule);
    ods_log_assert(schedule->tasks);

    ods_log_debug("[%s] schedule task [%s] for %s", schedule_str,
        task_what2str(task->what), task_who2str(task->who));
    if (schedule_lookup_task(schedule, task) != NULL) {
        ods_log_error("[%s] unable to schedule task [%s] for %s: "
            " already present", schedule_str, task_what2str(task->what),
            task_who2str(task->who));
        return ODS_STATUS_ERR;
    }
    new_node = task2node(task);
    ins_node = ldns_rbtree_insert(schedule->tasks, new_node);
    if (!ins_node) {
        ods_log_error("[%s] unable to schedule task [%s] for %s: "
            " insert failed", schedule_str, task_what2str(task->what),
            task_who2str(task->who));
        free((void*)new_node);
        return ODS_STATUS_ERR;
    }
    if (log) {
        task_log(task);
    }
    return ODS_STATUS_OK;
}


/**
 * Lock the schedule lock and then schedule a task.
 *
 */
ods_status 
lock_and_schedule_task(schedule_type* schedule, task_type* task,
                                     int log)
{
    ods_status status;
    lock_basic_lock(&schedule->schedule_lock);
    /* [LOCK] schedule */
    status = schedule_task(schedule, task, log);
    /* [UNLOCK] schedule */
    lock_basic_unlock(&schedule->schedule_lock);
    return status;
}


/**
 * Unschedule task.
 *
 */
task_type*
unschedule_task(schedule_type* schedule, task_type* task)
{
    ldns_rbnode_t* del_node = LDNS_RBTREE_NULL;
    task_type* del_task = NULL;

    if (!task) {
        /* we are done */
        return NULL;
    }
    ods_log_assert(task);
    if (!schedule) {
        ods_log_error("[%s] unable to unschedule task: no schedule",
            schedule_str);
        return task;
    }
    ods_log_assert(schedule);
    ods_log_assert(schedule->tasks);

    ods_log_debug("[%s] unschedule task [%s] for %s",
        schedule_str, task_what2str(task->what), task_who2str(task->who));
    del_node = ldns_rbtree_delete(schedule->tasks, (const void*) task);
    if (del_node) {
        del_task = (task_type*) del_node->data;
        free((void*)del_node);
    } else {
        ods_log_warning("[%s] unable to unschedule task [%s] for %s: not "
            "scheduled", schedule_str, task_what2str(task->what),
            task_who2str(task->who));
    }
    return del_task;
}


/**
 * Reschedule task.
 *
 */
ods_status
reschedule_task(schedule_type* schedule, task_type* task, task_id what,
    time_t when)
{
    task_type* del_task;

    del_task = unschedule_task(schedule, task);
    if (del_task) {
        del_task->what = what;
        del_task->when = when;
    }
    return schedule_task(schedule, del_task, 1);
}


/**
 * Get the first scheduled task.
 * \param[in] schedule schedule
 * \return task_type* first scheduled task
 */
static task_type*
schedule_get_first_task(schedule_type* schedule)
{
    ldns_rbnode_t* first_node;

    if (!schedule || !schedule->tasks) return NULL;
    
    first_node = ldns_rbtree_first(schedule->tasks);
    
    if (first_node)
        return (task_type*) first_node->data;
    return NULL;
}


/**
 * Pop the first scheduled task.
 *
 */
task_type*
schedule_pop_task(schedule_type* schedule)
{
    task_type* pop = NULL;
    time_t now = 0;

    if (!schedule) {
        ods_log_error("[%s] unable to pop task: no schedule", schedule_str);
        return NULL;
    }
    ods_log_assert(schedule);
    ods_log_assert(schedule->tasks);

    now = time_now();
    pop = schedule_get_first_task(schedule);
    if (pop && (pop->flush || pop->when <= now)) {
        if (pop->flush) {
            ods_log_debug("[%s] flush task for %s", schedule_str,
                pop->who?pop->who:"(null)");
        } else {
            ods_log_debug("[%s] pop task for %s", schedule_str,
                pop->who?pop->who:"(null)");
        }
        return unschedule_task(schedule, pop);
    }
    return NULL;
}


/**
 * Print schedule.
 *
 */
void
schedule_print(FILE* out, schedule_type* schedule)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    task_type* task = NULL;

    if (!out || !schedule || !schedule->tasks) {
        return;
    }
    ods_log_assert(out);
    ods_log_assert(schedule);
    ods_log_assert(schedule->tasks);

    node = ldns_rbtree_first(schedule->tasks);
    while (node && node != LDNS_RBTREE_NULL) {
        task = (task_type*) node->data;
        task_print(out, task);
        node = ldns_rbtree_next(node);
    }
    fprintf(out, "\n");
    return;
}


/**
 * Internal task cleanup function.
 *
 */
static void
task_delfunc(ldns_rbnode_t* elem)
{
    task_type* task;

    if (elem && elem != LDNS_RBTREE_NULL) {
        task = (task_type*) elem->data;
        task_delfunc(elem->left);
        task_delfunc(elem->right);
        task_cleanup(task);
        free((void*)elem);
    }
    return;
}

/**
 * Create new schedule.
 *
 */
schedule_type*
schedule_create()
{
    schedule_type* schedule;

    schedule = (schedule_type*) malloc(sizeof(schedule_type));
    if (!schedule) {
        ods_log_error("[%s] unable to create: malloc failed", schedule_str);
        return NULL;
    }

    schedule->loading = 0;
    schedule->tasks = ldns_rbtree_create(task_compare);
    pthread_mutex_init(&schedule->schedule_lock, NULL);
    pthread_cond_init(&schedule->schedule_cond, NULL);
    
    return schedule;
}

/**
 * Clean up schedule.
 *
 */
void
schedule_cleanup(schedule_type* schedule)
{
    if (!schedule) return;
    ods_log_debug("[%s] cleanup schedule", schedule_str);
    if (schedule->tasks) {
        task_delfunc(schedule->tasks->root);
        ldns_rbtree_free(schedule->tasks);
        schedule->tasks = NULL;
    }
    pthread_mutex_destroy(&schedule->schedule_lock);
    free(schedule);
}

/**
 * exported convinience functions should all be thread safe
 */

time_t
schedule_time_first(schedule_type* schedule)
{
    task_type* task;
    time_t when;
    
    if (!schedule || !schedule->tasks) return -1;

    pthread_mutex_lock(&schedule->schedule_lock);
        task = schedule_get_first_task(schedule);
        if (!task)
            when = -1;
        else if (task->flush)
            when = 0;
        else 
            when = task->when;
    pthread_mutex_unlock(&schedule->schedule_lock);
    return when;
}

size_t
schedule_taskcount(schedule_type* schedule)
{
    size_t count;
    if (!schedule || !schedule->tasks) return 0;
    pthread_mutex_lock(&schedule->schedule_lock);
        count = schedule->tasks->count;
    pthread_mutex_unlock(&schedule->schedule_lock);
    return count;
}

/**
 * Flush all tasks in schedule. thread safe.
 */
void
schedule_flush(schedule_type* schedule)
{
    ldns_rbnode_t* node;
    task_type* task;
    
    ods_log_debug("[%s] flush all tasks", schedule_str);
    if (!schedule || !schedule->tasks) return;

    pthread_mutex_lock(&schedule->schedule_lock);
        node = ldns_rbtree_first(schedule->tasks);
        while (node && node != LDNS_RBTREE_NULL) {
            task = (task_type*) node->data;
            task->flush = 1;
            node = ldns_rbtree_next(node);
        }
        /* wakeup! work to do! */
        pthread_cond_signal(&schedule->schedule_cond);
    pthread_mutex_unlock(&schedule->schedule_lock);
}

