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
#include "duration.h"
#include "log.h"

#include <ldns/ldns.h>

static const char* schedule_str = "scheduler";


/**
 * Create new schedule.
 *
 */
schedule_type*
schedule_create()
{
    schedule_type* schedule;
    CHECKALLOC(schedule = (schedule_type*) malloc(sizeof(schedule_type)));
    if (!schedule) {
        ods_log_error("[%s] unable to create schedule: allocator_alloc() "
            "failed", schedule_str);
        return NULL;
    }
    schedule->loading = 0;
    schedule->flushcount = 0;
    schedule->tasks = ldns_rbtree_create(task_compare);
    if (!schedule->tasks) {
        ods_log_error("[%s] unable to create schedule: ldns_rbtree_create() "
            "failed", schedule_str);
        free(schedule);
        return NULL;
    }
    lock_basic_init(&schedule->schedule_lock);
    return schedule;
}


/**
 * Flush schedule.
 *
 */
void
schedule_flush(schedule_type* schedule, task_id override)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    task_type* task = NULL;

    ods_log_debug("[%s] flush all tasks", schedule_str);
    if (!schedule || !schedule->tasks) {
        return;
    }
    node = ldns_rbtree_first(schedule->tasks);
    while (node && node != LDNS_RBTREE_NULL) {
        task = (task_type*) node->data;
        task->flush = 1;
        schedule->flushcount++;
        if (override != TASK_NONE) {
            task->what = override;
        }
        node = ldns_rbtree_next(node);
    }
}


/**
 * Convert task to a tree node.
 *
 */
static ldns_rbnode_t*
task2node(task_type* task)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) malloc(sizeof(ldns_rbnode_t));
    if (node) {
        node->key = task;
        node->data = task;
    }
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
    if (!task || !schedule || !schedule->tasks) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_debug("[%s] schedule task %s for zone %s", schedule_str,
        task_what2str(task->what), task_who2str(task));
    if (schedule_lookup_task(schedule, task) != NULL) {
        ods_log_error("[%s] unable to schedule task %s for zone %s: "
            " already present", schedule_str, task_what2str(task->what),
            task_who2str(task));
        return ODS_STATUS_ERR;
    }
    new_node = task2node(task);
    if (!new_node) {
        ods_log_error("[%s] unable to schedule task %s for zone %s: "
            " task2node() failed", schedule_str, task_what2str(task->what),
            task_who2str(task));
        return ODS_STATUS_MALLOC_ERR;
    }
    ins_node = ldns_rbtree_insert(schedule->tasks, new_node);
    if (!ins_node) {
        ods_log_error("[%s] unable to schedule task %s for zone %s: "
            " insert failed", schedule_str, task_what2str(task->what),
            task_who2str(task));
        free((void*)new_node);
        return ODS_STATUS_ERR;
    }
    if (task->flush) {
        schedule->flushcount++;
    }
    if (log) {
        task_log(task);
    }
    return ODS_STATUS_OK;
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
    if (!task || !schedule || !schedule->tasks) {
        return NULL;
    }
    ods_log_debug("[%s] unschedule task %s for zone %s",
        schedule_str, task_what2str(task->what), task_who2str(task));
    del_node = ldns_rbtree_delete(schedule->tasks, (const void*) task);
    if (del_node) {
        del_task = (task_type*) del_node->data;
        free((void*)del_node);
    } else {
        ods_log_warning("[%s] unable to unschedule task %s for zone %s: not "
            "scheduled", schedule_str, task_what2str(task->what),
            task_who2str(task));
        return NULL;
    }
    if (del_task->flush) {
        del_task->flush = 0;
        schedule->flushcount--;
    }
    return del_task;
}


/**
 * Get the first scheduled task.
 *
 */
task_type*
schedule_get_first_task(schedule_type* schedule)
{
    ldns_rbnode_t* first_node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    task_type* pop = NULL;
    if (!schedule || !schedule->tasks) {
        return NULL;
    }
    first_node = ldns_rbtree_first(schedule->tasks);
    if (!first_node) {
        return NULL;
    }
    if (schedule->flushcount > 0) {
        /* find remaining to be flushed tasks */
        node = first_node;
        while (node && node != LDNS_RBTREE_NULL) {
            pop = (task_type*) node->data;
            if (pop->flush) {
                return pop;
            }
            node = ldns_rbtree_next(node);
        }
        /* no more to be flushed tasks found */
        ods_log_warning("[%s] unable to get first scheduled task: could not "
            "find flush-task, while there should be %i flush-tasks left",
            schedule_str, schedule->flushcount);
        ods_log_info("[%s] reset flush count to 0", schedule_str);
        schedule->flushcount = 0;
    }
    /* no more tasks to be flushed, return first task in schedule */
    pop = (task_type*) first_node->data;
    return pop;
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
    if (!schedule || !schedule->tasks) {
        return NULL;
    }
    now = time_now();
    pop = schedule_get_first_task(schedule);
    if (pop && (pop->flush || pop->when <= now)) {
        if (pop->flush) {
            ods_log_debug("[%s] flush task for zone %s", schedule_str,
                task_who2str(pop));
        } else {
            ods_log_debug("[%s] pop task for zone %s", schedule_str,
                task_who2str(pop));
        }
        return unschedule_task(schedule, pop);
    }
    return NULL;
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
}


/**
 * Clean up schedule.
 *
 */
void
schedule_cleanup(schedule_type* schedule)
{
    lock_basic_type schedule_lock;

    if (!schedule) {
        return;
    }
    ods_log_debug("[%s] cleanup schedule", schedule_str);
    if (schedule->tasks) {
        task_delfunc(schedule->tasks->root);
        ldns_rbtree_free(schedule->tasks);
        schedule->tasks = NULL;
    }
    schedule_lock = schedule->schedule_lock;
    free(schedule);
    lock_basic_destroy(&schedule_lock);
}
