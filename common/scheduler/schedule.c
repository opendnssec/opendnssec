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
 * This module maintains a collection of tasks. All external functions
 * should be thread safe. Beware not to call an external function from
 * within this module, it will cause deadlocks.
 *
 * In principle the calling function should never need to lock the
 * scheduler.
 */

#include "config.h"

#include <ldns/ldns.h>
#include <pthread.h>
#include <signal.h>

#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "scheduler/fifoq.h"
#include "duration.h"
#include "log.h"
#include "locks.h"
#include "util.h"

static const char* schedule_str = "scheduler";

/**
 * Convert task to a tree node.
 * NULL on malloc failure
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
 * Get the first scheduled task. As long as return value is used
 * caller should hold schedule->schedule_lock.
 *
 * \param[in] schedule schedule
 * \return task_type* first scheduled task, NULL on no task or error.
 */
static task_type*
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
    /* no more tasks to be flushed, return first task in schedule */
    pop = (task_type*) first_node->data;
    return pop;
}

/**
 * pop the first scheduled task. Caller must hold
 * schedule->schedule_lock. Result is safe to use outside lock.
 * 
 * \param[in] schedule schedule
 * \return task_type* first scheduled task, NULL on no task or error.
 */
static task_type*
pop_first_task(schedule_type* schedule)
{
    ldns_rbnode_t *node, *delnode;
    task_type *task;

    if (!schedule || !schedule->tasks) return NULL;
    node = ldns_rbtree_first(schedule->tasks);
    if (!node) return NULL;
    delnode = ldns_rbtree_delete(schedule->tasks, node->data);
    /* delnode == node, but we don't free it just yet, data is shared
     * with tasks_by_name tree */
    if (!delnode) return NULL;
    delnode = ldns_rbtree_delete(schedule->tasks_by_name, node->data);
    free(node);
    if (!delnode) return NULL;
    task = (task_type*) delnode->data;
    free(delnode); /* this delnode != node */
    pthread_cond_signal(&schedule->schedule_cond);
    return task;
}

/**
 * Internal task cleanup function.
 *
 */
static void
task_delfunc(ldns_rbnode_t* node)
{
    task_type* task;

    if (node && node != LDNS_RBTREE_NULL) {
        task = (task_type*) node->data;
        task_delfunc(node->left);
        task_delfunc(node->right);
        task_destroy(task);
        free((void*)node);
    }
}
static void
task_delfunc2(ldns_rbnode_t* node)
{
    if (node && node != LDNS_RBTREE_NULL) {
        task_delfunc2(node->left);
        task_delfunc2(node->right);
        free((void*)node);
    }
}

/* Removes task from both trees and assign nodes to node1 and node2.
 * These belong to the caller now
 * 
 * 0 on success */
static int
fetch_node_pair(schedule_type *schedule, task_type *task,
    ldns_rbnode_t **nodeFromTimeTree, ldns_rbnode_t **nodeFromNameTree, int remove)
{
    task_type *originalTask;

    ods_log_assert(schedule);
    ods_log_assert(task);
    *nodeFromTimeTree = NULL;
    if (remove) {
        *nodeFromNameTree = ldns_rbtree_delete(schedule->tasks_by_name, task);
    } else {
        *nodeFromNameTree = ldns_rbtree_search(schedule->tasks_by_name, task);
    }
    if (!*nodeFromNameTree) {
        return 1; /* could not find task*/
    } else {
        originalTask = (task_type*) (*nodeFromNameTree)->key; /* This is the original task, it has the correct time so we can find it in tasks */
        ods_log_assert(originalTask);
        if (remove) {
            *nodeFromTimeTree = ldns_rbtree_delete(schedule->tasks, originalTask);
        } else {
            *nodeFromTimeTree = ldns_rbtree_search(schedule->tasks, originalTask);
        }
        ods_log_assert(*nodeFromTimeTree);
        return 0;
    }
}

/**
 * Create new schedule. Allocate and initialise scheduler. To clean
 * up schedule_cleanup() should be called.
 */
schedule_type*
schedule_create()
{
    schedule_type* schedule;
    CHECKALLOC(schedule = (schedule_type*) malloc(sizeof(schedule_type)));

    schedule->tasks = ldns_rbtree_create(task_compare_time_then_ttuple);
    schedule->tasks_by_name = ldns_rbtree_create(task_compare_ttuple);
    schedule->locks_by_name = ldns_rbtree_create(task_compare_ttuple);

    pthread_mutex_init(&schedule->schedule_lock, NULL);
    pthread_cond_init(&schedule->schedule_cond, NULL);
    schedule->num_waiting = 0;
    schedule->handlers = NULL;
    schedule->nhandlers = 0;
    
    CHECKALLOC(schedule->signq = fifoq_create());

    return schedule;
}

/**
 * Clean up schedule. deinitialise and free scheduler.
 * Threads MUST be stopped before calling this function.
 */
void
schedule_cleanup(schedule_type* schedule)
{
    if (!schedule) return;
    ods_log_debug("[%s] cleanup schedule", schedule_str);

    if (schedule->tasks) {
        task_delfunc(schedule->tasks->root);
        task_delfunc2(schedule->tasks_by_name->root);
        ldns_rbtree_free(schedule->tasks);
        ldns_rbtree_free(schedule->tasks_by_name);
        ldns_rbtree_free(schedule->locks_by_name);
        schedule->tasks = NULL;
    }
    fifoq_cleanup(schedule->signq);
    pthread_mutex_destroy(&schedule->schedule_lock);
    pthread_cond_destroy(&schedule->schedule_cond);
    free(schedule->handlers);
    free(schedule);
}

void
schedule_purge(schedule_type* schedule)
{
    ldns_rbnode_t* node;
    
    if (!schedule || !schedule->tasks) return;

    pthread_mutex_lock(&schedule->schedule_lock);
        /* don't attempt to free payload, still referenced by other tree*/
        while ((node = ldns_rbtree_first(schedule->tasks)) !=
            LDNS_RBTREE_NULL)
        {
            node = ldns_rbtree_delete(schedule->tasks, node->data);
            if (node == 0) break;
            free(node);
        }
        /* also clean up name tree */
        while ((node = ldns_rbtree_first(schedule->tasks_by_name)) !=
            LDNS_RBTREE_NULL)
        {
            node = ldns_rbtree_delete(schedule->tasks_by_name, node->data);
            if (node == 0) break;
            task_destroy((task_type*) node->data);
            free(node);
        }
        /* also clean up locks tree */
        while ((node = ldns_rbtree_first(schedule->locks_by_name)) !=
            LDNS_RBTREE_NULL)
        {
            node = ldns_rbtree_delete(schedule->locks_by_name, node->data);
            if (node == 0) break;
            pthread_mutex_destroy(((task_type*) node->data)->lock);
            free(((task_type*) node->data)->lock);
            task_destroy((task_type*) node->data);
            free(node);
        }
    pthread_mutex_unlock(&schedule->schedule_lock);
}

void
schedule_purge_owner(schedule_type* schedule, char const *class,
    char const *owner)
{
    /* This method is somewhat inefficient but not too bad. Approx:
     * O(N + M log N). Where N total tasks, M tasks to remove. Probably
     * a bit worse since the trees are balanced. */
    task_type **tasks, *task;
    int i, num_slots = 10, num_tasks = 0;
    ldns_rbnode_t *n1, *n2, *node;

    /* We expect around 3 tasks per owner so we probably never have to
     * realloc if we start with num_slots = 10 */
    tasks = (task_type **)malloc(num_slots * sizeof(task_type *));
    if (!tasks) return;

    pthread_mutex_lock(&schedule->schedule_lock);

        /* First collect all tasks that match. Don't fiddle with the
         * tree. That is not save and might mess up our iteration. */
        node = ldns_rbtree_first(schedule->tasks_by_name);
        while (node != LDNS_RBTREE_NULL) {
            task = (task_type *) node->key;
            node = ldns_rbtree_next(node);
            if (!strcmp(task->owner, owner) && !strcmp(task->class, class)) {
                tasks[num_tasks++] = task;
                if (num_tasks == num_slots) {
                    num_slots *= 2;
                    tasks = realloc(tasks, num_slots * sizeof(task_type *));
                    if (!tasks) {
                        pthread_mutex_unlock(&schedule->schedule_lock);
                        return;
                    }
                }
            }
        }

        /* Be free my little tasks, be free! */
        for (i = 0; i<num_tasks; i++) {
            if (!fetch_node_pair(schedule, tasks[i], &n1, &n2, 1)) {
                task_destroy(tasks[i]);
                free(n1);
                free(n2);
            }
        }
        free(tasks);

    pthread_mutex_unlock(&schedule->schedule_lock);
}

ods_status
schedule_task(schedule_type* schedule, task_type* task, int replace, int log)
{
    ods_status status = ODS_STATUS_OK;
    ldns_rbnode_t* node1;
    ldns_rbnode_t* node2;
    task_type *existing_task, *t;

    ods_log_assert(task);
    if (!schedule || !schedule->tasks) {
        ods_log_error("[%s] unable to schedule task: no schedule",
                schedule_str);
        return ODS_STATUS_ERR;
    }
    ods_log_debug("[%s] schedule task %s for %s", schedule_str,
            task->type, task->owner);

    pthread_mutex_lock(&schedule->schedule_lock);
    if (fetch_node_pair(schedule, task, &node1, &node2, replace)) {
        /* Though no such task is scheduled at the moment, there could
         * be a lock for it. If task already has a lock, keep using that.
         */
        if (!task->lock) {
            node1 = ldns_rbtree_search(schedule->locks_by_name, task);
            if (!node1) {
                /* New lock, insert in tree */
                t = task_duplicate_shallow(task);
                t->lock = (pthread_mutex_t *) malloc(sizeof(pthread_mutex_t));
                if (pthread_mutex_init(t->lock, NULL)) {
                    task_destroy(t);
                    pthread_mutex_unlock(&schedule->schedule_lock);
                    return ODS_STATUS_ERR;
                }
                node1 = task2node(t);
                ods_log_assert(ldns_rbtree_insert(schedule->locks_by_name, node1));
            }
            task->lock = ((task_type*)node1->key)->lock;
        }
        /* not is schedule yet */
        node1 = task2node(task);
        node2 = task2node(task);
        if (!node1 || !node2) {
            pthread_mutex_unlock(&schedule->schedule_lock);
            free(node1);
            free(node2);
            return ODS_STATUS_ERR;
        }
        ods_log_assert(ldns_rbtree_insert(schedule->tasks, node1));
        ods_log_assert(ldns_rbtree_insert(schedule->tasks_by_name, node2));
    } else {
        if (!replace) {
            ods_log_error("[%s] unable to schedule task %s for zone %s: already present", schedule_str, task->type, task->owner);
            status = ODS_STATUS_ERR;
        } else {
            ods_log_assert(node1->key == node2->key);
            existing_task = (task_type*) node1->key;
            if (task->due_date < existing_task->due_date)
                existing_task->due_date = task->due_date;
            if (existing_task->freedata)
                existing_task->freedata(existing_task->userdata);
            existing_task->userdata = task->userdata;
            existing_task->freedata = task->freedata;
            task->userdata = NULL; /* context is now assigned to existing_task, prevent it from freeing */
            task_destroy(task);
            ods_log_assert(ldns_rbtree_insert(schedule->tasks, node1));
            ods_log_assert(ldns_rbtree_insert(schedule->tasks_by_name, node2));
            task = existing_task;
        }
    }
    if (status == ODS_STATUS_OK) {
        if (log) {
            task_log(task);
        }
    }
    pthread_cond_signal(&schedule->schedule_cond);
    pthread_mutex_unlock(&schedule->schedule_lock);
    return status;
}


/**
 * Unschedule task.
 *
 * \param[in] schedule schedule
 * \return task_type* first scheduled task, NULL on no task or error.
 */
static task_type*
unschedule_task(schedule_type* schedule, task_type* task)
{
    ldns_rbnode_t* del_node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* node2 = LDNS_RBTREE_NULL;
    task_type* del_task = NULL;
    if (!task || !schedule || !schedule->tasks) {
        return NULL;
    }
    ods_log_debug("[%s] unschedule task %s for zone %s",
        schedule_str, task->type, task->owner);

    del_node = ldns_rbtree_delete(schedule->tasks, (const void*) task);
    if (del_node) {
        del_task = (task_type*) del_node->data;
        node2 = ldns_rbtree_delete(schedule->tasks_by_name, del_task);
        if (node2 != NULL && node2 != LDNS_RBTREE_NULL) {
            free(node2);
        }
        free((void*)del_node);
        return del_task;
    } else {
        return NULL;
    }
}

task_type*
schedule_unschedule(schedule_type* schedule, task_type* task)
{
    task_type* originalTask;
    pthread_mutex_lock(&schedule->schedule_lock);
    originalTask = unschedule_task(schedule, task);
    pthread_mutex_unlock(&schedule->schedule_lock);
    return originalTask;
}

task_type*
schedule_pop_task(schedule_type* schedule)
{
    time_t timeout, now = time_now();
    task_type* task;

    pthread_mutex_lock(&schedule->schedule_lock);
    task = schedule_get_first_task(schedule);
    if (task && (task->due_date <= now)) {
        ods_log_debug("[%s] pop task for zone %s", schedule_str, task->owner);
        task = unschedule_task(schedule, task);
    } else {
        /* nothing to do now, sleep and wait for signal */
        schedule->num_waiting += 1;
        timeout = clamp((task ? (task->due_date - now) : 0),
                        ((task && !strcmp(task->class, TASK_CLASS_ENFORCER)) ? 0 : 60),
                        ODS_SE_MAX_BACKOFF);
        if (time_leaped()) timeout = -1;
        ods_thread_wait(&schedule->schedule_cond, &schedule->schedule_lock, timeout);
        schedule->num_waiting -= 1;
        task = NULL;
    }
    pthread_mutex_unlock(&schedule->schedule_lock);
    return task;
}

task_type*
schedule_pop_first_task(schedule_type* schedule)
{
    task_type *task;

    pthread_mutex_lock(&schedule->schedule_lock);
    task = pop_first_task(schedule);
    pthread_mutex_unlock(&schedule->schedule_lock);
    return task;
}

void
schedule_flush(schedule_type* schedule)
{
    ldns_rbnode_t *node;
    task_type* task;

    ods_log_debug("[%s] flush all tasks", schedule_str);
    if (!schedule || !schedule->tasks) return;

    pthread_mutex_lock(&schedule->schedule_lock);
    do {
        node = ldns_rbtree_last(schedule->tasks);
        if (node && node != LDNS_RBTREE_NULL) {
            task = (task_type*) node->data;
            if (task->due_date > time_now()) {
                /* we only need to delete the node from the tasks tree as we
                 * are immediately inserting it again.
                 */
                ldns_rbtree_delete(schedule->tasks, task);
                task->due_date = time_now();
                ldns_rbtree_insert(schedule->tasks, node);
            } else {
                /* the last in the ordered tree is already executing
                 * immediately so this means that all of them are, we can abort
                 * the loop as if we just hit the last one in the tree.
                 */
                node = NULL;
            }
        }
    } while (node && node != LDNS_RBTREE_NULL);
    pthread_cond_signal(&schedule->schedule_cond);
    pthread_mutex_unlock(&schedule->schedule_lock);
}

int
schedule_info(schedule_type* schedule, time_t* firstFireTime, int* idleWorkers, int* taskCount)
{
    task_type* task;
    if (firstFireTime) {
        *firstFireTime = -1;
    }
    if (idleWorkers) {
        *idleWorkers = 0;
    }
    if (taskCount) {
        *taskCount = 0;
    }
    if (!schedule || !schedule->tasks) {
        return -1;
    }
    pthread_mutex_lock(&schedule->schedule_lock);
    if (taskCount)
        *taskCount = schedule->tasks->count;
    if (idleWorkers) {
        *idleWorkers = schedule->num_waiting;
    }
    task = schedule_get_first_task(schedule);
    if (task)
        if (firstFireTime)
            *firstFireTime = task->due_date;
    pthread_mutex_unlock(&schedule->schedule_lock);
    return 0;
}

void
schedule_release_all(schedule_type* schedule)
{
    pthread_mutex_lock(&schedule->schedule_lock);
    pthread_cond_broadcast(&schedule->schedule_cond);
    pthread_mutex_unlock(&schedule->schedule_lock);
    fifoq_notifyall(schedule->signq);
}

void
schedule_task_destroy(schedule_type* sched, task_type* task)
{
    pthread_mutex_lock(&sched->schedule_lock);
    task = unschedule_task(sched, (task_type*) task);
    pthread_mutex_unlock(&sched->schedule_lock);
    task_destroy(task);
}

char*
schedule_describetask(task_type* task)
{
    char ctimebuf[32]; /* at least 26 according to docs */
    char* strtime = NULL;
    char* strtask = NULL;
    time_t time;

    if (!task) return NULL;
    time = (task->due_date < time_now()) ? time_now() : task->due_date;
    strtime = ctime_r(&time, ctimebuf);
    if (strtime) {
        strtime[strlen(strtime)-1] = '\0';
    } else {
        strtime = (char *)"(null)";
    }
    strtask = (char*) calloc(ODS_SE_MAXLINE, sizeof(char));
    if (strtask) {
        char const *entity = strcmp(TASK_TYPE_RESALT, task->type) ? "zone" : "policy";
        snprintf(strtask, ODS_SE_MAXLINE, "On %s I will %s %s %s\n",
            strtime, task->type, entity, task->owner);
        return strtask;
    } else {
        ods_log_error("unable to convert task to string: malloc error");
        return NULL;
    }
    return strtask;
}

int
schedule_task_istype(task_type* task, task_id type)
{
    return !strcmp(task->type, type);
}

void
schedule_registertask(schedule_type* schedule, task_id taskclass, task_id tasktype, time_t (*callback)(task_type* task, char const *owner, void *userdata, void *context))
{
    struct schedule_handler* handlers;
    handlers = realloc(schedule->handlers, sizeof(struct schedule_handler)*(schedule->nhandlers+1));
    if (handlers != NULL) {
        handlers[schedule->nhandlers].class    = taskclass;
        handlers[schedule->nhandlers].type     = tasktype;
        handlers[schedule->nhandlers].callback = callback;
        schedule->handlers = handlers;
        schedule->nhandlers += 1;
    }
}

void
schedule_scheduletask(schedule_type* schedule, task_id type, const char* owner, void* userdata, pthread_mutex_t* resource, time_t when)
{
    int i;
    task_type* task;
    struct schedule_handler* handler = NULL;
    for (i = 0; i < schedule->nhandlers; i++) {
        if (schedule->handlers[i].type == type) {
            handler = &schedule->handlers[i];
        }
    }
    if (handler) {
        task = task_create(strdup(owner), handler->class, type, handler->callback, userdata, NULL, when);
        task->lock = resource;
        schedule_task(schedule, task, 0, 0);
    }
}

void
schedule_unscheduletask(schedule_type* schedule, task_id type, const char* owner)
{
    ldns_rbnode_t* node1;
    ldns_rbnode_t* node2;
    task_type* match;
    task_type* found;
    match = task_create(owner, TASK_CLASS_SIGNER, type, NULL, NULL, NULL, schedule_WHENEVER);
    pthread_mutex_lock(&schedule->schedule_lock);
    while (fetch_node_pair(schedule, match, &node1, &node2, 0) == 0) {
        ods_log_assert(node1->key == node2->key);
        found = (task_type*) node1->key;
        unschedule_task(schedule, found);
    }
    pthread_mutex_unlock(&schedule->schedule_lock);
    free(match); /* do not perform a destroy, this is a temporary, internal, flat task only */
}
