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
#include "duration.h"
#include "log.h"

static const char* schedule_str = "scheduler";

/* Condition must be accessible from ISR */
static pthread_cond_t *schedule_cond;

static task_type* get_first_task(schedule_type *schedule);

/**
 * Interrupt service routine on SIGALRM. When caught such signal one of
 * the threads waiting for a task is notified. Unfortunately we can not
 * put the notify in a lock. When we have just a single worker thread
 * there is a rare race condition where the thread just misses this
 * event. Having multiple threads the race condition is not a problem.
 */
static void*
alarm_handler(sig_atomic_t sig)
{
    switch (sig) {
        case SIGALRM:
            ods_log_debug("[%s] SIGALRM received", schedule_str);
            /* normally a signal is locked to prevent race conditions.
             * We MUST NOT lock this. This function is called by the
             * main thread as interrupt which might have acquired
             * the lock. */
            pthread_cond_signal(schedule_cond);
            break;
        default:
            ods_log_debug("[%s] Spurious signal %d received", 
                schedule_str, (int)sig);
    }
    return NULL;
}

/**
 * Inspect head of queue and wakeup a worker now or set alarm.
 * Caller SHOULD hold schedule->schedule_lock. Failing to do so
 * could possibly cause a thread to miss the wakeup.
 */
static void
set_alarm(schedule_type* schedule)
{
    time_t now = time_now();
    task_type *task = get_first_task(schedule);
    if (!task || task->when == -1) {
        ods_log_debug("[%s] no alarm set", schedule_str);
    } else if (task->when == 0 || task->when <= now) {
        ods_log_debug("[%s] signal now", schedule_str);
        pthread_cond_signal(&schedule->schedule_cond);
    } else {
        ods_log_debug("[%s] SIGALRM set", schedule_str);
        alarm(task->when - now);
    }
}

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
get_first_task(schedule_type* schedule)
{
    ldns_rbnode_t* first_node;

    if (!schedule || !schedule->tasks) return NULL;
    first_node = ldns_rbtree_first(schedule->tasks);
    if (!first_node) return NULL;
    return (task_type*) first_node->data;
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
    set_alarm(schedule);
    return task;
}

/**
 * Internal task cleanup function.
 *
 */
static void
task_delfunc(ldns_rbnode_t* elem, int del_payload)
{
    task_type* task;

    if (elem && elem != LDNS_RBTREE_NULL) {
        task = (task_type*) elem->data;
        task_delfunc(elem->left, del_payload);
        task_delfunc(elem->right, del_payload);
        if (del_payload)
            task_cleanup(task);
        free((void*)elem);
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
    struct sigaction action;

    schedule = (schedule_type*) malloc(sizeof(schedule_type));
    if (!schedule) {
        ods_log_error("[%s] unable to create: malloc failed", schedule_str);
        return NULL;
    }

    schedule->tasks = ldns_rbtree_create(task_compare);
    schedule->tasks_by_name = ldns_rbtree_create(task_compare_name);
    pthread_mutex_init(&schedule->schedule_lock, NULL);
    pthread_cond_init(&schedule->schedule_cond, NULL);
    /* static condition for alarm. Must be accessible from interrupt */
    schedule_cond = &schedule->schedule_cond;

    action.sa_handler = (void (*)(int))&alarm_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGALRM, &action, NULL);
    
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

    /* Disable any pending alarm before we destroy the pthread stuff
     * to prevent segfaults */
    alarm(0);
    
    if (schedule->tasks) {
        task_delfunc(schedule->tasks->root, 1);
        task_delfunc(schedule->tasks_by_name->root, 1);
        ldns_rbtree_free(schedule->tasks);
        ldns_rbtree_free(schedule->tasks_by_name);
        schedule->tasks = NULL;
    }
    pthread_mutex_destroy(&schedule->schedule_lock);
    pthread_cond_destroy(&schedule->schedule_cond);
    free(schedule);
}

/**
 * exported convenience functions should all be thread safe
 */

time_t
schedule_time_first(schedule_type* schedule)
{
    task_type* task;
    time_t when;
    
    if (!schedule || !schedule->tasks) return -1;

    pthread_mutex_lock(&schedule->schedule_lock);
        task = get_first_task(schedule);
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
    if (!schedule || !schedule->tasks) return 0;
    return schedule->tasks->count;
}

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
            /*
             * TODO BUG? schedule_flush_type() sets when to zero, this does not.
             * Whos right and whos wrong?
             */
            task->flush = 1;
            node = ldns_rbtree_next(node);
        }
        /* wakeup! work to do! */
        pthread_cond_signal(&schedule->schedule_cond);
    pthread_mutex_unlock(&schedule->schedule_lock);
}

int
schedule_flush_type(schedule_type* schedule, task_id id)
{
    ldns_rbnode_t *node, *nextnode;
    int nflushed = 0;
    
    ods_log_debug("[%s] flush task", schedule_str);
    if (!schedule || !schedule->tasks) return 0;

    pthread_mutex_lock(&schedule->schedule_lock);
        node = ldns_rbtree_first(schedule->tasks);
        while (node && node != LDNS_RBTREE_NULL) {
            nextnode = ldns_rbtree_next(node);
            if (node->data && ((task_type*)node->data)->what == id) {
                /* Merely setting flush is not enough. We must set it
                 * to the front of the queue as well. */
                node = ldns_rbtree_delete(schedule->tasks, node->data);
                if (!node) break; /* stange, bail out */
                if (node->data) { /* task */
                    ((task_type*)node->data)->flush = 1;
                    if (!ldns_rbtree_insert(schedule->tasks, node)) {
                        ods_log_crit("[%s] Could not reschedule task "
                            "after flush. A task has been lost!",
                            schedule_str);
                        free(node);
                        /* Do not free node->data it is still in use
                         * by the other rbtree. */
                        break;
                    }
                    nflushed++;
                }
            }
            node = nextnode;
        }
        /* wakeup! work to do! */
        pthread_cond_signal(&schedule->schedule_cond);
    pthread_mutex_unlock(&schedule->schedule_lock);
    return nflushed;
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
            task_cleanup((task_type*) node->data);
            free(node);
        }
    pthread_mutex_unlock(&schedule->schedule_lock);
}

task_type*
schedule_pop_task(schedule_type* schedule)
{
    time_t now = time_now();
    task_type* task;

    pthread_mutex_lock(&schedule->schedule_lock);
        task = get_first_task(schedule);
        if (!task || (!task->flush && (task->when == -1 || task->when > now))) {
            /* nothing to do now, sleep and wait for signal */
            pthread_cond_wait(&schedule->schedule_cond,
                &schedule->schedule_lock);
            task = NULL;
        } else {
            task = pop_first_task(schedule);
        }
    pthread_mutex_unlock(&schedule->schedule_lock);
    return task;
}

task_type*
schedule_pop_first_task(schedule_type* schedule)
{
    task_type* task;

    pthread_mutex_lock(&schedule->schedule_lock);
        task = pop_first_task(schedule);
    pthread_mutex_unlock(&schedule->schedule_lock);
    return task;
}

ods_status
schedule_task(schedule_type* schedule, task_type* task)
{
    ldns_rbnode_t *node1, *node2;
    ods_status status;
    task_type* task2;

    if (!task) {
        ods_log_error("[%s] unable to schedule task: no task", schedule_str);
        return ODS_STATUS_ERR;
    }
    task->flush = 0;
    if (!schedule || !schedule->tasks) {
        ods_log_error("[%s] unable to schedule task: no schedule",
            schedule_str);
        return ODS_STATUS_ERR;
    }

    ods_log_debug("[%s] schedule task [%s] for %s", schedule_str,
        task_what2str(task->what), task_who2str(task->who));

    pthread_mutex_lock(&schedule->schedule_lock);
        status = ODS_STATUS_ERR;
        if ((node1 = task2node(task))) {
            if (ldns_rbtree_insert(schedule->tasks_by_name, node1)) {
                if ((node2 = task2node(task))) {
                    if(ldns_rbtree_insert(schedule->tasks, node2)) {
                        /* success inserting in two trees */
                        set_alarm(schedule);
                        status = ODS_STATUS_OK;
                    } else { /* insert in tasks tree failed */
                        ods_log_error("[%s] unable to schedule task [%s] for %s: "
                            " already present", schedule_str, task_what2str(task->what),
                            task_who2str(task->who));
                        /* this will free node1 */
                        free(ldns_rbtree_delete(schedule->tasks_by_name, node1));
                        free(node2);
                    }
                } else { /* could not alloc node2 */
                    /* this will free node1 */
                    free(ldns_rbtree_delete(schedule->tasks_by_name, node1));
                }

            } else {/* insert in name tree failed */
                free(node1);
                /**
                 * Task is already in tasks_by_name queue, so we must
                 * update it in tasks queue
                 */
                /* still in lock guaranteed to succeed. */
                node1 = ldns_rbtree_search(schedule->tasks_by_name, task);
                /* This copy of 'task' is referenced by both trees */
                task2 = (task_type*)node1->key;
                node1 = ldns_rbtree_delete(schedule->tasks, task2);
                if (task->when < task2->when)
                    task2->when = task->when;
                if (task2->context && task2->clean_context) {
                    task2->clean_context(task2);
                }
                task2->context = task->context;
                task2->clean_context = task->clean_context;
                task->context = NULL;
                task_cleanup(task);
                (void) ldns_rbtree_insert(schedule->tasks, node1);
                /* node1 now owned by tree */
                node1 = NULL;
                set_alarm(schedule);
                status = ODS_STATUS_OK;
            }
        } /* else {failure) */
    pthread_mutex_unlock(&schedule->schedule_lock);
    return status;
}

void
schedule_release_all(schedule_type* schedule)
{
    pthread_mutex_lock(&schedule->schedule_lock);
        pthread_cond_broadcast(&schedule->schedule_cond);
    pthread_mutex_unlock(&schedule->schedule_lock);
}
