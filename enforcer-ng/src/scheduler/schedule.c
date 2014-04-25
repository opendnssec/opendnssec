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

#include <ldns/ldns.h>
#include <pthread.h>
#include <signal.h>

#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "shared/duration.h"
#include "shared/log.h"

static const char* schedule_str = "scheduler";

static pthread_cond_t *schedule_cond;
static pthread_mutex_t *schedule_lock;

static void
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
                schedule_str, sig);
    }
}

static task_type* schedule_get_first_task(schedule_type *schedule);
static void
set_alarm(schedule_type* schedule)
{
    time_t now = time_now();
    task_type *task = schedule_get_first_task(schedule);
    if (!task || task->when == -1) {
        ods_log_debug("[%s] no alarm set", schedule_str);
        return;
    }
    if (task->when == 0 || task->when <= now) {
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
 * pop the first scheduled task.
 * \param[in] schedule schedule
 * \return task_type* first scheduled task
 */
static task_type*
schedule_pop_first_task(schedule_type* schedule)
{
    ldns_rbnode_t *node;
    task_type *task;

    if (!schedule || !schedule->tasks) return NULL;
    node = ldns_rbtree_first(schedule->tasks);
    if (!node) return NULL;
    node = ldns_rbtree_delete(schedule->tasks, node->data);
    if (!node) return NULL;
    task = (task_type*) node->data;
    free(node);
    set_alarm(schedule);
    return task;
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
    struct sigaction action;

    schedule = (schedule_type*) malloc(sizeof(schedule_type));
    if (!schedule) {
        ods_log_error("[%s] unable to create: malloc failed", schedule_str);
        return NULL;
    }

    schedule->tasks = ldns_rbtree_create(task_compare);
    pthread_mutex_init(&schedule->schedule_lock, NULL);
    pthread_cond_init(&schedule->schedule_cond, NULL);
    /* static condition for alarm */
    schedule_cond = &schedule->schedule_cond;
    schedule_lock = &schedule->schedule_lock;

    action.sa_handler = &alarm_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGALRM, &action, NULL);
    
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
            task->flush = 1;
            node = ldns_rbtree_next(node);
        }
        /* wakeup! work to do! */
        pthread_cond_signal(&schedule->schedule_cond);
    pthread_mutex_unlock(&schedule->schedule_lock);
}

void
schedule_flush_type(schedule_type* schedule, task_id id)
{
    ldns_rbnode_t* node;
    task_type* task;
    
    ods_log_debug("[%s] flush task", schedule_str);
    if (!schedule || !schedule->tasks) return;

    pthread_mutex_lock(&schedule->schedule_lock);
        node = ldns_rbtree_first(schedule->tasks);
        while (node && node != LDNS_RBTREE_NULL) {
            task = (task_type*) node->data;
            if (task->what == id) {
                /* we must get it to front */
                node = ldns_rbtree_delete(schedule->tasks, node->data);
                task = (task_type*) node->data;
                free(node);
                task->flush = 1;
                task->when = 0;
                if ((node = task2node(task)))
                    node = ldns_rbtree_insert(schedule->tasks, node); /*check for NULL*/
            }
            node = ldns_rbtree_next(node);
        }
        /* wakeup! work to do! */
        pthread_cond_signal(&schedule->schedule_cond);
    pthread_mutex_unlock(&schedule->schedule_lock);
}

void
schedule_purge(schedule_type* schedule)
{
    ldns_rbnode_t* node;
    task_type* task;
    
    if (!schedule || !schedule->tasks) return;

    pthread_mutex_lock(&schedule->schedule_lock);
        while ((node = ldns_rbtree_first(schedule->tasks)) !=
            LDNS_RBTREE_NULL)
        {
            node = ldns_rbtree_delete(schedule->tasks, node->data);
            task = (task_type*) node->data;
            task_cleanup(task);
            free(node);
        }
    pthread_mutex_unlock(&schedule->schedule_lock);
}

/**
 * Pop the first scheduled task.
 *
 */
task_type*
schedule_pop_task(schedule_type* schedule)
{
    time_t now = time_now();
    task_type* task;

    pthread_mutex_lock(&schedule->schedule_lock);
        task = schedule_get_first_task(schedule);
        if (!task || (!task->flush && (task->when == -1 || task->when > now))) {
            /* nothing to do now, sleep and wait for signal */
            pthread_cond_wait(&schedule->schedule_cond,
                &schedule->schedule_lock);
            task = NULL;
        } else {
            task = schedule_pop_first_task(schedule);
        }
    pthread_mutex_unlock(&schedule->schedule_lock);
    return task;
}

/**
 * Schedule task.
 *
 */
ods_status
schedule_task(schedule_type* schedule, task_type* task)
{
    ldns_rbnode_t* node;
    ods_status status = ODS_STATUS_OK;

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
        node = task2node(task);
        if (!node || ldns_rbtree_insert(schedule->tasks, node) == NULL) {
            ods_log_error("[%s] unable to schedule task [%s] for %s: "
                " already present", schedule_str, task_what2str(task->what),
                task_who2str(task->who));
            status = ODS_STATUS_ERR;
        } else {
            set_alarm(schedule);
        }
    pthread_mutex_unlock(&schedule->schedule_lock);
    return status;
}
