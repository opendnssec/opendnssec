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

#include <time.h> /* time() */

#include "daemon/engine.h"
#include "daemon/worker.h"
#include "duration.h"
#include "hsm.h"
#include "locks.h"
#include "log.h"
#include "status.h"
#include "signer/tools.h"
#include "signer/zone.h"

/**
 * Create worker.
 *
 */
worker_type*
worker_create(char* name)
{
    worker_type* worker;
    CHECKALLOC(worker = (worker_type*) malloc(sizeof(worker_type)));
    ods_log_debug("[%s] create", name);
    lock_basic_init(&worker->worker_lock);
    lock_basic_set(&worker->worker_alarm);
    lock_basic_lock(&worker->worker_lock);
    worker->name = name;
    worker->engine = NULL;
    worker->task = NULL;
    worker->working_with = TASK_NONE;
    worker->need_to_exit = 0;
    worker->clock_in = 0;
    worker->jobs_appointed = 0;
    worker->jobs_completed = 0;
    worker->jobs_failed = 0;
    worker->sleeping = 0;
    worker->waiting = 0;
    lock_basic_unlock(&worker->worker_lock);
    return worker;
}


/**
 * Worker working with...
 *
 */
static void
worker_working_with(worker_type* worker, task_id with, task_id next,
    const char* str, const char* name, task_id* what, time_t* when)
{
    worker->working_with = with;
    ods_log_verbose("[%s] %s zone %s", worker->name, str, name);
    *what = next;
    *when = time_now();
}


/**
 * Has this worker measured up to all appointed jobs?
 *
 */
static int
worker_fulfilled(worker_type* worker)
{
    int ret = 0;
    ret = (worker->jobs_completed + worker->jobs_failed) ==
        worker->jobs_appointed;
    return ret;
}


/**
 * Clear jobs.
 *
 */
static void
worker_clear_jobs(worker_type* worker)
{
    ods_log_assert(worker);
    lock_basic_lock(&worker->worker_lock);
    worker->jobs_appointed = 0;
    worker->jobs_completed = 0;
    worker->jobs_failed = 0;
    lock_basic_unlock(&worker->worker_lock);
}


/**
 * Queue RRset for signing.
 *
 */
static void
worker_queue_rrset(worker_type* worker, fifoq_type* q, rrset_type* rrset)
{
    ods_status status = ODS_STATUS_UNCHANGED;
    int tries = 0;
    ods_log_assert(worker);
    ods_log_assert(worker->task);
    ods_log_assert(q);
    ods_log_assert(rrset);

    lock_basic_lock(&q->q_lock);
    status = fifoq_push(q, (void*) rrset, worker, &tries);
    while (status == ODS_STATUS_UNCHANGED) {
        tries++;
        if (worker->need_to_exit) {
            lock_basic_unlock(&q->q_lock);
            return;
        }
        /**
         * Apparently the queue is full. Lets take a small break to not hog CPU.
         * The worker will release the signq lock while sleeping and will
         * automatically grab the lock when the queue is nonfull.
         * Queue is nonfull at 10% of the queue size.
         */
        lock_basic_sleep(&q->q_nonfull, &q->q_lock, 5);
        status = fifoq_push(q, (void*) rrset, worker, &tries);
    }
    lock_basic_unlock(&q->q_lock);

    ods_log_assert(status == ODS_STATUS_OK);
    lock_basic_lock(&worker->worker_lock);
    worker->jobs_appointed += 1;
    lock_basic_unlock(&worker->worker_lock);
}


/**
 * Queue domain for signing.
 *
 */
static void
worker_queue_domain(worker_type* worker, fifoq_type* q, domain_type* domain)
{
    rrset_type* rrset = NULL;
    denial_type* denial = NULL;
    ods_log_assert(worker);
    ods_log_assert(q);
    ods_log_assert(domain);
    rrset = domain->rrsets;
    while (rrset) {
        worker_queue_rrset(worker, q, rrset);
        rrset = rrset->next;
}
    denial = (denial_type*) domain->denial;
    if (denial && denial->rrset) {
        worker_queue_rrset(worker, q, denial->rrset);
    }
}


/**
 * Queue zone for signing.
 *
 */
static void
worker_queue_zone(worker_type* worker, fifoq_type* q, zone_type* zone)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    ods_log_assert(worker);
    ods_log_assert(q);
    ods_log_assert(zone);
    worker_clear_jobs(worker);
    if (!zone->db || !zone->db->domains) {
        return;
    }
    if (zone->db->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zone->db->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        worker_queue_domain(worker, q, domain);
        node = ldns_rbtree_next(node);
    }
}


/**
 * Make sure that no appointed jobs have failed.
 *
 */
static ods_status
worker_check_jobs(worker_type* worker, task_type* task)
{
    ods_log_assert(worker);
    ods_log_assert(task);
    lock_basic_lock(&worker->worker_lock);
    if (worker->jobs_failed) {
        ods_log_error("[%s] sign zone %s failed: %lu RRsets failed",
            worker->name, task_who2str(task), (unsigned long)worker->jobs_failed);
        lock_basic_unlock(&worker->worker_lock);
        return ODS_STATUS_ERR;
    } else if (worker->jobs_completed != worker->jobs_appointed) {
        ods_log_error("[%s] sign zone %s failed: processed %lu of %lu "
            "RRsets", worker->name, task_who2str(task), (unsigned long)worker->jobs_completed,
            (unsigned long)worker->jobs_appointed);
        lock_basic_unlock(&worker->worker_lock);
        return ODS_STATUS_ERR;
    } else if (worker->need_to_exit) {
        ods_log_debug("[%s] sign zone %s failed: worker needs to exit",
            worker->name, task_who2str(task));
        lock_basic_unlock(&worker->worker_lock);
        return ODS_STATUS_ERR;
    } else {
        ods_log_debug("[%s] sign zone %s ok: %lu of %lu RRsets "
            "succeeded", worker->name,
            task_who2str(task), (unsigned long)worker->jobs_completed,
            (unsigned long)worker->jobs_appointed);
        ods_log_assert(worker->jobs_appointed == worker->jobs_completed);
    }
    lock_basic_unlock(&worker->worker_lock);
    return ODS_STATUS_OK;
}


/**
 * Perform task.
 *
 */
static void
worker_perform_task(worker_type* worker)
{
    engine_type* engine = NULL;
    zone_type* zone = NULL;
    task_type* task = NULL;
    task_id what = TASK_NONE;
    time_t when = 0;
    time_t never = (3600*24*365);
    ods_status status = ODS_STATUS_OK;
    int backup = 0;
    time_t start = 0;
    time_t end = 0;

    if (!worker || !worker->task || !worker->task->zone || !worker->engine) {
        return;
    }
    engine = worker->engine;
    task = (task_type*) worker->task;
    zone = (zone_type*) worker->task->zone;
    ods_log_debug("[%s] perform task %s for zone %s",
       worker->name, task_what2str(task->what), task_who2str(task));
    /* do what you have been told to do */
    switch (task->what) {
        case TASK_SIGNCONF:
            /* perform 'load signconf' task */
            worker_working_with(worker, TASK_SIGNCONF, TASK_READ,
                "configure", task_who2str(task), &what, &when);
            status = tools_signconf(zone);
            if (status == ODS_STATUS_UNCHANGED) {
                if (!zone->signconf->last_modified) {
                    ods_log_debug("[%s] no signconf.xml for zone %s yet",
                        worker->name, task_who2str(task));
                    status = ODS_STATUS_ERR;
                }
            }
            if (status == ODS_STATUS_UNCHANGED) {
                if (task->halted != TASK_NONE && task->halted != TASK_SIGNCONF) {
                    goto task_perform_continue;
                }
                status = ODS_STATUS_OK;
            } else if (status == ODS_STATUS_OK) {
                task->interrupt = TASK_NONE;
                task->halted = TASK_NONE;
            } else {
                if (task->halted == TASK_NONE) {
                    goto task_perform_fail;
                }
                goto task_perform_continue;
            }
            /* break; */
        case TASK_READ:
            /* perform 'read input adapter' task */
            worker_working_with(worker, TASK_READ, TASK_SIGN,
                "read", task_who2str(task), &what, &when);
            task->what = TASK_READ;
            if (!zone->signconf->last_modified) {
                ods_log_debug("[%s] no signconf.xml for zone %s yet",
                    worker->name, task_who2str(task));
                status = ODS_STATUS_ERR;
            } else {
                if (hsm_check_context()) {
                    ods_log_error("signer instructed to reload due to hsm reset in read task");
                    engine->need_to_reload = 1;
                    status = ODS_STATUS_ERR;
                } else {
                    status = tools_input(zone);
                }
            }

            if (status == ODS_STATUS_UNCHANGED) {
                ods_log_verbose("[%s] zone %s unsigned data not changed, "
                    "continue", worker->name, task_who2str(task));
                status = ODS_STATUS_OK;
            }
            if (status == ODS_STATUS_OK) {
                if (task->interrupt > TASK_SIGNCONF) {
                    task->interrupt = TASK_NONE;
                    task->halted = TASK_NONE;
                }
            } else {
                if (task->halted == TASK_NONE) {
                    goto task_perform_fail;
                }
                goto task_perform_continue;
            }
            /* break; */
        case TASK_SIGN:
            /* perform 'sign' task */
            worker_working_with(worker, TASK_SIGN, TASK_WRITE,
                "sign", task_who2str(task), &what, &when);
            task->what = TASK_SIGN;
            status = zone_update_serial(zone);
            if (status == ODS_STATUS_OK) {
                if (task->interrupt > TASK_SIGNCONF) {
                    task->interrupt = TASK_NONE;
                    task->halted = TASK_NONE;
                }
            } else {
                ods_log_error("[%s] unable to sign zone %s: "
                    "failed to increment serial",
                    worker->name, task_who2str(task));
                if (task->halted == TASK_NONE) {
                    goto task_perform_fail;
                }
                goto task_perform_continue;
            }

            /* start timer */
            start = time(NULL);
            if (zone->stats) {
                lock_basic_lock(&zone->stats->stats_lock);
                if (!zone->stats->start_time) {
                    zone->stats->start_time = start;
                }
                zone->stats->sig_count = 0;
                zone->stats->sig_soa_count = 0;
                zone->stats->sig_reuse = 0;
                zone->stats->sig_time = 0;
                lock_basic_unlock(&zone->stats->stats_lock);
            }
            /* check the HSM connection before queuing sign operations */
            if (hsm_check_context()) {
                ods_log_error("signer instructed to reload due to hsm reset in sign task");
                engine->need_to_reload = 1;
                goto task_perform_fail;
            }
            /* prepare keys */
            status = zone_prepare_keys(zone);
            if (status == ODS_STATUS_OK) {
                /* queue menial, hard signing work */
                worker_queue_zone(worker, engine->signq, zone);
                ods_log_deeebug("[%s] wait until drudgers are finished "
                    "signing zone %s", worker->name, task_who2str(task));
                /* sleep until work is done */
                worker_sleep_unless(worker, 0);
            }
            /* stop timer */
            end = time(NULL);
            /* check status and jobs */
            if (status == ODS_STATUS_OK) {
                status = worker_check_jobs(worker, task);
            }
            worker_clear_jobs(worker);
            if (status == ODS_STATUS_OK && zone->stats) {
                lock_basic_lock(&zone->stats->stats_lock);
                zone->stats->sig_time = (end-start);
                lock_basic_unlock(&zone->stats->stats_lock);
            }
            if (status != ODS_STATUS_OK) {
                if (task->halted == TASK_NONE) {
                    goto task_perform_fail;
                }
                goto task_perform_continue;
            } else {
                if (task->interrupt > TASK_SIGNCONF) {
                    task->interrupt = TASK_NONE;
                    task->halted = TASK_NONE;
                }
            }
            /* break; */
        case TASK_WRITE:
            /* perform 'write to output adapter' task */
            worker_working_with(worker, TASK_WRITE, TASK_SIGN,
                "write", task_who2str(task), &what, &when);
            task->what = TASK_WRITE;
            status = tools_output(zone, engine);
            if (status == ODS_STATUS_OK) {
                if (task->interrupt > TASK_SIGNCONF) {
                    task->interrupt = TASK_NONE;
                    task->halted = TASK_NONE;
                }
            } else {
                /* clear signatures? */
                if (task->halted == TASK_NONE) {
                    goto task_perform_fail;
                }
                goto task_perform_continue;
            }
            zone->db->is_processed = 1;
            if (zone->signconf &&
                duration2time(zone->signconf->sig_resign_interval)) {
                what = TASK_SIGN;
                when = worker->clock_in +
                    duration2time(zone->signconf->sig_resign_interval);
            } else {
                ods_log_error("[%s] unable to retrieve resign interval "
                    "for zone %s: duration2time() failed",
                    worker->name, task_who2str(task));
                ods_log_info("[%s] defaulting to 1H resign interval for "
                    "zone %s", worker->name, task_who2str(task));
                what = TASK_SIGN;
                when = worker->clock_in + 3600;
            }
            backup = 1;
            break;
        case TASK_NONE:
            worker->working_with = TASK_NONE;
            /* no task */
            ods_log_warning("[%s] none task for zone %s",
                worker->name, task_who2str(task));
            when = time_now() + never;
            break;
        default:
            worker->working_with = TASK_NONE;
            /* unknown task */
            ods_log_warning("[%s] unknown task, trying full sign zone %s",
                worker->name, task_who2str(task));
            what = TASK_SIGNCONF;
            when = time_now();
            break;
    }
    /* no error */
    task->backoff = 0;
    if (task->interrupt != TASK_NONE && task->interrupt != what) {
        ods_log_debug("[%s] interrupt task %s for zone %s",
            worker->name, task_what2str(what), task_who2str(task));
        task->halted = what;
        task->halted_when = when;
        task->what = task->interrupt;
        task->when = time_now();
    } else {
        ods_log_debug("[%s] next task %s for zone %s",
            worker->name, task_what2str(what), task_who2str(task));
        task->what = what;
        task->when = when;
        task->interrupt = TASK_NONE;
        task->halted = TASK_NONE;
        task->halted_when = 0;
    }
    /* backup the last successful run */
    if (backup) {
        status = zone_backup2(zone);
        if (status != ODS_STATUS_OK) {
            ods_log_warning("[%s] unable to backup zone %s: %s",
            worker->name, task_who2str(task), ods_status2str(status));
            /* just a warning */
            status = ODS_STATUS_OK;
        }
        backup = 0;
    }
    return;

task_perform_fail:
    if (!zone->signconf->last_modified) {
        ods_log_warning("[%s] WARNING: unable to sign zone %s, signconf is not ready", worker->name, task_who2str(task));
    } else if (status != ODS_STATUS_XFR_NOT_READY) {
        /* other statuses is critical, and we know it is not ODS_STATUS_OK */
        ods_log_crit("[%s] CRITICAL: failed to sign zone %s: %s",
            worker->name, task_who2str(task), ods_status2str(status));
    }
    /* in case of failure, also mark zone processed (for single run usage) */
    zone->db->is_processed = 1;
    if (task->backoff) {
        task->backoff *= 2;
    } else {
        task->backoff = 60;
    }
    if (task->backoff > ODS_SE_MAX_BACKOFF) {
        task->backoff = ODS_SE_MAX_BACKOFF;
    }
    ods_log_info("[%s] backoff task %s for zone %s with %lu seconds",
        worker->name, task_what2str(task->what), task_who2str(task), (long)task->backoff);
    task->when = time_now() + task->backoff;
    return;

task_perform_continue:
    ods_log_info("[%s] continue task %s for zone %s",
        worker->name, task_what2str(task->halted), task_who2str(task));
    task->what = task->halted;
    task->when = task->halted_when;
    task->interrupt = TASK_NONE;
    task->halted = TASK_NONE;
    task->halted_when = 0;
    return;
}


/**
 * Work.
 *
 */
void
worker_work(worker_type* worker)
{
    time_t now = 0;
    time_t timeout = 1;
    engine_type* engine = NULL;
    zone_type* zone = NULL;
    ods_status status = ODS_STATUS_OK;

    ods_log_assert(worker);

    engine = worker->engine;
    while (worker->need_to_exit == 0) {
        ods_log_debug("[%s] report for duty", worker->name);
        now = time_now();
        lock_basic_lock(&engine->taskq->schedule_lock);
        worker->task = schedule_pop_task(engine->taskq);
        if (worker->task) {
            worker->working_with = worker->task->what;
            lock_basic_unlock(&engine->taskq->schedule_lock);
            zone = (zone_type*) worker->task->zone;

            lock_basic_lock(&zone->zone_lock);
            ods_log_debug("[%s] start working on zone %s",
                worker->name, zone->name);
            worker->clock_in = time_now();
            worker_perform_task(worker);
            zone->task = worker->task;
            ods_log_debug("[%s] finished working on zone %s",
                worker->name, zone->name);

            lock_basic_lock(&engine->taskq->schedule_lock);
            worker->task = NULL;
            worker->working_with = TASK_NONE;
            status = schedule_task(engine->taskq, zone->task, 1);
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to schedule task for zone %s: "
                "%s", worker->name, zone->name, ods_status2str(status));
            }
            lock_basic_unlock(&engine->taskq->schedule_lock);
            lock_basic_unlock(&zone->zone_lock);
            timeout = 1;
            /** Do we need to tell the engine that we require a reload? */
            lock_basic_lock(&engine->signal_lock);
            if (engine->need_to_reload) {
                lock_basic_alarm(&engine->signal_cond);
            }
            lock_basic_unlock(&engine->signal_lock);

        } else {
            ods_log_debug("[%s] nothing to do", worker->name);
            worker->task = schedule_get_first_task(engine->taskq);
            lock_basic_unlock(&engine->taskq->schedule_lock);
            if (worker->task && !engine->taskq->loading) {
                timeout = (worker->task->when - now);
            } else {
                timeout *= 2;
            }
            if (timeout > ODS_SE_MAX_BACKOFF) {
                timeout = ODS_SE_MAX_BACKOFF;
            }
            worker->task = NULL;
            worker_sleep(worker, timeout);
        }
    }
}


/**
 * Drudge.
 *
 */
void
worker_drudge(worker_type* worker)
{
    engine_type* engine = NULL;
    zone_type* zone = NULL;
    task_type* task = NULL;
    rrset_type* rrset = NULL;
    ods_status status = ODS_STATUS_OK;
    worker_type* superior = NULL;
    hsm_ctx_t* ctx = NULL;

    ods_log_assert(worker);
    ods_log_assert(worker->engine);

    engine = worker->engine;
    while (worker->need_to_exit == 0) {
        ods_log_deeebug("[%s] report for duty", worker->name);
        superior = NULL;
        zone = NULL;
        task = NULL;
        /* get item */
        lock_basic_lock(&engine->signq->q_lock);
        rrset = (rrset_type*) fifoq_pop(engine->signq, &superior);
        if (!rrset) {
            ods_log_deeebug("[%s] nothing to do, wait", worker->name);
            /**
             * Apparently the queue is empty. Wait until new work is queued.
             * The drudger will release the signq lock while sleeping and
             * will automatically grab the lock when the threshold is reached.
             * Threshold is at 1 and MAX (after a number of tries).
             */
            lock_basic_sleep(&engine->signq->q_threshold,
                &engine->signq->q_lock, 0);
            if(worker->need_to_exit == 0)
                rrset = (rrset_type*) fifoq_pop(engine->signq, &superior);
        }
        lock_basic_unlock(&engine->signq->q_lock);
        /* do some work */
        if (rrset) {
            ods_log_assert(superior);
            if (!ctx) {
                ods_log_debug("[%s] create hsm context", worker->name);
                ctx = hsm_create_context();
            }
            if (!ctx) {
                ods_log_crit("[%s] error creating libhsm context", worker->name);
                engine->need_to_reload = 1;
                ods_log_error("signer instructed to reload due to hsm reset while signing");
                lock_basic_lock(&superior->worker_lock);
                superior->jobs_failed++;
                lock_basic_unlock(&superior->worker_lock);
            } else {
                ods_log_assert(ctx);
                lock_basic_lock(&superior->worker_lock);
                task = superior->task;
                ods_log_assert(task);
                zone = task->zone;
                lock_basic_unlock(&superior->worker_lock);
                ods_log_assert(zone);
                ods_log_assert(zone->apex);
                ods_log_assert(zone->signconf);
                worker->clock_in = time_now();
                status = rrset_sign(ctx, rrset, superior->clock_in);
                lock_basic_lock(&superior->worker_lock);
                if (status == ODS_STATUS_OK) {
                    superior->jobs_completed++;
                } else {
                    superior->jobs_failed++;
                }
                lock_basic_unlock(&superior->worker_lock);
            }
            if (worker_fulfilled(superior) && superior->sleeping) {
                ods_log_deeebug("[%s] wake up superior[%s], work is "
                    "done", worker->name, superior->name);
                worker_wakeup(superior);
            }
            superior = NULL;
            rrset = NULL;
        }
        /* done work */
    }
    /* cleanup open HSM sessions */
    if (ctx) {
        hsm_destroy_context(ctx);
    }
}

/**
 * Put worker to sleep.
 *
 */
void
worker_sleep(worker_type* worker, time_t timeout)
{
    ods_log_assert(worker);
    if (!worker->need_to_exit) {
        lock_basic_lock(&worker->worker_lock);
        worker->sleeping = 1;
        lock_basic_sleep(&worker->worker_alarm, &worker->worker_lock,
            timeout);
        lock_basic_unlock(&worker->worker_lock);
    }
}


/**
 * Put worker to sleep unless worker has measured up to all appointed jobs.
 *
 */
void
worker_sleep_unless(worker_type* worker, time_t timeout)
{
    ods_log_assert(worker);
    lock_basic_lock(&worker->worker_lock);
    while (!worker->need_to_exit && !worker_fulfilled(worker)) {
        worker->sleeping = 1;
        lock_basic_sleep(&worker->worker_alarm, &worker->worker_lock,
            timeout);
        ods_log_debug("[%s] somebody poked me, check completed jobs %lu "
           "appointed, %lu completed, %lu failed", worker->name,
           (long)worker->jobs_appointed, (long)worker->jobs_completed,
           (long)worker->jobs_failed);
    }
    lock_basic_unlock(&worker->worker_lock);
}


/**
 * Wake up worker.
 *
 */
void
worker_wakeup(worker_type* worker)
{
    ods_log_assert(worker);
    if (worker && worker->sleeping && !worker->waiting) {
        ods_log_debug("[%s] wake up", worker->name);
        lock_basic_lock(&worker->worker_lock);
        lock_basic_alarm(&worker->worker_alarm);
        worker->sleeping = 0;
        lock_basic_unlock(&worker->worker_lock);
    }
}


/**
 * Notify all workers.
 *
 */
void
worker_notify_all(lock_basic_type* lock, cond_basic_type* condition)
{
    lock_basic_lock(lock);
    lock_basic_broadcast(condition);
    lock_basic_unlock(lock);
}


/**
 * Clean up worker.
 *
 */
void
worker_cleanup(worker_type* worker)
{
    if (!worker) {
        return;
    }
    lock_basic_destroy(&worker->worker_lock);
    lock_basic_off(&worker->worker_alarm);
    free(worker);
}
