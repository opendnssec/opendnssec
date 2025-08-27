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
#include "scheduler/worker.h"
#include "scheduler/schedule.h"
#include "signertasks.h"
#include "duration.h"
#include "hsm.h"
#include "locks.h"
#include "util.h"
#include "log.h"
#include "status.h"
#include "signer/tools.h"
#include "signer/zone.h"
#include "util.h"
#include "signertasks.h"

/**
 * Queue RRset for signing.
 *
 */
static void
worker_queue_rrset(struct worker_context* context, fifoq_type* q, rrset_type* rrset, long* nsubtasks)
{
    ods_status status = ODS_STATUS_UNCHANGED;
    int tries = 0;
    ods_log_assert(q);
    ods_log_assert(rrset);

    pthread_mutex_lock(&q->q_lock);
    status = fifoq_push(q, (void*) rrset, context, &tries);
    while (status == ODS_STATUS_UNCHANGED) {
        tries++;
        if (context->worker->need_to_exit) {
            pthread_mutex_unlock(&q->q_lock);
            return;
        }
        /**
         * Apparently the queue is full. Lets take a small break to not hog CPU.
         * The worker will release the signq lock while sleeping and will
         * automatically grab the lock when the queue is nonfull.
         * Queue is nonfull at 10% of the queue size.
         */
        ods_thread_wait(&q->q_nonfull, &q->q_lock, 5);
        status = fifoq_push(q, (void*) rrset, context, &tries);
    }
    pthread_mutex_unlock(&q->q_lock);

    ods_log_assert(status == ODS_STATUS_OK);
    *nsubtasks += 1;
}


/**
 * Queue domain for signing.
 *
 */
static void
worker_queue_domain(struct worker_context* context, fifoq_type* q, domain_type* domain, long* nsubtasks)
{
    rrset_type* rrset = NULL;
    denial_type* denial = NULL;
    ods_log_assert(context);
    ods_log_assert(q);
    ods_log_assert(domain);
    rrset = domain->rrsets;
    while (rrset) {
        if (rrset->rrtype != LDNS_RR_TYPE_ZONEMD) {
            worker_queue_rrset(context, q, rrset, nsubtasks);
        }
        rrset = rrset->next;
    }
    denial = (denial_type*) domain->denial;
    if (denial && denial->rrset) {
        worker_queue_rrset(context, q, denial->rrset, nsubtasks);
    }
}


/**
 * Queue zone for signing.
 *
 */
static void
worker_queue_zone(struct worker_context* context, fifoq_type* q, zone_type* zone, long* nsubtasks)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    ods_log_assert(context);
    ods_log_assert(q);
    ods_log_assert(zone);
    if (!zone->db || !zone->db->domains) {
        return;
    }
    if (zone->db->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zone->db->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        worker_queue_domain(context, q, domain, nsubtasks);
        node = ldns_rbtree_next(node);
    }
}


/**
 * Make sure that no appointed jobs have failed.
 *
 */
static ods_status
worker_check_jobs(worker_type* worker, task_type* task, int ntasks, long ntasksfailed)
{
    ods_log_assert(worker);
    ods_log_assert(task);
    if (ntasksfailed) {
        ods_log_error("[%s] sign zone %s failed: %ld RRsets failed",
            worker->name, task->owner, ntasksfailed);
        return ODS_STATUS_ERR;
    } else if (worker->need_to_exit) {
        ods_log_error("[%s] sign zone %s failed: worker needs to exit",
            worker->name, task->owner);
        return ODS_STATUS_ERR;
    }
    return ODS_STATUS_OK;
}

void
drudge(worker_type* worker)
{
    rrset_type* rrset;
    ods_status status;
    struct worker_context* superior;
    hsm_ctx_t* ctx = NULL;
    engine_type* engine;
    fifoq_type* signq = worker->taskq->signq;

    while (worker->need_to_exit == 0) {
        ods_log_deeebug("[%s] report for duty", worker->name);
        pthread_mutex_lock(&signq->q_lock);
        superior = NULL;
        rrset = (rrset_type*) fifoq_pop(signq, (void**)&superior);
        if (!rrset) {
            ods_log_deeebug("[%s] nothing to do, wait", worker->name);
            /**
             * Apparently the queue is empty. Wait until new work is queued.
             * The drudger will release the signq lock while sleeping and
             * will automatically grab the lock when the threshold is reached.
             * Threshold is at 1 and MAX (after a number of tries).
             */
            pthread_cond_wait(&signq->q_threshold, &signq->q_lock);
            if(worker->need_to_exit == 0)
                rrset = (rrset_type*) fifoq_pop(signq, (void**)&superior);
        }
        pthread_mutex_unlock(&signq->q_lock);
        /* do some work */
        if (rrset) {
            ods_log_assert(superior);
            if (!ctx) {
                ods_log_debug("[%s] create hsm context", worker->name);
                ctx = hsm_create_context();
            }
            if (!ctx) {
                engine = superior->engine;
                ods_log_crit("[%s] error creating libhsm context", worker->name);
                engine->need_to_reload = 1;
                pthread_mutex_lock(&engine->signal_lock);
                pthread_cond_signal(&engine->signal_cond);
                pthread_mutex_unlock(&engine->signal_lock);
                ods_log_error("signer instructed to reload due to hsm reset while signing");
                status = ODS_STATUS_HSM_ERR;
            } else {
                status = rrset_sign(ctx, rrset, superior->clock_in);
            }
            fifoq_report(signq, superior->worker, status);
        }
        /* done work */
    }
    /* cleanup open HSM sessions */
    if (ctx) {
        hsm_destroy_context(ctx);
    }
}

time_t
do_readsignconf(task_type* task, const char* zonename, void* zonearg, void *contextarg)
{
    struct worker_context* context = contextarg;
    engine_type* engine = context->engine;
    zone_type* zone = zonearg;
    ods_status status;
    status = tools_signconf(zone);
    if (status == ODS_STATUS_UNCHANGED && !zone->signconf->last_modified) {
        ods_log_debug("No signconf.xml for zone %s yet", task->owner);
        status = ODS_STATUS_ERR;
        zone->zoneconfigvalid = 0;
    }
    if (status == ODS_STATUS_OK || status == ODS_STATUS_UNCHANGED) {
        /* status unchanged not really possible */
        schedule_unscheduletask(engine->taskq, TASK_READ, zone->name);
        schedule_scheduletask(engine->taskq, TASK_READ, zone->name, zone, &zone->zone_lock, schedule_PROMPTLY);
        zone->zoneconfigvalid = 1;
        return schedule_SUCCESS;
    } else {
        zone->zoneconfigvalid = 0;
        if (!zone->signconf->last_modified) {
            ods_log_warning("WARNING: unable to sign zone %s, signconf is not ready", task->owner);
        } else {
            ods_log_crit("CRITICAL: failed to sign zone %s: %s", task->owner, ods_status2str(status));
        }
        return schedule_DEFER;
    }
}

time_t
do_forcereadsignconf(task_type* task, const char* zonename, void* zonearg, void *contextarg)
{
    struct worker_context* context = contextarg;
    engine_type* engine = context->engine;
    zone_type* zone = zonearg;
    ods_status status;
    /* perform 'load signconf' task */
    status = tools_signconf(zone);
    if (status == ODS_STATUS_UNCHANGED) {
        schedule_unscheduletask(engine->taskq, TASK_SIGNCONF, zone->name);
        if(!zone->zoneconfigvalid) {
            zone->zoneconfigvalid = 1;
            schedule_unscheduletask(engine->taskq, TASK_READ, zone->name);
            schedule_scheduletask(engine->taskq, TASK_READ, zone->name, zone, &zone->zone_lock, schedule_PROMPTLY);
        }
        return schedule_SUCCESS;
    } else if (status == ODS_STATUS_OK) {
        schedule_unscheduletask(engine->taskq, TASK_SIGNCONF, zone->name);
        schedule_unscheduletask(engine->taskq, TASK_READ, zone->name);
        schedule_unscheduletask(engine->taskq, TASK_SIGN, zone->name);
        schedule_unscheduletask(engine->taskq, TASK_WRITE, zone->name);
        schedule_scheduletask(engine->taskq, TASK_READ, zone->name, zone, &zone->zone_lock, schedule_PROMPTLY);
        return schedule_SUCCESS;
    } else {
        return schedule_SUCCESS;
    }
}

static void
zonemdinitialize(struct worker_context* context, zone_type* zone, rrset_type** zonemdrr)
{
    *zonemdrr = zone_lookup_rrset(zone, zone->apex, LDNS_RR_TYPE_ZONEMD);
    if(*zonemdrr) {
        for(int i=0; i<(*zonemdrr)->rr_count; i++) {
            ldns_rdf* oldserial;
            oldserial = ldns_rr_set_rdf((*zonemdrr)->rrs[i].rr, ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, zone->db->intserial), 0);
            if (oldserial)
                ldns_rdf_deep_free(oldserial);
        }
    } else if (zone->signconf->zonemodus & 0x06) {
        ldns_rr* soa = zone_lookup_rrset(zone, zone->apex, LDNS_RR_TYPE_SOA)->rrs[0].rr;
        if(zone->signconf->zonemodus & 0x02) {
            ldns_rr* rr = ldns_rr_new_frm_type(LDNS_RR_TYPE_ZONEMD);
            ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
            ldns_rr_set_owner(rr, ldns_rdf_clone(ldns_rr_owner(soa)));
            ldns_rr_set_rdf(rr, ldns_rdf_clone(ldns_rr_rdf(soa, 2)), 0);
            ldns_rr_set_rdf(rr, ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, 1), 1);
            ldns_rr_set_rdf(rr, ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, 1), 2);
            ldns_rr_set_rdf(rr, ldns_rdf_new(LDNS_RDF_TYPE_HEX, LDNS_SHA384_DIGEST_LENGTH, LDNS_XMALLOC(uint8_t, LDNS_SHA384_DIGEST_LENGTH)), 3);
            zone_add_rr(zone, rr, 1);
        }
        if(zone->signconf->zonemodus & 0x04) {
            ldns_rr* rr = ldns_rr_new_frm_type(LDNS_RR_TYPE_ZONEMD);
            ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
            ldns_rr_set_owner(rr, ldns_rdf_clone(ldns_rr_owner(soa)));
            ldns_rr_set_rdf(rr, ldns_rdf_clone(ldns_rr_rdf(soa, 2)), 0);
            ldns_rr_set_rdf(rr, ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, 1), 1);
            ldns_rr_set_rdf(rr, ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, 2), 2);
            ldns_rr_set_rdf(rr, ldns_rdf_new(LDNS_RDF_TYPE_HEX, LDNS_SHA512_DIGEST_LENGTH, LDNS_XMALLOC(uint8_t, LDNS_SHA512_DIGEST_LENGTH)), 3);
            zone_add_rr(zone, rr, 1);
        }
        *zonemdrr = zone_lookup_rrset(zone, zone->apex, LDNS_RR_TYPE_ZONEMD);
        for(int i=0; i<(*zonemdrr)->rr_count; i++) {
            (*zonemdrr)->rrs[i].exists = 1;
        }
    }
}

static void
worker_zonemdrrset(rrset_type* rrset, ldns_sha512_CTX* sha384ctx, ldns_sha512_CTX* sha512ctx)
{
    uint8_t data[65536];
    ldns_buffer buf;
    ldns_status status;
    ldns_rr_list* list;
    ldns_rr* rr;

    buf._data = data;
    buf._position = 0;
    buf._limit = sizeof(data);
    buf._capacity = sizeof(data);
    buf._fixed = 0;
    buf._status = LDNS_STATUS_OK;

    list = ldns_rr_list_new();
    for(int i=0; i<rrset->rr_count; i++) {
        ldns_rr_list_push_rr(list, rrset->rrs[i].rr);
    }
    ldns_rr_list_sort(list);
    while((rr = ldns_rr_list_pop_rr(list))) {
        status = ldns_rr2buffer_wire_canonical(&buf, rr, LDNS_SECTION_ANSWER);
        assert(!status);
        if(sha384ctx)
            ldns_sha512_update(sha384ctx, data, buf._position);
        if(sha512ctx)
            ldns_sha512_update(sha512ctx, data, buf._position);
    }
    ldns_rr_list_free(list);
}

static void
zomemdprocess(struct worker_context* context, zone_type* zone, rrset_type* zonemdrr)
{
    ldns_rbnode_t* node1 = LDNS_RBTREE_NULL;
    ldns_rbnode_t* node2 = LDNS_RBTREE_NULL;
    domain_type* domain;
    denial_type* denial;
    rrset_type* rrsets;
    ldns_sha384_CTX sha384ctx;
    ldns_sha512_CTX sha512ctx;
    uint8_t sha384value[LDNS_SHA384_DIGEST_LENGTH];
    uint8_t sha512value[LDNS_SHA512_DIGEST_LENGTH];
    ldns_rr* sha384rr = NULL;
    ldns_rr* sha512rr = NULL;

    for(int i=0; i<zonemdrr->rr_count; i++) {
        ldns_rdf* rdf = ldns_rr_rdf(zonemdrr->rrs[i].rr, 2);
        switch(ldns_rdf2native_int8(rdf)) {
            case 1:
                sha384rr = zonemdrr->rrs[i].rr;
                break;
            case 2:
                sha512rr = zonemdrr->rrs[i].rr;
                break;
        }
    }
    
    if (zone->db->domains->root != LDNS_RBTREE_NULL) {
        node1 = ldns_rbtree_first(zone->db->domains);
    }
    if (zone->db->denials->root != LDNS_RBTREE_NULL) {
        node2 = ldns_rbtree_first(zone->db->denials);
    }
    ldns_sha384_init(&sha384ctx);
    ldns_sha512_init(&sha512ctx);
    while ((node1 && node1 != LDNS_RBTREE_NULL) || (node2 && node2 != LDNS_RBTREE_NULL)) {
        domain = ((node1 && node1 != LDNS_RBTREE_NULL) ? (domain_type*) node1->data :  NULL);
        denial = ((node2 && node2 != LDNS_RBTREE_NULL) ? (denial_type*) node2->data :  NULL);
        if(!denial || (domain && ldns_dname_compare(domain->dname, denial->dname) < 0)) {
            rrsets = domain->rrsets;
            node1 = ldns_rbtree_next(node1);
        } else {
            rrsets = denial->rrset;
            node2 = ldns_rbtree_next(node2);
        }
        if(rrsets != zonemdrr) {
            worker_zonemdrrset(rrsets, (sha384rr ? &sha384ctx : NULL), (sha512rr ? &sha512ctx : NULL));
        }
    }
    ldns_sha384_final(sha384value, &sha384ctx);
    ldns_sha512_final(sha512value, &sha512ctx);

    if(sha384rr)
        memcpy(ldns_rdf_data(ldns_rr_rdf(sha384rr, 3)), sha384value, LDNS_SHA384_DIGEST_LENGTH);
    if(sha512rr)
        memcpy(ldns_rdf_data(ldns_rr_rdf(sha512rr, 3)), sha512value, LDNS_SHA512_DIGEST_LENGTH);

    long nsubtasks = 0;
    long nsubtasksfailed = 0;
    worker_queue_rrset(context, context->signq, zonemdrr, &nsubtasks);
    fifoq_waitfor(context->signq, context->worker, nsubtasks, &nsubtasksfailed);
}

time_t
do_signzone(task_type* task, const char* zonename, void* zonearg, void *contextarg)
{
    struct worker_context* context = contextarg;
    engine_type* engine = context->engine;
    worker_type* worker = context->worker;
    zone_type* zone = zonearg;
    rrset_type* zonemdrr;
    ods_status status;
    time_t start = 0;
    time_t end = 0;
    long nsubtasks = 0;
    long nsubtasksfailed = 0;

    context->clock_in = time_now();

    status = zone_update_serial(zone);
    if (status != ODS_STATUS_OK) {
        if(!strcmp(zone->signconf->soa_serial,"keep") && (status == ODS_STATUS_FOPEN_ERR || status == ODS_STATUS_CONFLICT_ERR)) {
            if(task->backoff > 0) {
                ods_log_error("[%s] unable to sign zone %s: failed to increment serial", worker->name, task->owner);
                ods_log_crit("[%s] CRITICAL: repeatedly failed to sign zone %s: %s", worker->name, task->owner, ods_status2str(status));
            } else {
                ods_log_warning("[%s] unable to sign zone %s: failed to increment serial", worker->name, task->owner);
                ods_log_warning("[%s] CRITICAL: failed to sign zone %s: %s", worker->name, task->owner, ods_status2str(status));
            }
            task->backoff = duration2time(zone->signconf->sig_resign_interval);
            return time_now() + duration2time(zone->signconf->sig_resign_interval);
        } else {
            ods_log_error("[%s] unable to sign zone %s: failed to increment serial", worker->name, task->owner);
            ods_log_crit("[%s] CRITICAL: failed to sign zone %s: %s", worker->name, task->owner, ods_status2str(status));
            return schedule_DEFER;
        }
    }
    zonemdinitialize(context, zone, &zonemdrr);

    /* start timer */
    start = time(NULL);
    if (zone->stats) {
        pthread_mutex_lock(&zone->stats->stats_lock);
        if (!zone->stats->start_time) {
            zone->stats->start_time = start;
        }
        zone->stats->sig_count = 0;
        zone->stats->sig_soa_count = 0;
        zone->stats->sig_reuse = 0;
        zone->stats->sig_time = 0;
        pthread_mutex_unlock(&zone->stats->stats_lock);
    }
    /* check the HSM connection before queuing sign operations */
    if (hsm_check_context()) {
        ods_log_error("signer instructed to reload due to hsm reset in sign task");
        engine->need_to_reload = 1;
        pthread_mutex_lock(&engine->signal_lock);
        pthread_cond_signal(&engine->signal_cond);
        pthread_mutex_unlock(&engine->signal_lock);
        ods_log_crit("[%s] CRITICAL: failed to sign zone %s: %s", worker->name, task->owner, ods_status2str(status));
        return schedule_DEFER; /* backoff */
    }
    /* prepare keys */
    status = zone_prepare_keys(zone);
    if (status == ODS_STATUS_OK) {
        /* queue menial, hard signing work */
        worker_queue_zone(context, worker->taskq->signq, zone, &nsubtasks);
        ods_log_deeebug("[%s] wait until drudgers are finished "
                "signing zone %s", worker->name, task->owner);
        /* sleep until work is done */
        fifoq_waitfor(context->signq, worker, nsubtasks, &nsubtasksfailed);
    }
    /* stop timer */
    end = time(NULL);
    /* check status and jobs */
    if (status == ODS_STATUS_OK) {
        status = worker_check_jobs(worker, task, nsubtasks, nsubtasksfailed);
    }

    if(zonemdrr)
        zomemdprocess(context, zone, zonemdrr);

    if (status == ODS_STATUS_OK && zone->stats) {
        pthread_mutex_lock(&zone->stats->stats_lock);
        zone->stats->sig_time = (end - start);
        pthread_mutex_unlock(&zone->stats->stats_lock);
    }
    if (status != ODS_STATUS_OK) {
        ods_log_crit("[%s] CRITICAL: failed to sign zone %s: %s", worker->name, task->owner, ods_status2str(status));
        return schedule_DEFER; /* backoff */
    }

    schedule_scheduletask(engine->taskq, TASK_WRITE, zone->name, zone, &zone->zone_lock, schedule_PROMPTLY);
    return schedule_SUCCESS;
}

time_t
do_readzone(task_type* task, const char* zonename, void* zonearg, void *contextarg)
{
    ods_status status = ODS_STATUS_OK;
    struct worker_context* context = contextarg;
    engine_type* engine = context->engine;
    zone_type* zone = zonearg;
    /* perform 'read input adapter' task */
    if (!zone->signconf->last_modified) {
        ods_log_debug("no signconf.xml for zone %s yet", task->owner);
        status = ODS_STATUS_ERR;
    }
    if (status == ODS_STATUS_OK) {
        status = tools_input(zone);
        if (status == ODS_STATUS_UNCHANGED) {
            ods_log_verbose("zone %s unsigned data not changed, continue", task->owner);
            status = ODS_STATUS_OK;
        }
    }
    if (status != ODS_STATUS_OK) {
        if (!zone->signconf->last_modified) {
            ods_log_warning("WARNING: unable to sign zone %s, signconf is not ready", task->owner);
            return schedule_DEFER;
        } else if (status != ODS_STATUS_XFR_NOT_READY) {
            /* other statuses is critical, and we know it is not ODS_STATUS_OK */
            if(!strcmp(zone->signconf->soa_serial,"keep") && (status == ODS_STATUS_FOPEN_ERR || status == ODS_STATUS_CONFLICT_ERR)) {
                if(task->backoff > 0) {
                    ods_log_crit("CRITICAL: repeatedly failed to sign zone %s: %s", task->owner, ods_status2str(status));
                } else {
                    ods_log_warning("Warning: failed to sign zone %s: %s", task->owner, ods_status2str(status));
                }
                task->backoff = duration2time(zone->signconf->sig_resign_interval);
                return time_now() + duration2time(zone->signconf->sig_resign_interval);
            } else {
                ods_log_crit("CRITICAL: failed to sign zone %s: %s", task->owner, ods_status2str(status));
                return schedule_DEFER;
            }
        }
    } else {
        /* unscheduling an existing sign task should no be necessary.  After a read (this action)
         * the logical next step is a sign.  No other regular procedure that does not explicitly
         * remove a sign task could create a sign task for this zone.  So here we would be able
         * to assume there is no sign task.  However it occurs.  The original code before refactoring
         * also removed sign tasks.  My premis this is caused by the locking code.  A task actually
         * starts executing even though the zone is being processed from another task.  So for
         * instance performing a force signconf just before a read task starts, can load to the read
         * task to start executing even though the signconf task was still running.  The forced signconf
         * task cannot remove the read task (it is no longer queued), but will schedule a sign task.
         * The read task can then continue, finding the just created sign task in its path.
         */
        schedule_unscheduletask(engine->taskq, TASK_SIGN, zone->name);
        schedule_scheduletask(engine->taskq, TASK_SIGN, zone->name, zone, &zone->zone_lock, schedule_PROMPTLY);
        return schedule_SUCCESS;
    }
}

time_t
do_forcereadzone(task_type* task, const char* zonename, void* zonearg, void *contextarg)
{
    ods_status status = ODS_STATUS_OK;
    struct worker_context* context = contextarg;
    engine_type* engine = context->engine;
    zone_type* zone = zonearg;
    /* perform 'read input adapter' task */
    if (!zone->signconf->last_modified) {
        ods_log_debug("no signconf.xml for zone %s yet", task->owner);
        status = ODS_STATUS_ERR;
    }
    if (status == ODS_STATUS_OK) {
        status = tools_input(zone);
        if (status == ODS_STATUS_UNCHANGED) {
            ods_log_verbose("zone %s unsigned data not changed, continue", task->owner);
            status = ODS_STATUS_OK;
        }
    }
    if (status != ODS_STATUS_OK) {
        if (!zone->signconf->last_modified) {
            ods_log_warning("WARNING: unable to sign zone %s, signconf is not ready", task->owner);
        } else if (status != ODS_STATUS_XFR_NOT_READY) {
            /* other statuses is critical, and we know it is not ODS_STATUS_OK */
            if(!strcmp(zone->signconf->soa_serial,"keep") && (status == ODS_STATUS_FOPEN_ERR || status == ODS_STATUS_CONFLICT_ERR)) {
                if(task->backoff > 0) {
                    ods_log_crit("CRITICAL: repeatedly failed to sign zone %s: %s", task->owner, ods_status2str(status));
                } else {
                    ods_log_warning("Warning: failed to sign zone %s: %s", task->owner, ods_status2str(status));
                }
                task->backoff = duration2time(zone->signconf->sig_resign_interval);
                return time_now() + duration2time(zone->signconf->sig_resign_interval);
            } else {
                ods_log_crit("CRITICAL: failed to sign zone %s: %s", task->owner, ods_status2str(status));
                return schedule_DEFER;
            }
        }
        return schedule_SUCCESS;
    } else {
        schedule_unscheduletask(engine->taskq, TASK_SIGNCONF, zone->name);
        schedule_unscheduletask(engine->taskq, TASK_FORCEREAD, zone->name);
        schedule_unscheduletask(engine->taskq, TASK_READ, zone->name);
        schedule_unscheduletask(engine->taskq, TASK_SIGN, zone->name);
        schedule_unscheduletask(engine->taskq, TASK_WRITE, zone->name);
        schedule_scheduletask(engine->taskq, TASK_SIGN, zone->name, zone, &zone->zone_lock, schedule_PROMPTLY);
        return schedule_SUCCESS;
    }
}

time_t
do_writezone(task_type* task, const char* zonename, void* zonearg, void *contextarg)
{
    struct worker_context* context = contextarg;
    engine_type* engine = context->engine;
    worker_type* worker = context->worker;
    zone_type* zone = zonearg;
    ods_status status;
    time_t resign;
    context->clock_in = time_now(); /* TODO this means something different */
    /* perform write to output adapter task */
    status = tools_output(zone, engine);
    if (status != ODS_STATUS_OK) {
        ods_log_crit("[%s] CRITICAL: failed to sign zone %s: %s",
                worker->name, task->owner, ods_status2str(status));
        return schedule_DEFER;
    }
    if (zone->signconf &&
            duration2time(zone->signconf->sig_resign_interval)) {
        resign = context->clock_in +
                duration2time(zone->signconf->sig_resign_interval);
    } else {
        ods_log_error("[%s] unable to retrieve resign interval "
                "for zone %s: duration2time() failed",
                worker->name, task->owner);
        ods_log_info("[%s] defaulting to 1H resign interval for "
                "zone %s", worker->name, task->owner);
        resign = context->clock_in + 3600;
    }
    /* backup the last successful run */
    status = zone_backup2(zone, resign);
    if (status != ODS_STATUS_OK) {
        ods_log_warning("[%s] unable to backup zone %s: %s",
                worker->name, task->owner, ods_status2str(status));
        /* just a warning */
        status = ODS_STATUS_OK;
    }
    schedule_scheduletask(engine->taskq, TASK_SIGN, zone->name, zone, &zone->zone_lock, resign);
    return schedule_SUCCESS;
}
