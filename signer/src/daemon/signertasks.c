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

#include <time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

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
#include "file.h"
#include "settings.h"

/**
 * Queue RRset for signing.
 *
 */
static void
worker_queue_domain(struct worker_context* context, fifoq_type* q, void* item, long* nsubtasks)
{
    ods_status status = ODS_STATUS_UNCHANGED;
    int tries = 0;
    ods_log_assert(q);

        pthread_mutex_lock(&q->q_lock);
        status = fifoq_push(q, item, context, &tries);
        while (status == ODS_STATUS_UNCHANGED) {
            tries++;
            if (context->worker->need_to_exit) {
                pthread_mutex_unlock(&q->q_lock);
                return; /* FIXME should indicate some fundamental problem */
            }
            /**
             * Apparently the queue is full. Lets take a small break to not hog CPU.
             * The worker will release the signq lock while sleeping and will
             * automatically grab the lock when the queue is nonfull.
             * Queue is nonfull at 10% of the queue size.
             */
            ods_thread_wait(&q->q_nonfull, &q->q_lock, 5);
            status = fifoq_push(q, item, context, &tries);
        }
        pthread_mutex_unlock(&q->q_lock);

        ods_log_assert(status == ODS_STATUS_OK);
        *nsubtasks += 1;
}


/**
 * Queue zone for signing.
 *
 */
static void
worker_queue_zone(struct worker_context* context, fifoq_type* q, names_view_type view, long* nsubtasks)
{
    names_iterator iter;
    recordset_type record;
    time_t refreshtime = context->clock_in + duration2time(context->zone->signconf->sig_refresh_interval);
    for(iter=names_viewiterator(view,names_iteratorexpiring,refreshtime); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
        names_amend(view, record);
        worker_queue_domain(context, q, record, nsubtasks);
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

static ods_status
signdomain(struct worker_context* superior, hsm_ctx_t* ctx, recordset_type record)
{
    ods_status status;
    names_iterator iter;
    ldns_rr_type rrtype;
    int expiration = INT_MAX;
    time_t rrsigexpirationtime;
    ldns_rr* rrsig;
    ldns_rr_list* rrsigs;
    ldns_rdf* rrsigexpiration;

    for (iter=names_recordalltypes(record); names_iterate(&iter,&rrtype); names_advance(&iter,NULL)) {
        if ((status = rrset_sign(superior->zone->signconf, superior->view, record, rrtype, ctx, superior->clock_in)) != ODS_STATUS_OK)
            return status;
    }
    if(names_recordgetdenial(record)) {
        if((status = rrset_sign(superior->zone->signconf, superior->view, record, LDNS_RR_TYPE_NSEC, ctx, superior->clock_in)) != ODS_STATUS_OK)
            return status;
    }

    names_recordlookupall(record, LDNS_RR_TYPE_RRSIG, NULL, NULL, &rrsigs);
    while((rrsig=ldns_rr_list_pop_rr(rrsigs))) {
        rrsigexpiration = ldns_rr_rrsig_expiration(rrsig);
        rrsigexpirationtime = ldns_rdf2native_time_t(rrsigexpiration);
        if(rrsigexpirationtime < expiration)
            expiration = rrsigexpirationtime;
    }
    ldns_rr_list_free(rrsigs);
    names_recordsetexpiry(record, expiration);

    return ODS_STATUS_OK;
}

void
drudge(worker_type* worker)
{
    recordset_type record;
    ods_status status;
    struct worker_context* superior;
    hsm_ctx_t* ctx = NULL;
    engine_type* engine;
    fifoq_type* signq = worker->taskq->signq;

    while (worker->need_to_exit == 0) {
        ods_log_deeebug("[%s] report for duty", worker->name);
        pthread_mutex_lock(&signq->q_lock);
        if (worker->need_to_exit != 0) {
            pthread_mutex_unlock(&signq->q_lock);
            break;
        }
        superior = NULL;
        record = (recordset_type) fifoq_pop(signq, (void**)&superior);
        if (!record) {
            ods_log_deeebug("[%s] nothing to do, wait", worker->name);
            /**
             * Apparently the queue is empty. Wait until new work is queued.
             * The drudger will release the signq lock while sleeping and
             * will automatically grab the lock when the threshold is reached.
             * Threshold is at 1 and MAX (after a number of tries).
             */
            pthread_cond_wait(&signq->q_threshold, &signq->q_lock);
            if(worker->need_to_exit == 0)
                record = (recordset_type) fifoq_pop(signq, (void**)&superior);
        }
        pthread_mutex_unlock(&signq->q_lock);
        /* do some work */
        if (record) {
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
                status = signdomain(superior, ctx, record);
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

void
processoccluded(names_view_type view)
{
    struct dual change;
    names_iterator iter;
    /* for any occluded domain names, clear the annotation, since we should not be genereating NSECs for them */
    for (iter=names_viewiterator(view,names_iteratordenialchainupdates); names_iterate(&iter,&change); names_advance(&iter,NULL)) {
        if(domain_is_occluded(view, change.src) != LDNS_RR_TYPE_SOA) {
            recordset_type record = change.src;
            names_update(view, &record);
            names_recordannotate(record, NULL);
        }
    }
}

void
processneighbours(names_view_type view, signconf_type* signconf, int newserial)
{
    struct dual change;
    names_iterator iter;
    // BERRY FIXME does this iterate over all?  should be only over updates
    for (iter=names_viewiterator(view,names_iteratordenialchainupdates); names_iterate(&iter,&change); names_advance(&iter,NULL)) {
        const char* nextnamestr;
        ldns_rdf* nextnamerdf;
        if(signconf->nsec3params)
            nextnamestr = names_recordgetdenial(change.dst);
        else
            nextnamestr = names_recordgetname(change.dst);
        nextnamerdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, nextnamestr);
        ldns_rr* nsec = denial_nsecify(signconf, view, change.src, nextnamerdf);
        if (names_recordcmpdenial(change.src, nsec)) {
            recordset_type record = change.src;
            if(names_recordhasexpiry(record)) {
                names_amend(view, record);
                names_recordsetvalidupto(record, newserial);
                names_underwrite(view, &record); // BERTY
                names_recordsetvalidfrom(record, newserial);
            } else {
                names_amend(view, record);
            }
            names_recordsetdenial(record, nsec);
        }
        ldns_rdf_deep_free(nextnamerdf);
    }
}

time_t
do_signzone(task_type* task, const char* zonename, void* zonearg, void *contextarg)
{
    struct worker_context* context = contextarg;
    engine_type* engine = context->engine;
    worker_type* worker = context->worker;
    zone_type* zone = zonearg;
    ods_status status;
    time_t start = 0;
    time_t end = 0;
    long nsubtasks = 0;
    long nsubtasksfailed = 0;
    int newserial;
    int conflict;
    recordset_type record;
    struct dual change;
    names_iterator iter;

    names_viewreset(zone->prepareview);
    context->clock_in = time_now();
    context->zone = zone;
    context->view = zone->signview;
    if (!zone->nextserial) {
        namedb_update_serial(zone);
    }
    newserial = *(zone->nextserial);

    names_view_type prepareview = zone->prepareview;
    /* The purpose of the next iteration is to go over all new or modified records and fix the SOA serial number from
     * which these records are valid.  If the records is a modified record, the records that it superceeds, will be
     * marked with the same serial indicating that it is no longer valid from this moment on.
     */
    for (iter=names_viewiterator(prepareview,names_iteratorincoming); names_iterate(&iter,&change); names_advance(&iter,NULL)) {
        assert(change.dst != change.src);
        if(names_recordhasexpiry(change.src)) {
            if(change.dst) {
                names_amend(prepareview, change.dst);
                names_recordsetvalidupto(change.dst, newserial);
            }
            names_amend(prepareview, change.src);
            names_recordsetvalidfrom(change.src, newserial);
        }
    }
    for (iter=names_viewiterator(prepareview,names_iteratorincoming); names_iterate(&iter,&change); names_advance(&iter,NULL)) {
        if(change.dst && !names_recordvalidupto(change.dst,NULL)) {
            names_amend(prepareview, change.dst);
            names_recordsetvalidupto(change.dst, newserial);
        }
        if(!names_recordvalidfrom(change.src,NULL)) {
            if(names_recordhasdata(change.src, 0, NULL, 0)) {
                names_amend(prepareview, change.src);
                names_recordsetvalidfrom(change.src, newserial);
            } else {
                names_remove(prepareview, change.src); // FIXME what if multiple are overwritten?
            }
        }
    }
    conflict = names_viewcommit(zone->prepareview);
    names_viewvalidate(prepareview);
    assert(!conflict);

    status = zone_update_serial(zone, zone->prepareview);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to sign zone %s: failed to increment serial", worker->name, task->owner);
        ods_log_crit("[%s] CRITICAL: failed to sign zone %s: %s",
                worker->name, task->owner, ods_status2str(status));
        return schedule_DEFER; /* backoff */
    }
    conflict = names_viewcommit(zone->prepareview);
    assert(!conflict);

    names_viewreset(zone->signview);
    names_viewreset(zone->neighview);
    processoccluded(zone->neighview);
    conflict = names_viewcommit(zone->neighview);
    assert(!conflict);

    names_viewreset(zone->signview);
    processneighbours(zone->signview, zone->signconf, newserial);
    conflict = names_viewcommit(zone->signview);
    assert(!conflict);

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
        ods_log_crit("[%s] CRITICAL: failed to sign zone %s: %s",
                worker->name, task->owner, ods_status2str(status));
        return schedule_DEFER; /* backoff */
    }
    /* prepare keys */
    status = zone_prepare_keys(zone);
    if (status == ODS_STATUS_OK) {
        names_viewreset(zone->signview);
        /* queue menial, hard signing work */
        if(context->signq) {
            worker_queue_zone(context, worker->taskq->signq, zone->signview, &nsubtasks);
            ods_log_deeebug("[%s] wait until drudgers are finished "
                    "signing zone %s", worker->name, task->owner);
            /* sleep until work is done */
            fifoq_waitfor(context->signq, worker, nsubtasks, &nsubtasksfailed);
        } else {
            names_iterator iter;
            hsm_ctx_t* ctx;
            recordset_type record;
            time_t refreshtime = context->clock_in + duration2time(zone->signconf->sig_refresh_interval);
            ctx = hsm_create_context();
            for(iter=names_viewiterator(zone->signview,names_iteratorexpiring,refreshtime); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
                names_amend(zone->signview, record);
                signdomain(context, ctx, record);
            }
            hsm_destroy_context(ctx);
        }
    }
    /* stop timer */
    end = time(NULL);
    /* check status and jobs */
    if (status == ODS_STATUS_OK) {
        status = worker_check_jobs(worker, task, nsubtasks, nsubtasksfailed);
    }
    if (status == ODS_STATUS_OK && zone->stats) {
        pthread_mutex_lock(&zone->stats->stats_lock);
        zone->stats->sig_time = (end - start);
        pthread_mutex_unlock(&zone->stats->stats_lock);
    }
    if (status != ODS_STATUS_OK) {
        ods_log_crit("[%s] CRITICAL: failed to sign zone %s: %s",
                worker->name, task->owner, ods_status2str(status));
        return schedule_DEFER; /* backoff */
    }
    if (zone->stats) {
        pthread_mutex_lock(&zone->stats->stats_lock);
        if (zone->stats->sort_done == 0 &&
            (zone->stats->sig_count <= zone->stats->sig_soa_count)) {
            ods_log_verbose("skip write zone %s serial %u (zone not "
                "changed)", (zone->name?zone->name:"(null)"),
                (zone->inboundserial?(unsigned int)*zone->inboundserial:0));
            stats_clear(zone->stats);
            pthread_mutex_unlock(&zone->stats->stats_lock);
            return schedule_SUCCESS;
        }
        pthread_mutex_unlock(&zone->stats->stats_lock);
    }
    status = names_viewcommit(zone->signview);
    if(status) {
        logger_message(&logger_cls,logger_noctx,logger_ERROR,"Failed to commit sign");
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
        } else if (status != ODS_STATUS_XFR_NOT_READY) {
            /* other statuses is critical, and we know it is not ODS_STATUS_OK */
            ods_log_crit("CRITICAL: failed to sign zone %s: %s", task->owner, ods_status2str(status));
        }
        return schedule_DEFER;
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
            ods_log_crit("CRITICAL: failed to sign zone %s: %s", task->owner, ods_status2str(status));
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


static const long default_statefile_freq = 1;
static const long default_zonefile_freq = 1;
static const long default_ixfr_history = 30;

void
do_outputzonefile(zone_type* zone)
{
    names_view_type outputview;
    char* filename;
    char* tmpname;

    /* Write the zone as it currently stands */
    outputview = zone->outputview;
    names_viewreset(outputview);
    tmpname = ods_build_path(zone->adoutbound->configstr, ".tmp", 0, 0);
    if(writezone(outputview, tmpname)) {
        if (zone->adoutbound->error) {
            ods_log_error("unable to write zone %s file %s", zone->name, filename);
            zone->adoutbound->error = 0;
            // status = ODS_STATUS_FWRITE_ERR;
        }
    } else {
        if (rename((const char*) tmpname, zone->adoutbound->configstr) != 0) {
            ods_log_error("unable to write file: failed to rename %s to %s (%s)", tmpname, filename, strerror(errno));
            // status = ODS_STATUS_RENAME_ERR;
        }
    }
    free(tmpname);
}

void
do_purgezone(zone_type* zone)
{
    int serial;
    names_view_type baseview;
    names_iterator iter;
     recordset_type record;

    baseview = zone->baseview;
    names_viewreset(baseview);

    /* find any items that are no longer worth preserving because they are
     * outdated for too long (ie their last valid serial number is too far
     * in the past.
     */
    serial = zone->outboundserial - (zone->operatingconf ? zone->operatingconf->ixfr_history : 4);
    for(iter=names_viewiterator(baseview,names_iteratoroutdated,serial); names_iterate(&iter,&record); names_advance(&iter, NULL)) {
        names_remove(baseview, record);
    }
    if(names_viewcommit(baseview)) {
        ods_log_error("Unable to clean zone, retrying next pass");
    }
}

void
do_outputstatefile(zone_type* zone)
{
    /* Refresh the current state jounral file */
    struct stat statbuf;
    names_view_type baseview;
    char* filename;

    baseview = zone->baseview;
    names_viewreset(baseview);
    filename = ods_build_path(zone->name, ".state", 0, 1);
    if(fstatat(AT_FDCWD, filename, &statbuf, 0)) {
        if(errno == ENOENT) {
            names_viewpersist(baseview, AT_FDCWD, filename);
        } else {
            ods_log_error("unable to create state file for zone %s", zone->name);
        }
    }
    free(filename);
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

    if(zone->operatingconf == NULL) {
        long defaultvalue;
        ods_cfg_access(NULL, "opendnssec.conf");
        zone->operatingconf = malloc(sizeof(struct operatingconf));
        zone->operatingconf->statefile_timer = 0;
        ods_cfg_getcount(NULL, &zone->operatingconf->statefile_freq, &default_statefile_freq, NULL, "signer", "output-statefile-period", NULL);
        zone->operatingconf->zonefile_timer = 0;
        ods_cfg_getcount(NULL, &zone->operatingconf->zonefile_freq, &default_zonefile_freq, NULL, "signer", "output-zonefile-period", NULL);
        ods_cfg_getcount(NULL, &zone->operatingconf->ixfr_history, &default_ixfr_history, NULL, "signer", "output-ixfr-history", NULL);
    }

    if(zone->operatingconf->statefile_timer > 0) {
        if(--(zone->operatingconf->statefile_timer) == 0) {
            zone->operatingconf->statefile_timer = zone->operatingconf->statefile_freq;
            do_outputstatefile(zone);
        }
    }

    names_viewreset(zone->outputview);
    status = tools_output(zone, engine);

    if(zone->operatingconf->zonefile_timer > 0) {
        if(--(zone->operatingconf->zonefile_timer) == 0) {
            zone->operatingconf->zonefile_timer = zone->operatingconf->zonefile_freq;
            do_outputzonefile(zone);
        }
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
    schedule_scheduletask(engine->taskq, TASK_SIGN, zone->name, zone, &zone->zone_lock, resign);
    return schedule_SUCCESS;
}
