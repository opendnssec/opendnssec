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
 * The engine.
 *
 */

#include "config.h"
#include "daemon/cfg.h"
#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "daemon/signal.h"
#include "daemon/worker.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/locks.h"
#include "shared/log.h"
#include "shared/privdrop.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/zone.h"
#include "signer/zonelist.h"
#include "tools/zone_fetcher.h"

#include <errno.h>
#include <libhsm.h>
#include <libxml/parser.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static const char* engine_str = "engine";


/**
 * Create engine.
 *
 */
static engine_type*
engine_create(void)
{
    engine_type* engine;
    allocator_type* allocator = allocator_create(malloc, free);
    if (!allocator) {
        return NULL;
    }
    engine = (engine_type*) allocator_alloc(allocator, sizeof(engine_type));
    if (!engine) {
        allocator_cleanup(allocator);
        return NULL;
    }
    engine->allocator = allocator;
    engine->config = NULL;
    engine->workers = NULL;
    engine->drudgers = NULL;
    engine->cmdhandler = NULL;
    engine->cmdhandler_done = 0;
    engine->pid = -1;
    engine->zfpid = -1;
    engine->uid = -1;
    engine->gid = -1;
    engine->daemonize = 0;
    engine->need_to_exit = 0;
    engine->need_to_reload = 0;

    engine->signal = SIGNAL_INIT;
    lock_basic_init(&engine->signal_lock);
    lock_basic_set(&engine->signal_cond);

    engine->zonelist = zonelist_create(engine->allocator);
    if (!engine->zonelist) {
        engine_cleanup(engine);
        return NULL;
    }
    engine->taskq = schedule_create(engine->allocator);
    if (!engine->taskq) {
        engine_cleanup(engine);
        return NULL;
    }
    engine->signq = fifoq_create(engine->allocator);
    if (!engine->signq) {
        engine_cleanup(engine);
        return NULL;
    }
    return engine;
}


/**
 * Start command handler.
 *
 */
static void*
cmdhandler_thread_start(void* arg)
{
    cmdhandler_type* cmd = (cmdhandler_type*) arg;
    ods_thread_blocksigs();
    cmdhandler_start(cmd);
    return NULL;
}
static void
engine_start_cmdhandler(engine_type* engine)
{
    ods_log_assert(engine);
    ods_log_debug("[%s] start command handler", engine_str);
    engine->cmdhandler->engine = engine;
    ods_thread_create(&engine->cmdhandler->thread_id,
        cmdhandler_thread_start, engine->cmdhandler);
    return;
}
/**
 * Self pipe trick (see Unix Network Programming).
 *
 */
static int
self_pipe_trick(engine_type* engine)
{
    int sockfd, ret;
    struct sockaddr_un servaddr;
    const char* servsock_filename = ODS_SE_SOCKFILE;

    ods_log_assert(engine);
    ods_log_assert(engine->cmdhandler);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd <= 0) {
        ods_log_error("[%s] cannot connect to command handler: "
            "socket() failed: %s\n", engine_str, strerror(errno));
        return 1;
    } else {
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sun_family = AF_UNIX;
        strncpy(servaddr.sun_path, servsock_filename,
            sizeof(servaddr.sun_path) - 1);

        ret = connect(sockfd, (const struct sockaddr*) &servaddr,
            sizeof(servaddr));
        if (ret != 0) {
            ods_log_error("[%s] cannot connect to command handler: "
                "connect() failed: %s\n", engine_str, strerror(errno));
            close(sockfd);
            return 1;
        } else {
            /* self-pipe trick */
            ods_writen(sockfd, "", 1);
            close(sockfd);
        }
    }
    return 0;
}
/**
 * Stop command handler.
 *
 */
static void
engine_stop_cmdhandler(engine_type* engine)
{
    ods_log_assert(engine);
    if (!engine->cmdhandler) {
        return;
    }
    ods_log_debug("[%s] stop command handler", engine_str);
    engine->cmdhandler->need_to_exit = 1;
    if (self_pipe_trick(engine) == 0) {
        while (!engine->cmdhandler_done) {
            ods_log_debug("[%s] waiting for command handler to exit...",
                engine_str);
            sleep(1);
        }
    } else {
        ods_log_error("[%s] command handler self pipe trick failed, "
            "unclean shutdown", engine_str);
    }
    return;
}


/**
 * Drop privileges.
 *
 */
static ods_status
engine_privdrop(engine_type* engine)
{
    ods_status status = ODS_STATUS_OK;
    uid_t uid = -1;
    gid_t gid = -1;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] drop privileges", engine_str);

    if (engine->config->username && engine->config->group) {
        ods_log_verbose("[%s] drop privileges to user %s, group %s",
           engine_str, engine->config->username, engine->config->group);
    } else if (engine->config->username) {
        ods_log_verbose("[%s] drop privileges to user %s", engine_str,
           engine->config->username);
    } else if (engine->config->group) {
        ods_log_verbose("[%s] drop privileges to group %s", engine_str,
           engine->config->group);
    }
    if (engine->config->chroot) {
        ods_log_verbose("[%s] chroot to %s", engine_str,
            engine->config->chroot);
    }
    status = privdrop(engine->config->username, engine->config->group,
        engine->config->chroot, &uid, &gid);
    engine->uid = uid;
    engine->gid = gid;
    privclose(engine->config->username, engine->config->group);
    return status;
}


/**
 * Start/stop workers.
 *
 */
static void
engine_create_workers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_assert(engine->allocator);
    engine->workers = (worker_type**) allocator_alloc(engine->allocator,
        ((size_t)engine->config->num_worker_threads) * sizeof(worker_type*));
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        engine->workers[i] = worker_create(engine->allocator, i,
            WORKER_WORKER);
    }
    return;
}
static void
engine_create_drudgers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_assert(engine->allocator);
    engine->drudgers = (worker_type**) allocator_alloc(engine->allocator,
        ((size_t)engine->config->num_signer_threads) * sizeof(worker_type*));
    for (i=0; i < (size_t) engine->config->num_signer_threads; i++) {
        engine->drudgers[i] = worker_create(engine->allocator, i,
            WORKER_DRUDGER);
    }
    return;
}
static void*
worker_thread_start(void* arg)
{
    worker_type* worker = (worker_type*) arg;
    ods_thread_blocksigs();
    worker_start(worker);
    return NULL;
}
static void
engine_start_workers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] start workers", engine_str);
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        engine->workers[i]->need_to_exit = 0;
        engine->workers[i]->engine = (struct engine_struct*) engine;
        ods_thread_create(&engine->workers[i]->thread_id, worker_thread_start,
            engine->workers[i]);
    }
    return;
}
static void
engine_start_drudgers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] start drudgers", engine_str);
    for (i=0; i < (size_t) engine->config->num_signer_threads; i++) {
        engine->drudgers[i]->need_to_exit = 0;
        engine->drudgers[i]->engine = (struct engine_struct*) engine;
        ods_thread_create(&engine->drudgers[i]->thread_id, worker_thread_start,
            engine->drudgers[i]);
    }
    return;
}
static void
engine_stop_workers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] stop workers", engine_str);
    /* tell them to exit and wake up sleepyheads */
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        engine->workers[i]->need_to_exit = 1;
        worker_wakeup(engine->workers[i]);
    }
    /* head count */
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        ods_log_debug("[%s] join worker %i", engine_str, i+1);
        ods_thread_join(engine->workers[i]->thread_id);
        engine->workers[i]->engine = NULL;
    }
    return;
}
static void
engine_stop_drudgers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] stop drudgers", engine_str);
    /* tell them to exit and wake up sleepyheads */
    for (i=0; i < (size_t) engine->config->num_signer_threads; i++) {
        engine->drudgers[i]->need_to_exit = 1;
    }
    worker_notify_all(&engine->signq->q_lock, &engine->signq->q_threshold);

    /* head count */
    for (i=0; i < (size_t) engine->config->num_signer_threads; i++) {
        ods_log_debug("[%s] join drudger %i", engine_str, i+1);
        ods_thread_join(engine->drudgers[i]->thread_id);
        engine->drudgers[i]->engine = NULL;
    }
    return;
}


/**
 * Wake up all workers.
 *
 */
void
engine_wakeup_workers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] wake up workers", engine_str);
    /* wake up sleepyheads */
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        worker_wakeup(engine->workers[i]);
    }
    return;
}


/**
 * Start zonefetcher.
 *
 */
static int
start_zonefetcher(engine_type* engine)
{
    pid_t zfpid = 0;
    int result = 0;
    char* zf_filename = NULL;
    char* zl_filename = NULL;
    char* log_filename = NULL;
    char* grp = NULL;
    char* usr = NULL;
    char* chrt = NULL;
    int use_syslog = 0;
    int verbosity = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);

    if (!engine->config->zonefetch_filename) {
        /* zone fetcher disabled */
        return 0;
    }

    switch ((zfpid = fork())) {
        case -1: /* error */
            ods_log_error("failed to fork zone fetcher: %s",
                strerror(errno));
            return 1;
        case 0: /* child */
            break;
        default: /* parent */
            engine->zfpid = zfpid;
            return 0;
    }

    if (setsid() == -1) {
        ods_log_error("failed to setsid zone fetcher: %s",
            strerror(errno));
        return 1;
    }

    hsm_close();
    ods_log_verbose("zone fetcher running as pid %lu",
        (unsigned long) getpid());

    if (engine->config->zonefetch_filename) {
        zf_filename = strdup(engine->config->zonefetch_filename);
    }
    if (engine->config->zonelist_filename) {
        zl_filename = strdup(engine->config->zonelist_filename);
    }
    if (engine->config->group) {
        grp = strdup(engine->config->group);
    }
    if (engine->config->username) {
        usr = strdup(engine->config->username);
    }
    if (engine->config->chroot) {
        chrt = strdup(engine->config->chroot);
    }
    if (engine->config->log_filename) {
        log_filename = strdup(engine->config->log_filename);
    }
    use_syslog = engine->config->use_syslog;
    verbosity = engine->config->verbosity;

    result = tools_zone_fetcher(zf_filename, zl_filename, grp, usr,
        chrt, log_filename, use_syslog, verbosity);

    ods_log_verbose("zone fetcher done", result);
    if (zf_filename)  { free((void*)zf_filename); }
    if (zl_filename)  { free((void*)zl_filename); }
    if (grp)          { free((void*)grp); }
    if (usr)          { free((void*)usr); }
    if (chrt)         { free((void*)chrt); }
    if (log_filename) { free((void*)log_filename); }

    engine_cleanup(engine);
    engine = NULL;
    ods_log_close();
    xmlCleanupParser();
    xmlCleanupGlobals();
    xmlCleanupThreads();
    exit(result);

    return 0;
}


/**
 * Reload zonefetcher.
 *
 */
static void
reload_zonefetcher(engine_type* engine)
{
    int result = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);

    if (engine->config->zonefetch_filename) {
        if (engine->zfpid > 0) {
            result = kill(engine->zfpid, SIGHUP);
            if (result == -1) {
                ods_log_error("cannot reload zone fetcher: %s",
                    strerror(errno));
            } else {
                ods_log_info("zone fetcher reloaded (pid=%i)", engine->zfpid);
            }
        } else {
            ods_log_error("cannot reload zone fetcher: process id unknown");
        }
    }
    return;
}


/**
 * Stop zonefetcher.
 *
 */
static void
stop_zonefetcher(engine_type* engine)
{
    int result = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);

    if (engine->config->zonefetch_filename) {
        if (engine->zfpid > 0) {
            result = kill(engine->zfpid, SIGTERM);
            if (result == -1) {
                ods_log_error("cannot stop zone fetcher: %s", strerror(errno));
            } else {
                ods_log_info("zone fetcher stopped (pid=%i)", engine->zfpid);
            }
            engine->zfpid = -1;
        } else {
            ods_log_error("cannot stop zone fetcher: process id unknown");
        }
    }
    return;
}


/**
 * Initialize adapters.
 *
 */
static ods_status
engine_init_adapters(engine_type* engine)
{
    size_t i = 0;
    ods_status status = ODS_STATUS_OK;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] initialize adapters", engine_str);
    for (i=0; i < (size_t) engine->config->num_adapters; i++) {
        status = adapter_init(engine->config->adapters[i]);
        if (status != ODS_STATUS_OK) {
            return status;
        }
    }
    return status;
}


/**
 * Set up engine.
 *
 */
static ods_status
engine_setup(engine_type* engine)
{
    struct sigaction action;
    int result = 0;
    ods_status status = ODS_STATUS_OK;

    ods_log_debug("[%s] signer setup", engine_str);
    if (!engine || !engine->config) {
        return ODS_STATUS_ASSERT_ERR;
    }

    /* create command handler (before chowning socket file) */
    engine->cmdhandler = cmdhandler_create(engine->allocator,
        engine->config->clisock_filename);
    if (!engine->cmdhandler) {
        ods_log_error("[%s] create command handler to %s failed",
            engine_str, engine->config->clisock_filename);
        return ODS_STATUS_CMDHANDLER_ERR;
    }

    /* fork of fetcher */
    if (start_zonefetcher(engine) != 0) {
        ods_log_error("[%s] cannot start zonefetcher", engine_str);
        return ODS_STATUS_ERR;
    }

    /* initialize adapters */
    status = engine_init_adapters(engine);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] initializing adapters failed", engine_str);
        return status;
    }

    /* privdrop */
    engine->uid = privuid(engine->config->username);
    engine->gid = privgid(engine->config->group);
    /* TODO: does piddir exists? */
    /* remove the chown stuff: piddir? */
    ods_chown(engine->config->pid_filename, engine->uid, engine->gid, 1);
    ods_chown(engine->config->clisock_filename, engine->uid, engine->gid, 0);
    ods_chown(engine->config->working_dir, engine->uid, engine->gid, 0);
    if (engine->config->log_filename && !engine->config->use_syslog) {
        ods_chown(engine->config->log_filename, engine->uid, engine->gid, 0);
    }
    if (engine->config->working_dir &&
        chdir(engine->config->working_dir) != 0) {
        ods_log_error("[%s] chdir to %s failed: %s", engine_str,
            engine->config->working_dir, strerror(errno));
        return ODS_STATUS_CHDIR_ERR;
    }
    if (engine_privdrop(engine) != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to drop privileges", engine_str);
        return ODS_STATUS_PRIVDROP_ERR;
    }

    /* daemonize */
    if (engine->daemonize) {
        switch ((engine->pid = fork())) {
            case -1: /* error */
                ods_log_error("[%s] unable to fork daemon: %s",
                    engine_str, strerror(errno));
                return ODS_STATUS_FORK_ERR;
            case 0: /* child */
                break;
            default: /* parent */
                engine_cleanup(engine);
                engine = NULL;
                xmlCleanupParser();
                xmlCleanupGlobals();
                xmlCleanupThreads();
                exit(0);
        }
        if (setsid() == -1) {
            ods_log_error("[%s] unable to setsid daemon (%s)",
                engine_str, strerror(errno));
            return ODS_STATUS_SETSID_ERR;
        }
    }
    engine->pid = getpid();
    ods_log_verbose("[%s] running as pid %lu", engine_str,
        (unsigned long) engine->pid);

    /* catch signals */
    signal_set_engine(engine);
    action.sa_handler = signal_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    /* set up hsm */ /* LEAK */
    result = hsm_open(engine->config->cfg_filename, hsm_prompt_pin, NULL);
    if (result != HSM_OK) {
        ods_log_error("[%s] error initializing libhsm (errno %i)",
            engine_str, result);
        return ODS_STATUS_HSM_ERR;
    }

    /* create workers */
    engine_create_workers(engine);
    engine_create_drudgers(engine);

    /* start command handler */
    engine_start_cmdhandler(engine);

    /* write pidfile */
    if (util_write_pidfile(engine->config->pid_filename, engine->pid) == -1) {
        hsm_close();
        ods_log_error("[%s] unable to write pid file", engine_str);
        return ODS_STATUS_WRITE_PIDFILE_ERR;
    }

    return ODS_STATUS_OK;
}


/**
 * Make sure that all zones have been worked on at least once.
 *
 */
static int
engine_all_zones_processed(engine_type* engine)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;

    ods_log_assert(engine);
    ods_log_assert(engine->zonelist);
    ods_log_assert(engine->zonelist->zones);

    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->key;
        if (!zone->processed) {
		return 0;
        }
        node = ldns_rbtree_next(node);
    }
    return 1;
}


/**
 * Run engine, run!.
 *
 */
static void
engine_run(engine_type* engine, int single_run)
{
    if (!engine) {
        return;
    }
    ods_log_assert(engine);

    engine_start_workers(engine);
    engine_start_drudgers(engine);

    lock_basic_lock(&engine->signal_lock);
    /* [LOCK] signal */
    engine->signal = SIGNAL_RUN;
    /* [UNLOCK] signal */
    lock_basic_unlock(&engine->signal_lock);

    while (!engine->need_to_exit && !engine->need_to_reload) {
        lock_basic_lock(&engine->signal_lock);
        /* [LOCK] signal */
        engine->signal = signal_capture(engine->signal);
        switch (engine->signal) {
            case SIGNAL_RUN:
                ods_log_assert(1);
                break;
            case SIGNAL_RELOAD:
                engine->need_to_reload = 1;
                break;
            case SIGNAL_SHUTDOWN:
                engine->need_to_exit = 1;
                break;
            default:
                ods_log_warning("[%s] invalid signal captured: %d, "
                    "keep running", engine_str, signal);
                engine->signal = SIGNAL_RUN;
                break;
        }
        /* [UNLOCK] signal */
        lock_basic_unlock(&engine->signal_lock);

        if (single_run) {
           engine->need_to_exit = engine_all_zones_processed(engine);
        }

        lock_basic_lock(&engine->signal_lock);
        /* [LOCK] signal */
        if (engine->signal == SIGNAL_RUN && !single_run) {
           ods_log_debug("[%s] taking a break", engine_str);
           lock_basic_sleep(&engine->signal_cond, &engine->signal_lock, 3600);
        }
        /* [UNLOCK] signal */
        lock_basic_unlock(&engine->signal_lock);
    }
    ods_log_debug("[%s] signer halted", engine_str);
    engine_stop_drudgers(engine);
    engine_stop_workers(engine);
    return;
}


/**
 * Parse notify command.
 *
 */
static void
set_notify_ns(zone_type* zone, const char* cmd)
{
    const char* str = NULL;
    const char* str2 = NULL;

    ods_log_assert(cmd);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->adoutbound);

    if (zone->adoutbound->type == ADAPTER_FILE) {
        str = ods_replace(cmd, "%zonefile", zone->adoutbound->configstr);
    } else {
        str = cmd;
    }

    str2 = ods_replace(str, "%zone", zone->name);
    free((void*)str);
    zone->notify_ns = (const char*) str2;
    ods_log_debug("[%s] set notify ns: %s", engine_str, zone->notify_ns);
    return;
}


/**
 * Update zones.
 *
 */
void
engine_update_zones(engine_type* engine)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;
    zone_type* delzone = NULL;
    task_type* task = NULL;
    ods_status status = ODS_STATUS_OK;
    int wake_up = 0;
    time_t now;

    if (!engine || !engine->zonelist || !engine->zonelist->zones) {
        ods_log_error("[%s] cannot update zones: no engine or zonelist",
            engine_str);
        return;
    }
    ods_log_assert(engine);
    ods_log_assert(engine->zonelist);
    ods_log_assert(engine->zonelist->zones);

    now = time_now();
    reload_zonefetcher(engine);

    lock_basic_lock(&engine->zonelist->zl_lock);
    /* [LOCK] zonelist */
    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->data;

        if (zone->tobe_removed) {
            node = ldns_rbtree_next(node);

            lock_basic_lock(&zone->zone_lock);
            /* [LOCK] zone */
            delzone = zonelist_del_zone(engine->zonelist, zone);
            if (delzone) {
                lock_basic_lock(&engine->taskq->schedule_lock);
                /* [LOCK] schedule */
                task = unschedule_task(engine->taskq,
                    (task_type*) zone->task);
                /* [UNLOCK] schedule */
                lock_basic_unlock(&engine->taskq->schedule_lock);
            }
            task_cleanup(task);
            task = NULL;
            /* [UNLOCK] zone */
            lock_basic_unlock(&zone->zone_lock);

            zone_cleanup(zone);
            zone = NULL;
            continue;
        } else if (zone->just_added) {
            ods_log_assert(!zone->task);
            zone->just_added = 0;
            /* notify nameserver */
            if (engine->config->notify_command && !zone->notify_ns) {
                set_notify_ns(zone, engine->config->notify_command);
            }
            /* schedule task */
            task = task_create(TASK_SIGNCONF, now, zone->name, zone);
            if (!task) {
                ods_log_crit("[%s] failed to create task for zone %s",
                    engine_str, zone->name);
            } else {
                lock_basic_lock(&engine->taskq->schedule_lock);
                /* [LOCK] schedule */
                status = schedule_task(engine->taskq, task, 0);
                /* [UNLOCK] schedule */
                lock_basic_unlock(&engine->taskq->schedule_lock);
                wake_up = 1;
           }
           /* zone fetcher enabled? */
           zone->fetch = (engine->config->zonefetch_filename != NULL);

        } else if (zone->just_updated) {
            ods_log_assert(zone->task);
            zone->just_updated = 0;
            /* reschedule task */
            lock_basic_lock(&engine->taskq->schedule_lock);
            /* [LOCK] schedule */
            task = unschedule_task(engine->taskq, (task_type*) zone->task);
            if (task != NULL) {
                ods_log_debug("[%s] reschedule task for zone %s", engine_str,
                    zone->name);
                if (task->what != TASK_SIGNCONF) {
                    task->halted = task->what;
                    task->interrupt = TASK_SIGNCONF;
                }
                task->what = TASK_SIGNCONF;
                task->when = now;
                status = schedule_task(engine->taskq, task, 0);
            } else {
                /* task now queued, being worked on? */
                ods_log_debug("[%s] worker busy with zone %s, will update "
                    "signconf as soon as possible", engine_str, zone->name);
                task = (task_type*) zone->task;
                task->interrupt = TASK_SIGNCONF;
                /* task->halted set by worker */
            }
            /* [UNLOCK] schedule */
            lock_basic_unlock(&engine->taskq->schedule_lock);

            wake_up = 1;
        }

        zone->task = task;
        if (status != ODS_STATUS_OK) {
            ods_log_crit("[%s] failed to schedule task for zone %s: %s",
                engine_str, zone->name, ods_status2str(status));
            task_cleanup(task);
            zone->task = NULL;
        }
        node = ldns_rbtree_next(node);
    }
    /* [UNLOCK] zonelist */
    lock_basic_unlock(&engine->zonelist->zl_lock);

    if (wake_up) {
        engine_wakeup_workers(engine);
    }
    return;
}


/**
 * Try to recover from the backup files.
 *
 */
static ods_status
engine_recover(engine_type* engine)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;
    ods_status status = ODS_STATUS_OK;
    ods_status result = ODS_STATUS_UNCHANGED;

    if (!engine || !engine->zonelist || !engine->zonelist->zones) {
        ods_log_error("[%s] cannot update zones: no engine or zonelist",
            engine_str);
        return ODS_STATUS_OK; /* will trigger update zones */
    }
    ods_log_assert(engine);
    ods_log_assert(engine->zonelist);
    ods_log_assert(engine->zonelist->zones);

    lock_basic_lock(&engine->zonelist->zl_lock);
    /* [LOCK] zonelist */
    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->data;

        ods_log_assert(zone->just_added);
        status = zone_recover(zone);
        if (status == ODS_STATUS_OK) {
            ods_log_assert(zone->task);
            ods_log_assert(zone->zonedata);
            ods_log_assert(zone->signconf);
            /* notify nameserver */
            if (engine->config->notify_command && !zone->notify_ns) {
                set_notify_ns(zone, engine->config->notify_command);
            }
            /* zone fetcher enabled? */
            zone->fetch = (engine->config->zonefetch_filename != NULL);
            /* schedule task */
            lock_basic_lock(&engine->taskq->schedule_lock);
            /* [LOCK] schedule */
            status = schedule_task(engine->taskq, (task_type*) zone->task, 0);
            /* [UNLOCK] schedule */
            lock_basic_unlock(&engine->taskq->schedule_lock);

            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] unable to schedule task for zone %s: %s",
                    engine_str, zone->name, ods_status2str(status));
                task_cleanup((task_type*) zone->task);
                zone->task = NULL;
                result = ODS_STATUS_OK; /* will trigger update zones */
            } else {
                ods_log_verbose("[%s] recovered zone %s", engine_str,
                    zone->name);
                /* recovery done */
                zone->just_added = 0;
            }
        } else {
            if (status != ODS_STATUS_UNCHANGED) {
                ods_log_warning("[%s] unable to recover zone %s from backup,"
                " performing full sign", engine_str, zone->name);
            }
            result = ODS_STATUS_OK; /* will trigger update zones */
        }
        node = ldns_rbtree_next(node);
    }
    /* [UNLOCK] zonelist */
    lock_basic_unlock(&engine->zonelist->zl_lock);
    return result;
}


/**
 * Start engine.
 *
 */
void
engine_start(const char* cfgfile, int cmdline_verbosity, int daemonize,
    int info, int single_run)
{
    engine_type* engine = NULL;
    int use_syslog = 0;
    ods_status zl_changed = ODS_STATUS_UNCHANGED;
    ods_status status = ODS_STATUS_OK;

    ods_log_assert(cfgfile);
    ods_log_init(NULL, use_syslog, cmdline_verbosity);
    ods_log_verbose("[%s] starting signer", engine_str);

    /* initialize */
    xmlInitGlobals();
    xmlInitParser();
    xmlInitThreads();
    engine = engine_create();
    if (!engine) {
        ods_fatal_exit("[%s] create failed", engine_str);
        return;
    }
    engine->daemonize = daemonize;

    /* config */
    engine->config = engine_config(engine->allocator, cfgfile,
        cmdline_verbosity);
    status = engine_config_check(engine->config);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] cfgfile %s has errors", engine_str, cfgfile);
        goto earlyexit;
    }
    if (info) {
        engine_config_print(stdout, engine->config); /* for debugging */
        goto earlyexit;
    }

    /* open log */
    ods_log_init(engine->config->log_filename, engine->config->use_syslog,
       engine->config->verbosity);

    /* setup */
    tzset(); /* for portability */
    status = engine_setup(engine);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] setup failed: %s", engine_str,
            ods_status2str(status));
        engine->need_to_exit = 1;
        if (status != ODS_STATUS_WRITE_PIDFILE_ERR) {
            /* command handler had not yet been started */
            engine->cmdhandler_done = 1;
        }
    }

    /* run */
    while (engine->need_to_exit == 0) {
        /* update zone list */
        lock_basic_lock(&engine->zonelist->zl_lock);
        /* [LOCK] zonelist */
        zl_changed = zonelist_update(engine->zonelist,
            engine->config->zonelist_filename);
        engine->zonelist->just_removed = 0;
        engine->zonelist->just_added = 0;
        engine->zonelist->just_updated = 0;
        /* [UNLOCK] zonelist */
        lock_basic_unlock(&engine->zonelist->zl_lock);

        if (engine->need_to_reload) {
            ods_log_info("[%s] signer reloading", engine_str);
            engine->need_to_reload = 0;
        } else {
            ods_log_info("[%s] signer started", engine_str);
            zl_changed = engine_recover(engine);
        }

        /* update zones */
        if (zl_changed == ODS_STATUS_OK) {
            ods_log_debug("[%s] commit zone list changes", engine_str);
            engine_update_zones(engine);
            ods_log_debug("[%s] signer configurations updated", engine_str);
            zl_changed = ODS_STATUS_UNCHANGED;
        }

        engine_run(engine, single_run);
    }

    /* shutdown */
    ods_log_info("[%s] signer shutdown", engine_str);
    stop_zonefetcher(engine);
    hsm_close();
    if (engine->cmdhandler != NULL) {
        engine_stop_cmdhandler(engine);
    }

earlyexit:
    if (engine && engine->config) {
        if (engine->config->pid_filename) {
            (void)unlink(engine->config->pid_filename);
        }
        if (engine->config->clisock_filename) {
            (void)unlink(engine->config->clisock_filename);
        }
    }
    engine_cleanup(engine);
    engine = NULL;
    ods_log_close();
    xmlCleanupParser();
    xmlCleanupGlobals();
    xmlCleanupThreads();
    return;
}


/**
 * Clean up engine.
 *
 */
void
engine_cleanup(engine_type* engine)
{
    size_t i = 0;
    allocator_type* allocator;
    cond_basic_type signal_cond;
    lock_basic_type signal_lock;

    if (!engine) {
        return;
    }
    allocator = engine->allocator;
    signal_cond = engine->signal_cond;
    signal_lock = engine->signal_lock;

    if (engine->workers && engine->config) {
        for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
            worker_cleanup(engine->workers[i]);
        }
        allocator_deallocate(allocator, (void*) engine->workers);
    }
    if (engine->drudgers && engine->config) {
       for (i=0; i < (size_t) engine->config->num_signer_threads; i++) {
           worker_cleanup(engine->drudgers[i]);
       }
        allocator_deallocate(allocator, (void*) engine->drudgers);
    }
    zonelist_cleanup(engine->zonelist);
    schedule_cleanup(engine->taskq);
    fifoq_cleanup(engine->signq);
    cmdhandler_cleanup(engine->cmdhandler);
    engine_config_cleanup(engine->config);
    allocator_deallocate(allocator, (void*) engine);

    lock_basic_destroy(&signal_lock);
    lock_basic_off(&signal_cond);
    allocator_cleanup(allocator);
    return;
}
