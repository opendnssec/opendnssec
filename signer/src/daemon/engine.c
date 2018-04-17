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
 * The engine.
 *
 */

#include "config.h"
#include "daemon/cfg.h"
#include "daemon/engine.h"
#include "daemon/signal.h"
#include "shared/allocator.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/hsm.h"
#include "shared/locks.h"
#include "shared/log.h"
#include "shared/privdrop.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/zonelist.h"
#include "wire/tsig.h"
#include "libhsm.h"

#include <errno.h>
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
        ods_log_error("[%s] unable to create engine: allocator_create() "
            "failed", engine_str);
        return NULL;
    }
    engine = (engine_type*) allocator_alloc(allocator, sizeof(engine_type));
    if (!engine) {
        ods_log_error("[%s] unable to create engine: allocator_alloc() "
            "failed", engine_str);
        allocator_cleanup(allocator);
        return NULL;
    }
    engine->allocator = allocator;
    engine->config = NULL;
    engine->workers = NULL;
    engine->drudgers = NULL;
    engine->cmdhandler = NULL;
    engine->cmdhandler_done = 0;
    engine->dnshandler = NULL;
    engine->xfrhandler = NULL;
    engine->pid = -1;
    engine->uid = -1;
    engine->gid = -1;
    engine->daemonize = 0;
    engine->need_to_exit = 0;
    engine->need_to_reload = 0;
    lock_basic_init(&engine->signal_lock);
    lock_basic_set(&engine->signal_cond);
    lock_basic_lock(&engine->signal_lock);
    engine->signal = SIGNAL_INIT;
    lock_basic_unlock(&engine->signal_lock);
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
    if (sockfd < 0) {
        ods_log_error("[%s] unable to connect to command handler: "
            "socket() failed (%s)", engine_str, strerror(errno));
        return 1;
    } else {
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sun_family = AF_UNIX;
        strncpy(servaddr.sun_path, servsock_filename,
            sizeof(servaddr.sun_path) - 1);
        ret = connect(sockfd, (const struct sockaddr*) &servaddr,
            sizeof(servaddr));
        if (ret != 0) {
            ods_log_error("[%s] unable to connect to command handler: "
                "connect() failed (%s)", engine_str, strerror(errno));
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
    if (!engine->cmdhandler || engine->cmdhandler_done) {
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
}


/**
 * Start/stop dnshandler.
 *
 */
static void*
dnshandler_thread_start(void* arg)
{
    dnshandler_type* dnshandler = (dnshandler_type*) arg;
    dnshandler_start(dnshandler);
    return NULL;
}
static void
engine_start_dnshandler(engine_type* engine)
{
    if (!engine || !engine->dnshandler) {
        return;
    }
    ods_log_debug("[%s] start dnshandler", engine_str);
    engine->dnshandler->engine = engine;
    ods_thread_create(&engine->dnshandler->thread_id,
        dnshandler_thread_start, engine->dnshandler);
}
static void
engine_stop_dnshandler(engine_type* engine)
{
    if (!engine || !engine->dnshandler || !engine->dnshandler->thread_id) {
        return;
    }
    ods_log_debug("[%s] stop dnshandler", engine_str);
    engine->dnshandler->need_to_exit = 1;
    dnshandler_signal(engine->dnshandler);
    ods_log_debug("[%s] join dnshandler", engine_str);
    ods_thread_join(engine->dnshandler->thread_id);
    engine->dnshandler->engine = NULL;
}


/**
 * Start/stop xfrhandler.
 *
 */
static void*
xfrhandler_thread_start(void* arg)
{
    xfrhandler_type* xfrhandler = (xfrhandler_type*) arg;
    xfrhandler_start(xfrhandler);
    return NULL;
}
static void
engine_start_xfrhandler(engine_type* engine)
{
    if (!engine || !engine->xfrhandler) {
        return;
    }
    ods_log_debug("[%s] start xfrhandler", engine_str);
    engine->xfrhandler->engine = engine;
    ods_thread_create(&engine->xfrhandler->thread_id,
        xfrhandler_thread_start, engine->xfrhandler);
    /* This might be the wrong place to mark the xfrhandler started but
     * if its isn't done here we might try to shutdown and stop it before
     * it has marked itself started
     */
    engine->xfrhandler->started = 1;
}
static void
engine_stop_xfrhandler(engine_type* engine)
{
    if (!engine || !engine->xfrhandler) {
        return;
    }
    ods_log_debug("[%s] stop xfrhandler", engine_str);
    engine->xfrhandler->need_to_exit = 1;
    xfrhandler_signal(engine->xfrhandler);
    ods_log_debug("[%s] join xfrhandler", engine_str);
    if (engine->xfrhandler->started) {
    	ods_thread_join(engine->xfrhandler->thread_id);
    	engine->xfrhandler->started = 0;
    }
    engine->xfrhandler->engine = NULL;
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
        engine->workers[i]->engine = (void*) engine;
        ods_thread_create(&engine->workers[i]->thread_id, worker_thread_start,
            engine->workers[i]);
    }
}
void
engine_start_drudgers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] start drudgers", engine_str);
    for (i=0; i < (size_t) engine->config->num_signer_threads; i++) {
        engine->drudgers[i]->need_to_exit = 0;
        engine->drudgers[i]->engine = (void*) engine;
        ods_thread_create(&engine->drudgers[i]->thread_id, worker_thread_start,
            engine->drudgers[i]);
    }
}
static void
engine_stop_workers(engine_type* engine)
{
    int i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] stop workers", engine_str);
    /* tell them to exit and wake up sleepyheads */
    for (i=0; i < engine->config->num_worker_threads; i++) {
        engine->workers[i]->need_to_exit = 1;
        worker_wakeup(engine->workers[i]);
    }
    ods_log_debug("[%s] notify workers", engine_str);
    worker_notify_all(&engine->signq->q_lock, &engine->signq->q_nonfull);
    /* head count */
    for (i=0; i < engine->config->num_worker_threads; i++) {
        ods_log_debug("[%s] join worker %d", engine_str, i+1);
        ods_thread_join(engine->workers[i]->thread_id);
        engine->workers[i]->engine = NULL;
    }
}
void
engine_stop_drudgers(engine_type* engine)
{
    int i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] stop drudgers", engine_str);
    /* tell them to exit and wake up sleepyheads */
    for (i=0; i < engine->config->num_signer_threads; i++) {
        engine->drudgers[i]->need_to_exit = 1;
    }
    ods_log_debug("[%s] notify drudgers", engine_str);
    worker_notify_all(&engine->signq->q_lock, &engine->signq->q_threshold);
    /* head count */
    for (i=0; i < engine->config->num_signer_threads; i++) {
        ods_log_debug("[%s] join drudger %d", engine_str, i+1);
        ods_thread_join(engine->drudgers[i]->thread_id);
        engine->drudgers[i]->engine = NULL;
    }
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
}


/**
 * Set up engine.
 *
 */
static ods_status
engine_setup(engine_type* engine)
{
    ods_status status = ODS_STATUS_OK;
    struct sigaction action;
    int sockets[2] = {0,0};

    ods_log_debug("[%s] setup signer engine", engine_str);
    if (!engine || !engine->config) {
        return ODS_STATUS_ASSERT_ERR;
    }
    /* set edns */
    edns_init(&engine->edns, EDNS_MAX_MESSAGE_LEN);

    /* create command handler (before chowning socket file) */
    engine->cmdhandler = cmdhandler_create(engine->allocator,
        engine->config->clisock_filename);
    if (!engine->cmdhandler) {
        return ODS_STATUS_CMDHANDLER_ERR;
    }
    engine->dnshandler = dnshandler_create(engine->allocator,
        engine->config->interfaces);
    engine->xfrhandler = xfrhandler_create(engine->allocator);
    if (!engine->xfrhandler) {
        return ODS_STATUS_XFRHANDLER_ERR;
    }
    if (engine->dnshandler) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == -1) {
            return ODS_STATUS_XFRHANDLER_ERR;
        }
        engine->xfrhandler->dnshandler.fd = sockets[0];
        engine->dnshandler->xfrhandler.fd = sockets[1];
        status = dnshandler_listen(engine->dnshandler);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] setup: unable to listen to sockets (%s)",
                engine_str, ods_status2str(status));
            return ODS_STATUS_XFRHANDLER_ERR;
        }
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
        ods_log_error("[%s] setup: unable to chdir to %s (%s)", engine_str,
            engine->config->working_dir, strerror(errno));
        return ODS_STATUS_CHDIR_ERR;
    }
    if (engine_privdrop(engine) != ODS_STATUS_OK) {
        return ODS_STATUS_PRIVDROP_ERR;
    }
    /* daemonize */
    if (engine->daemonize) {
        switch ((engine->pid = fork())) {
            case -1: /* error */
                ods_log_error("[%s] setup: unable to fork daemon (%s)",
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
            ods_log_error("[%s] setup: unable to setsid daemon (%s)",
                engine_str, strerror(errno));
            return ODS_STATUS_SETSID_ERR;
        }
    }
    engine->pid = getpid();
    ods_log_verbose("[%s] running as pid %lu", engine_str,
        (unsigned long) engine->pid);
    /* catch signals */
    signal_set_engine(engine);
    action.sa_handler = (void (*)(int))signal_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGILL, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGALRM, &action, NULL);
    sigaction(SIGCHLD, &action, NULL);
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);
    /* create workers/drudgers */
    engine_create_workers(engine);
    engine_create_drudgers(engine);
    /* start cmd/dns/xfr handlers */
    engine_start_cmdhandler(engine);
    engine_start_dnshandler(engine);
    engine_start_xfrhandler(engine);
    tsig_handler_init(engine->allocator);
    /* write pidfile */
    if (util_write_pidfile(engine->config->pid_filename, engine->pid) == -1) {
        hsm_close();
        return ODS_STATUS_WRITE_PIDFILE_ERR;
    }
    /* setup done */
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
        ods_log_assert(zone);
        ods_log_assert(zone->db);
        if (!zone->db->is_processed) {
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
    engine_start_workers(engine);
    engine_start_drudgers(engine);

    lock_basic_lock(&engine->signal_lock);
    engine->signal = SIGNAL_RUN;
    lock_basic_unlock(&engine->signal_lock);

    while (!engine->need_to_exit && !engine->need_to_reload) {
        lock_basic_lock(&engine->signal_lock);
        engine->signal = signal_capture(engine->signal);
        switch (engine->signal) {
            case SIGNAL_RUN:
                ods_log_assert(1);
                break;
            case SIGNAL_RELOAD:
                ods_log_error("signer instructed to reload due to explicit signal");
                engine->need_to_reload = 1;
                break;
            case SIGNAL_SHUTDOWN:
                engine->need_to_exit = 1;
                break;
            default:
                ods_log_warning("[%s] invalid signal %d captured, "
                    "keep running", engine_str, (int)engine->signal);
                engine->signal = SIGNAL_RUN;
                break;
        }
        lock_basic_unlock(&engine->signal_lock);

        if (single_run) {
           engine->need_to_exit = engine_all_zones_processed(engine);
        }
        lock_basic_lock(&engine->signal_lock);
        if (engine->signal == SIGNAL_RUN && !single_run) {
           ods_log_debug("[%s] taking a break", engine_str);
           lock_basic_sleep(&engine->signal_cond, &engine->signal_lock, 3600);
        }
        lock_basic_unlock(&engine->signal_lock);
    }
    ods_log_debug("[%s] signer halted", engine_str);
    engine_stop_drudgers(engine);
    engine_stop_workers(engine);
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
    char* token = NULL;
    ods_log_assert(cmd);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->adoutbound);
    if (zone->adoutbound->type == ADAPTER_FILE) {
        str = ods_replace(cmd, "%zonefile", zone->adoutbound->configstr);
        if (!str) {
            ods_log_error("[%s] unable to set notify ns: replace zonefile failed",
                engine_str);
        }
        str2 = ods_replace(str, "%zone", zone->name);
        free((void*)str);
    } else {
        str2 = ods_replace(cmd, "%zone", zone->name);
    }
    if (str2) {
        ods_str_trim((char*) str2);
        str = str2;
        if (*str) {
            token = NULL;
            while ((token = strtok((char*) str, " "))) {
                if (*token) {
                    ods_str_list_add(&zone->notify_args, token);
                }
                str = NULL;
            }
        }
        zone->notify_command = (char*) str2;
        zone->notify_ns = zone->notify_args[0];
        ods_log_debug("[%s] set notify ns: %s", engine_str, zone->notify_ns);
    } else {
        ods_log_error("[%s] unable to set notify ns: replace zone failed",
            engine_str);
    }
}


/**
 * Update DNS configuration for zone.
 *
 */
static int
dnsconfig_zone(engine_type* engine, zone_type* zone)
{
    int numdns = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->xfrhandler);
    ods_log_assert(engine->xfrhandler->netio);
    ods_log_assert(zone);
    ods_log_assert(zone->adinbound);
    ods_log_assert(zone->adoutbound);
    ods_log_assert(zone->name);

    if (zone->adinbound->type == ADAPTER_DNS) {
        /* zone transfer handler */
        if (!zone->xfrd) {
            ods_log_debug("[%s] add transfer handler for zone %s",
                engine_str, zone->name);
            zone->xfrd = xfrd_create((void*) engine->xfrhandler,
                (void*) zone);
            ods_log_assert(zone->xfrd);
            netio_add_handler(engine->xfrhandler->netio,
                &zone->xfrd->handler);
        } else if (!zone->xfrd->serial_disk_acquired) {
            xfrd_set_timer_now(zone->xfrd);
        }
        numdns++;
    } else if (zone->xfrd) {
        netio_remove_handler(engine->xfrhandler->netio,
            &zone->xfrd->handler);
        xfrd_cleanup(zone->xfrd, 0);
        zone->xfrd = NULL;
    }
    if (zone->adoutbound->type == ADAPTER_DNS) {
        /* notify handler */
        if (!zone->notify) {
            ods_log_debug("[%s] add notify handler for zone %s",
                engine_str, zone->name);
            zone->notify = notify_create((void*) engine->xfrhandler,
                (void*) zone);
            ods_log_assert(zone->notify);
            netio_add_handler(engine->xfrhandler->netio,
                &zone->notify->handler);
        }
        numdns++;
    } else if (zone->notify) {
        netio_remove_handler(engine->xfrhandler->netio,
            &zone->notify->handler);
        notify_cleanup(zone->notify);
        zone->notify = NULL;
    }
    return numdns;
}


/**
 * Update zones.
 *
 */
void
engine_update_zones(engine_type* engine, ods_status zl_changed)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;
    zone_type* delzone = NULL;
    task_type* task = NULL;
    ods_status status = ODS_STATUS_OK;
    unsigned wake_up = 0;
    int warnings = 0;
    time_t now = 0;

    if (!engine || !engine->zonelist || !engine->zonelist->zones) {
        return;
    }
    now = time_now();

    ods_log_debug("[%s] commit zone list changes", engine_str);
    lock_basic_lock(&engine->zonelist->zl_lock);
    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->data;
        task = NULL; /* reset task */

        if (zone->zl_status == ZONE_ZL_REMOVED) {
            node = ldns_rbtree_next(node);
            lock_basic_lock(&zone->zone_lock);
            delzone = zonelist_del_zone(engine->zonelist, zone);
            if (delzone) {
                lock_basic_lock(&engine->taskq->schedule_lock);
                task = unschedule_task(engine->taskq,
                    (task_type*) zone->task);
                lock_basic_unlock(&engine->taskq->schedule_lock);
            }
            task_cleanup(task);
            task = NULL;
            lock_basic_unlock(&zone->zone_lock);
            netio_remove_handler(engine->xfrhandler->netio,
                &zone->xfrd->handler);
            netio_remove_handler(engine->xfrhandler->netio,
                &zone->notify->handler);
            zone_cleanup(zone);
            zone = NULL;
            continue;
        } else if (zone->zl_status == ZONE_ZL_ADDED) {
            lock_basic_lock(&zone->zone_lock);
            ods_log_assert(!zone->task);
            /* set notify nameserver command */
            if (engine->config->notify_command && !zone->notify_ns) {
                set_notify_ns(zone, engine->config->notify_command);
            }
            /* create task */
            task = task_create(TASK_SIGNCONF, now, zone);
            lock_basic_unlock(&zone->zone_lock);
            if (!task) {
                ods_log_crit("[%s] unable to create task for zone %s: "
                    "task_create() failed", engine_str, zone->name);
                node = ldns_rbtree_next(node);
                continue;
            }
        }
        /* load adapter config */
        status = adapter_load_config(zone->adinbound);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to load config for inbound adapter "
                "for zone %s: %s", engine_str, zone->name,
                ods_status2str(status));
        }
        status = adapter_load_config(zone->adoutbound);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to load config for outbound adapter "
                "for zone %s: %s", engine_str, zone->name,
                ods_status2str(status));
        }
        /* for dns adapters */
        warnings += dnsconfig_zone(engine, zone);

        if (zone->zl_status == ZONE_ZL_ADDED) {
            ods_log_assert(task);
            lock_basic_lock(&zone->zone_lock);
            zone->task = task;
            lock_basic_unlock(&zone->zone_lock);
            /* TODO: task is reachable from other threads by means of
             * zone->task. To fix this we need to nest the locks. But
             * first investigate any possible deadlocks. */
            lock_basic_lock(&engine->taskq->schedule_lock);
            status = schedule_task(engine->taskq, task, 0);
            lock_basic_unlock(&engine->taskq->schedule_lock);
        } else if (zl_changed == ODS_STATUS_OK) {
            /* always try to update signconf */
            lock_basic_lock(&zone->zone_lock);
            status = zone_reschedule_task(zone, engine->taskq, TASK_SIGNCONF);
            lock_basic_unlock(&zone->zone_lock);
        }
        if (status != ODS_STATUS_OK) {
            ods_log_crit("[%s] unable to schedule task for zone %s: %s",
                engine_str, zone->name, ods_status2str(status));
        } else {
            wake_up = 1;
            zone->zl_status = ZONE_ZL_OK;
        }
        node = ldns_rbtree_next(node);
    }
    lock_basic_unlock(&engine->zonelist->zl_lock);
    if (engine->dnshandler) {
        ods_log_debug("[%s] forward notify for all zones", engine_str);
        dnshandler_fwd_notify(engine->dnshandler,
            (uint8_t*) ODS_SE_NOTIFY_CMD, strlen(ODS_SE_NOTIFY_CMD));
    } else if (warnings) {
        ods_log_warning("[%s] no dnshandler/listener configured, but zones "
         "are configured with dns adapters: notify and zone transfer "
         "requests will not work properly", engine_str);
    }
    if (wake_up) {
        engine_wakeup_workers(engine);
    }
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
        ods_log_error("[%s] cannot recover zones: no engine or zonelist",
            engine_str);
        return ODS_STATUS_ERR; /* no need to update zones */
    }
    ods_log_assert(engine);
    ods_log_assert(engine->zonelist);
    ods_log_assert(engine->zonelist->zones);

    lock_basic_lock(&engine->zonelist->zl_lock);
    /* [LOCK] zonelist */
    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->data;

        ods_log_assert(zone->zl_status == ZONE_ZL_ADDED);
        lock_basic_lock(&zone->zone_lock);
        status = zone_recover2(zone);
        if (status == ODS_STATUS_OK) {
            ods_log_assert(zone->task);
            ods_log_assert(zone->db);
            ods_log_assert(zone->signconf);
            /* notify nameserver */
            if (engine->config->notify_command && !zone->notify_ns) {
                set_notify_ns(zone, engine->config->notify_command);
            }
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
                ods_log_debug("[%s] recovered zone %s", engine_str,
                    zone->name);
                /* recovery done */
                zone->zl_status = ZONE_ZL_OK;
            }
        } else {
            if (status != ODS_STATUS_UNCHANGED) {
                ods_log_warning("[%s] unable to recover zone %s from backup,"
                " performing full sign", engine_str, zone->name);
            }
            result = ODS_STATUS_OK; /* will trigger update zones */
        }
        lock_basic_unlock(&zone->zone_lock);
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
    /* check pidfile */
    if (!util_check_pidfile(engine->config->pid_filename)) {
        exit(1);
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
        if (status != ODS_STATUS_WRITE_PIDFILE_ERR) {
            /* command handler had not yet been started */
            engine->cmdhandler_done = 1;
        }
        goto earlyexit;
    }

    /* run */
    while (engine->need_to_exit == 0) {
        /* update zone list */
        lock_basic_lock(&engine->zonelist->zl_lock);
        zl_changed = zonelist_update(engine->zonelist,
            engine->config->zonelist_filename);
        engine->zonelist->just_removed = 0;
        engine->zonelist->just_added = 0;
        engine->zonelist->just_updated = 0;
        lock_basic_unlock(&engine->zonelist->zl_lock);
        /* start/reload */
        if (engine->need_to_reload) {
            ods_log_info("[%s] signer reloading", engine_str);
            fifoq_wipe(engine->signq);
            engine->need_to_reload = 0;
        } else {
            ods_log_info("[%s] signer started (version %s), pid %u",
                engine_str, PACKAGE_VERSION, engine->pid);
            if (hsm_open(engine->config->cfg_filename, hsm_check_pin) != HSM_OK) {
                char* error =  hsm_get_error(NULL);
                if (error != NULL) {
                    ods_log_error("[%s] %s", "hsm", error);
                    free(error);
                }
                ods_log_error("[%s] opening hsm failed (for engine recover)", engine_str);
                break;
            }
            zl_changed = engine_recover(engine);
            hsm_close();
        }
        if (zl_changed == ODS_STATUS_OK ||
            zl_changed == ODS_STATUS_UNCHANGED) {
            engine_update_zones(engine, zl_changed);
        }
        if (hsm_open(engine->config->cfg_filename, hsm_check_pin) != HSM_OK) {
            char* error =  hsm_get_error(NULL);
            if (error != NULL) {
                ods_log_error("[%s] %s", "hsm", error);
                free(error);
            }
            ods_log_error("[%s] opening hsm failed (for engine run)", engine_str);
            break;
        }
        engine_run(engine, single_run);
        hsm_close();
    }

    /* shutdown */
    ods_log_info("[%s] signer shutdown", engine_str);
    engine_stop_cmdhandler(engine);
    engine_stop_xfrhandler(engine);
    engine_stop_dnshandler(engine);

earlyexit:
    if (engine && engine->config) {
        if (engine->config->pid_filename) {
            (void)unlink(engine->config->pid_filename);
        }
        if (engine->config->clisock_filename) {
            (void)unlink(engine->config->clisock_filename);
        }
    }
    tsig_handler_cleanup();
    engine_cleanup(engine);
    engine = NULL;
    ods_log_close();
    xmlCleanupParser();
    xmlCleanupGlobals();
    xmlCleanupThreads();
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
    dnshandler_cleanup(engine->dnshandler);
    xfrhandler_cleanup(engine->xfrhandler);
    engine_config_cleanup(engine->config);
    allocator_deallocate(allocator, (void*) engine);
    lock_basic_destroy(&signal_lock);
    lock_basic_off(&signal_cond);
    allocator_cleanup(allocator);
}
