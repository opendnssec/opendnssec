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
#include "signer/zone.h"
#include "signer/zonelist.h"
#include "tools/zone_fetcher.h"
#include "util/se_malloc.h"

#include <errno.h>
#include <libhsm.h>
#include <libxml/parser.h>
#include <malloc.h>
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
        allocator->deallocator(allocator);
        return NULL;
    }
    engine->allocator = allocator;
    engine->config = NULL;
    engine->daemonize = 0;
    engine->workers = NULL;
    engine->cmdhandler = NULL;
    engine->cmdhandler_done = 0;
    engine->pid = -1;
    engine->zfpid = -1;
    engine->uid = -1;
    engine->gid = -1;
    engine->need_to_exit = 0;
    engine->need_to_reload = 0;

    engine->zonelist = zonelist_create();
    if (!engine->zonelist) {
        engine_cleanup(engine);
        return NULL;
    }
    engine->taskq = schedule_create(engine->allocator);
    if (!engine->taskq) {
        engine_cleanup(engine);
        return NULL;
    }

    lock_basic_init(&engine->signal_lock);
    lock_basic_set(&engine->signal_cond);
    return engine;
}


/**
 * Start command handler thread.
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


/**
 * Start command handler.
 *
 */
static int
engine_start_cmdhandler(engine_type* engine)
{
    ods_log_assert(engine);
    ods_log_debug("[%s] start command handler", engine_str);
    engine->cmdhandler->engine = engine;
    ods_thread_create(&engine->cmdhandler->thread_id,
        cmdhandler_thread_start, engine->cmdhandler);
    return 0;
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
static int
engine_privdrop(engine_type* engine)
{
    int error;
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
        ods_log_verbose("[%s] chroot to %s", engine_str, engine->config->chroot);
    }
    error = privdrop(engine->config->username, engine->config->group,
        engine->config->chroot, &uid, &gid);
    engine->uid = uid;
    engine->gid = gid;
    privclose(engine->config->username, engine->config->group);
    return error;
}


/**
 * Stop parent process.
 *
 */
static void
parent_cleanup(engine_type* engine, int keep_pointer)
{
    if (engine) {
        if (engine->config) {
            engine_config_cleanup(engine->config);
            engine->config = NULL;
        }
        if (!keep_pointer) {
            se_free((void*) engine);
        }
    }
}


/**
 * Write process id to file.
 *
 */
static int
write_pidfile(const char* pidfile, pid_t pid)
{
    FILE* fd;
    char pidbuf[32];
    size_t result = 0, size = 0;

    ods_log_assert(pidfile);
    ods_log_assert(pid);
    ods_log_debug("writing pid %lu to pidfile %s", (unsigned long) pid,
        pidfile?pidfile:"(null)");
    snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long) pid);
    fd = ods_fopen(pidfile, NULL, "w");
    if (!fd) {
        return -1;
    }
    size = strlen(pidbuf);
    if (size == 0) {
        result = 1;
    } else {
        result = fwrite((const void*) pidbuf, 1, size, fd);
    }
    if (result == 0) {
        ods_log_error("write to pidfile %s failed: %s", pidfile?pidfile:"(null)",
            strerror(errno));
    } else if (result < size) {
        ods_log_error("short write to pidfile %s: disk full?",
            pidfile?pidfile:"(null)");
        result = 0;
    } else {
        result = 1;
    }
    ods_fclose(fd);
    if (!result) {
        return -1;
    }
    return 0;
}


/**
 * Create workers.
 *
 */
static void
engine_create_workers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    engine->workers = (worker_type**)
        se_calloc((size_t)engine->config->num_worker_threads,
        sizeof(worker_type*));

    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        engine->workers[i] = worker_create(i, WORKER_WORKER);
    }
    return;
}


/**
 * Start worker thread.
 *
 */
static void*
worker_thread_start(void* arg)
{
    worker_type* worker = (worker_type*) arg;
    ods_thread_blocksigs();
    worker_start(worker);
    return NULL;
}


/**
 * Start workers.
 *
 */
static void
engine_start_workers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] start workers", engine_str);
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        engine->workers[i]->need_to_exit = 0;
        engine->workers[i]->engineptr = (struct engine_struct*) engine;
        ods_thread_create(&engine->workers[i]->thread_id, worker_thread_start,
            engine->workers[i]);
    }
    return;
}


/**
 * Stop workers.
 *
 */
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
        engine->workers[i]->engineptr = NULL;
    }
    return;
}


/**
 * Search for zone in workers
 *
 */
int
engine_search_workers(engine_type* engine, const char* zone_name)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);

    if (!zone_name) {
        return 1;
    }

    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        if (engine->workers[i]->task &&
            ods_strcmp(engine->workers[i]->task->who, zone_name) == 0) {
            /* ba-da bing */
            return 0;
        }
    }
    /* no potato */
    return 1;
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

    zf_filename = se_strdup(engine->config->zonefetch_filename);
    zl_filename = se_strdup(engine->config->zonelist_filename);
    grp = se_strdup(engine->config->group);
    usr = se_strdup(engine->config->username);
    chrt = se_strdup(engine->config->chroot);
    log_filename = se_strdup(engine->config->log_filename);
    use_syslog = engine->config->use_syslog;
    verbosity = engine->config->verbosity;

    result = tools_zone_fetcher(zf_filename, zl_filename, grp, usr,
        chrt, log_filename, use_syslog, verbosity);

    ods_log_verbose("zone fetcher done", result);
    if (zf_filename)  { se_free((void*)zf_filename); }
    if (zl_filename)  { se_free((void*)zl_filename); }
    if (grp)          { se_free((void*)grp); }
    if (usr)          { se_free((void*)usr); }
    if (chrt)         { se_free((void*)chrt); }
    if (log_filename) { se_free((void*)log_filename); }

    cmdhandler_cleanup(engine->cmdhandler);
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
                ods_log_error("cannot reload zone fetcher: %s", strerror(errno));
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
 * Set up engine.
 *
 */
static int
engine_setup(engine_type* engine)
{
    struct sigaction action;
    int result = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] signer setup", engine_str);

    /* create command handler (before chowning socket file) */
    engine->cmdhandler = cmdhandler_create(engine->config->clisock_filename);
    if (!engine->cmdhandler) {
        ods_log_error("[%s] create command handler to %s failed",
            engine_str, engine->config->clisock_filename);
        return 1;
    }

    /* fork of fetcher */
    if (start_zonefetcher(engine) != 0) {
        ods_log_error("[%s] cannot start zonefetcher", engine_str);
        cmdhandler_cleanup(engine->cmdhandler);
        engine->cmdhandler = NULL;
        return 1;
    }

    /* privdrop */
    engine->uid = privuid(engine->config->username);
    engine->gid = privgid(engine->config->group);
    /* TODO: does piddir exists? */
    /* remove the chown stuff: piddir? */
    /* chown pidfile directory */
    ods_chown(engine->config->pid_filename, engine->uid, engine->gid, 1);
    /* chown sockfile */
    ods_chown(engine->config->clisock_filename, engine->uid, engine->gid, 0);
    /* chown workdir */
    ods_chown(engine->config->working_dir, engine->uid, engine->gid, 0);
    if (engine->config->log_filename && !engine->config->use_syslog) {
        /* chown logfile */
        ods_chown(engine->config->log_filename, engine->uid, engine->gid, 0);
    }
    if (engine->config->working_dir &&
        chdir(engine->config->working_dir) != 0) {
        ods_log_error("[%s] setup failed: chdir to %s failed: %s", engine_str,
            engine->config->working_dir, strerror(errno));
        cmdhandler_cleanup(engine->cmdhandler);
        engine->cmdhandler = NULL;
        return 1;
    }

    if (engine_privdrop(engine) != 0) {
        ods_log_error("[%s] setup failed: unable to drop privileges", engine_str);
        cmdhandler_cleanup(engine->cmdhandler);
        engine->cmdhandler = NULL;
        return 1;
    }

    /* daemonize */
    if (engine->daemonize) {
        switch ((engine->pid = fork())) {
            case -1: /* error */
                ods_log_error("[%s] setup failed: unable to fork daemon: %s",
                    engine_str, strerror(errno));
                cmdhandler_cleanup(engine->cmdhandler);
                engine->cmdhandler = NULL;
                return 1;
            case 0: /* child */
                break;
            default: /* parent */
                cmdhandler_cleanup(engine->cmdhandler);
                engine->cmdhandler = NULL;
                parent_cleanup(engine, 0);
                xmlCleanupParser();
                xmlCleanupGlobals();
                xmlCleanupThreads();
                exit(0);
        }
        if (setsid() == -1) {
            ods_log_error("[%s] setup failed: unable to setsid daemon (%s)",
                engine_str, strerror(errno));
            cmdhandler_cleanup(engine->cmdhandler);
            engine->cmdhandler = NULL;
            return 1;
        }
    }
    engine->pid = getpid();
    /* make common with enforcer */
    if (write_pidfile(engine->config->pid_filename, engine->pid) == -1) {
        ods_log_error("[%s] setup failed: unable to write pid file", engine_str);
        cmdhandler_cleanup(engine->cmdhandler);
        engine->cmdhandler = NULL;
        return 1;
    }
    ods_log_verbose("[%s] running as pid %lu", engine_str,
        (unsigned long) engine->pid);

    /* start command handler */
    if (engine_start_cmdhandler(engine) != 0) {
        ods_log_error("[%s] setup failed: unable to start command handler", engine_str);
        cmdhandler_cleanup(engine->cmdhandler);
        engine->cmdhandler = NULL;
        return 1;
    }

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
        ods_log_error("[%s] setup failed: error initializing libhsm (errno %i)",
            engine_str, result);
        cmdhandler_cleanup(engine->cmdhandler);
        engine->cmdhandler = NULL;
        return 1;
    }

    /* set up the work floor */
    engine_create_workers(engine); /* workers */

    return 0;
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
 * Engine running.
 *
 */
static void
engine_run(engine_type* engine, int single_run)
{
    if (!engine) {
        return;
    }
    ods_log_assert(engine);

    engine->signal = SIGNAL_RUN;
    while (engine->need_to_exit == 0 && engine->need_to_reload == 0) {
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
    return;
}


/**
 * Update zone list.
 *
 */
int
engine_update_zonelist(engine_type* engine, char* buf)
{
    zonelist_type* new_zlist = NULL;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_assert(engine->zonelist);
    ods_log_debug("update zone list");

    new_zlist = zonelist_read(engine->config->zonelist_filename,
        engine->zonelist->last_modified);
    if (!new_zlist) {
        if (buf) {
            /* fstat <= last_modified || rng check failed */
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone list has not changed.\n");
        }
        return 1;
    }

    zonelist_lock(engine->zonelist);
    zonelist_merge(engine->zonelist, new_zlist);
    zonelist_update(engine->zonelist, engine->taskq,
        engine->config->notify_command, buf);
    zonelist_unlock(engine->zonelist);
    return 0;
}


/**
 * Parse notify command.
 *
 */
void
set_notify_ns(zone_type* zone, const char* cmd)
{
    const char* str = NULL;
    const char* str2 = NULL;

    ods_log_assert(cmd);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->outbound_adapter);
    ods_log_assert(zone->outbound_adapter->filename);

    str = ods_replace(cmd, "%zonefile", zone->outbound_adapter->filename);
    str2 = ods_replace(str, "%zone", zone->name);
    se_free((void*)str);
    zone->notify_ns = (const char*) str2;
    ods_log_debug("set notify ns: %s", zone->notify_ns);

    return;
}


/**
 * Update zones.
 *
 */
int
engine_update_zones(engine_type* engine, const char* zone_name, char* buf,
    int first_try)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;
    int tmp = 0;
    int unchanged = 0;
    int errors = 0;
    int updated = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->zonelist);
    ods_log_assert(engine->zonelist->zones);

    reload_zonefetcher(engine);

    lock_basic_lock(&engine->taskq->schedule_lock);
    engine->taskq->loading = 1;
    lock_basic_unlock(&engine->taskq->schedule_lock);

    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->key;

        lock_basic_lock(&zone->zone_lock);

        if (!zone_name || ods_strcmp(zone->name, zone_name) == 0) {
            if (zone_name) {
                ods_log_debug("update zone %s (signconf file %s)", zone->name,
                    zone->signconf_filename?zone->signconf_filename:"(null)");
                lock_basic_lock(&engine->taskq->schedule_lock);
                tmp = zone_update_signconf(zone, engine->taskq, buf);
                zone->fetch = (engine->config->zonefetch_filename != NULL);
                engine->taskq->loading = 0;

                lock_basic_unlock(&engine->taskq->schedule_lock);
                lock_basic_unlock(&zone->zone_lock);
                return 0;
            }

            lock_basic_lock(&engine->taskq->schedule_lock);
            tmp = zone_update_signconf(zone, engine->taskq, buf);
            zone->fetch = (engine->config->zonefetch_filename != NULL);

            lock_basic_unlock(&engine->taskq->schedule_lock);

            if (tmp < 0) {
                errors++;
            } else if (tmp > 0) {
                updated++;
            } else {
                unchanged++;
            }
        }

        lock_basic_unlock(&zone->zone_lock);
        node = ldns_rbtree_next(node);
    }

    lock_basic_lock(&engine->taskq->schedule_lock);
    engine->taskq->loading = 0;
    lock_basic_unlock(&engine->taskq->schedule_lock);

    if (zone_name) {
        ods_log_debug("zone %s not found", zone_name);
        if (buf) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s not found%s.\n",
            zone_name, first_try?", updating zone list":"");
        }
        return 1;
    } else {
        ods_log_debug("configurations updated");
        if (buf) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Configurations updated: %i; "
                "errors: %i; unchanged: %i.\n", updated, errors, unchanged);
        }
    }
    return 0;
}


/**
 * Try to recover from the backup files.
 *
 */
static void
engine_recover_from_backups(engine_type* engine)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;

    ods_log_assert(engine);
    ods_log_assert(engine->zonelist);
    ods_log_assert(engine->zonelist->zones);

    lock_basic_lock(&engine->taskq->schedule_lock);
    engine->taskq->loading = 1;
    lock_basic_unlock(&engine->taskq->schedule_lock);

    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->key;
        lock_basic_lock(&zone->zone_lock);

        /* set the notify ns command */
        if (engine->config->notify_command && !zone->notify_ns) {
            set_notify_ns(zone, engine->config->notify_command);
        }

        lock_basic_lock(&engine->taskq->schedule_lock);
        zone_recover_from_backup(zone, engine->taskq);
        lock_basic_unlock(&engine->taskq->schedule_lock);
        lock_basic_unlock(&zone->zone_lock);
        node = ldns_rbtree_next(node);
    }

    lock_basic_lock(&engine->taskq->schedule_lock);
    engine->taskq->loading = 0;
    lock_basic_unlock(&engine->taskq->schedule_lock);

    return;
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
    int zl_changed = 0;

    ods_log_assert(cfgfile);
    ods_log_init(NULL, use_syslog, cmdline_verbosity);
    ods_log_verbose("[%s] starting signer", engine_str);

    /* initialize */
    xmlInitGlobals();
    xmlInitParser();
    engine = engine_create();
    if (!engine) {
        ods_fatal_exit("[%s] create failed", engine_str);
        return;
    }
    engine->daemonize = daemonize;

    /* config */
    engine->config = engine_config(cfgfile, cmdline_verbosity);
    if (engine_check_config(engine->config) != 0) {
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
    if (engine_setup(engine) != 0) {
        ods_log_error("[%s] setup failed", engine_str);
        engine->need_to_exit = 1;
    }

    /* run */
    while (engine->need_to_exit == 0) {
        zl_changed = (engine_update_zonelist(engine, NULL) == 0);

        if (engine->need_to_reload) {
            ods_log_info("[%s] signer reloading", engine_str);
            engine->need_to_reload = 0;
        } else {
            ods_log_info("[%s] signer started", engine_str);
            /* try to recover from backups */
            engine_recover_from_backups(engine);
        }

        if (zl_changed) {
            zl_changed = engine_update_zones(engine, NULL, NULL, 0);
            zl_changed = 0;
        }

        engine_start_workers(engine);
        engine_run(engine, single_run);
        engine_stop_workers(engine);
    }

    /* shutdown */
    ods_log_info("[%s] signer shutdown", engine_str);
    stop_zonefetcher(engine);
    hsm_close();
    if (engine->cmdhandler != NULL) {
        engine_stop_cmdhandler(engine);
    }

    (void)unlink(engine->config->pid_filename);
    (void)unlink(engine->config->clisock_filename);

earlyexit:
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

    if (engine->workers) {
        for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
            worker_cleanup(engine->workers[i]);
        }
        se_free((void*) engine->workers);
    }
    schedule_cleanup(engine->taskq);
    if (engine->zonelist) {
        zonelist_cleanup(engine->zonelist);
        engine->zonelist = NULL;
    }
    parent_cleanup(engine, 1);

    allocator_deallocate(engine->allocator);
    allocator_cleanup(allocator);
    lock_basic_destroy(&signal_lock);
    lock_basic_off(&signal_cond);
    return;
}
