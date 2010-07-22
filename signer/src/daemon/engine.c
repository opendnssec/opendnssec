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
#include "daemon/cmdhandler.h"
#include "daemon/config.h"
#include "daemon/engine.h"
#include "daemon/signal.h"
#include "daemon/worker.h"
#include "scheduler/locks.h"
#include "scheduler/task.h"
#include "signer/zone.h"
#include "signer/zonelist.h"
#include "tools/zone_fetcher.h"
#include "util/file.h"
#include "util/log.h"
#include "util/privdrop.h"
#include "util/se_malloc.h"

#include <errno.h>
#include <libhsm.h> /* hsm_open(), hsm_close() */
#include <libxml/parser.h> /* xmlInitParser(), xmlCleanupParser(), xmlCleanupThreads() */
#include <signal.h> /* sigfillset(), sigaction(), kill() */
#include <stdio.h> /* snprintf() */
#include <stdlib.h> /* exit(), fwrite() */
#include <string.h> /* strlen(), strncpy(), strerror() */
#include <strings.h> /* bzero() */
#include <sys/socket.h> /* socket(), connect(), close()  */
#include <sys/types.h> /* getpid(), kill() */
#include <sys/un.h> /* unix socket */
#include <time.h> /* tzset() */
#include <unistd.h> /* fork(), setsid(), getpid(), chdir() */


/**
 * Create engine.
 *
 */
engine_type*
engine_create(void)
{
    engine_type* engine = (engine_type*) se_malloc(sizeof(engine_type));

    se_log_debug("create signer engine");
    engine->config = NULL;
    engine->daemonize = 0;
    engine->zonelist = NULL;
    engine->tasklist = NULL;
    engine->workers = NULL;
    engine->cmdhandler = NULL;
    engine->cmdhandler_done = 0;
    engine->pid = -1;
    engine->zfpid = -1;
    engine->uid = -1;
    engine->gid = -1;
    engine->need_to_exit = 0;
    engine->need_to_reload = 0;
    engine->signal = SIGNAL_INIT;
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

    se_thread_blocksigs();
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
    se_log_assert(engine);
    se_log_assert(engine->config);
    se_log_debug("start command handler");

    engine->cmdhandler = cmdhandler_create(engine->config->clisock_filename);
    if (!engine->cmdhandler) {
        return 1;
    }
    engine->cmdhandler->engine = engine;
    se_thread_create(&engine->cmdhandler->thread_id,
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

    se_log_assert(engine);
    se_log_assert(engine->cmdhandler);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd <= 0) {
        se_log_error("cannot connect to command handler: "
            "socket() failed: %s\n", strerror(errno));
        return 1;
    } else {
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sun_family = AF_UNIX;
        strncpy(servaddr.sun_path, servsock_filename,
            sizeof(servaddr.sun_path) - 1);

        ret = connect(sockfd, (const struct sockaddr*) &servaddr,
            sizeof(servaddr));
        if (ret != 0) {
            se_log_error("cannot connect to command handler: "
                "connect() failed: %s\n", strerror(errno));
            close(sockfd);
            return 1;
        } else {
            /* self-pipe trick */
            se_writen(sockfd, "", 1);
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
    se_log_assert(engine);
    se_log_assert(engine->cmdhandler);
    se_log_debug("stop command handler");

    engine->cmdhandler->need_to_exit = 1;
    if (self_pipe_trick(engine) == 0) {
        while (!engine->cmdhandler_done) {
			se_log_debug("waiting for command handler to exit...");
            sleep(1);
        }
    } else {
        se_log_error("command handler self pipe trick failed, "
            "unclean shutdown");
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
    se_log_assert(engine);
    se_log_assert(engine->config);
    se_log_debug("drop privileges");

    if (engine->config->username && engine->config->group) {
        se_log_verbose("drop privileges to user %s, group %s",
           engine->config->username, engine->config->group);
    } else if (engine->config->username) {
        se_log_verbose("drop privileges to user %s",
           engine->config->username);
    } else if (engine->config->group) {
        se_log_verbose("drop privileges to group %s",
           engine->config->group);
    }
    if (engine->config->chroot) {
        se_log_verbose("chroot to %s", engine->config->chroot);
    }

    return privdrop(engine->config->username, engine->config->group,
        engine->config->chroot);
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
    } else {
        se_log_warning("cleanup empty parent");
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

    se_log_assert(pidfile);
    se_log_assert(pid);
    se_log_debug("writing pid %lu to pidfile %s", (unsigned long) pid,
        pidfile);
    snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long) pid);
    fd = se_fopen(pidfile, NULL, "w");
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
        se_log_error("write to pidfile %s failed: %s", pidfile,
            strerror(errno));
    } else if (result < size) {
        se_log_error("short write to pidfile %s: disk full?", pidfile);
        result = 0;
    } else {
        result = 1;
    }
    se_fclose(fd);
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

    se_log_assert(engine);
    se_log_assert(engine->config);

    engine->workers = (worker_type**)
        se_calloc((size_t)engine->config->num_worker_threads,
        sizeof(worker_type*));

    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        engine->workers[i] = worker_create(i, WORKER_WORKER);
        engine->workers[i]->tasklist = engine->tasklist;
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
    se_thread_blocksigs();
    worker_start(worker);
    return NULL;
}


/**
 * Start workers.
 *
 */
void
engine_start_workers(engine_type* engine)
{
    size_t i = 0;

    se_log_assert(engine);
    se_log_assert(engine->config);
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        engine->workers[i]->need_to_exit = 0;
        se_thread_create(&engine->workers[i]->thread_id, worker_thread_start,
            engine->workers[i]);
        engine->workers[i]->engineptr = (struct engine_struct*) engine;
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

    se_log_assert(engine);
    se_log_assert(engine->config);
    se_log_debug("stop workers");

    /* tell them to exit and wake up sleepyheads */
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        engine->workers[i]->need_to_exit = 1;
        worker_wakeup(engine->workers[i]);
    }
    /* head count */
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        se_thread_join(engine->workers[i]->thread_id);
        engine->workers[i]->engineptr = NULL;
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

    se_log_assert(engine);
    se_log_assert(engine->config);
    se_log_debug("perform setup");

    /* start command handler (before chowning socket file) */
    if (engine_start_cmdhandler(engine) != 0) {
        se_log_error("setup failed: unable to start command handler");
        return 1;
    }

    /* privdrop */
    engine->uid = privuid(engine->config->username); /* LEAKS */
    engine->gid = privgid(engine->config->group); /* LEAKS */
    /* TODO: does piddir exists? */
    /* remove the chown stuff: piddir? */
    se_chown(engine->config->pid_filename, engine->uid, engine->gid, 1); /* chown pidfile directory */
    se_chown(engine->config->clisock_filename, engine->uid, engine->gid, 0); /* chown sockfile */
    se_chown(engine->config->working_dir, engine->uid, engine->gid, 0); /* chown workdir */
    if (engine->config->log_filename && !engine->config->use_syslog) {
        se_chown(engine->config->log_filename, engine->uid, engine->gid, 0); /* chown logfile */
    }
    if (chdir(engine->config->working_dir) != 0) {
        se_log_error("setup failed: chdir to %s failed: %s", engine->config->working_dir,
            strerror(errno));
        return 1;
    }

    if (engine_privdrop(engine) != 0) {
        se_log_error("setup failed: unable to drop privileges");
        return 1;
    }

    /* daemonize */
    if (engine->daemonize) {
        switch ((engine->pid = fork())) {
            case -1: /* error */
                se_log_error("setup failed: unable to fork daemon: %s",
                    strerror(errno));
                return 1;
            case 0: /* child */
                break;
            default: /* parent */
                parent_cleanup(engine, 0);
                xmlCleanupParser();
                xmlCleanupThreads();
                exit(0);
        }
        if (setsid() == -1) {
            se_log_error("setup failed: unable to setsid daemon (%s)",
                strerror(errno));
            return 1;
        }
    }
    engine->pid = getpid();
    /* make common with enforcer */
    if (write_pidfile(engine->config->pid_filename, engine->pid) == -1) {
        se_log_error("setup failed: unable to write pid file");
        return 1;
    }
    se_log_verbose("running as pid %lu", (unsigned long) engine->pid);

    /* catch signals */
    signal_set_engine(engine);
    action.sa_handler = signal_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    /* set up hsm */
    result = hsm_open(engine->config->cfg_filename, hsm_prompt_pin, NULL); /* LEAKS */
   if (result != HSM_OK) {
        se_log_error("Error initializing libhsm (errno %i)", result);
        return 1;
    }

    /* set up the work floor */
    engine->tasklist = tasklist_create(); /* tasks */
    engine->zonelist = zonelist_create(); /* zones */
    engine_create_workers(engine); /* workers */

    return 0;
}


/**
 * Engine running.
 *
 */
static void
engine_run(engine_type* engine, int single_run)
{
    se_log_assert(engine);

    engine->signal = SIGNAL_RUN;
    while (engine->need_to_exit == 0 && engine->need_to_reload == 0) {
        lock_basic_lock(&engine->signal_lock);
        engine->signal = signal_capture(engine->signal);
        switch (engine->signal) {
            case SIGNAL_RUN:
                se_log_assert(1);
                break;
            case SIGNAL_RELOAD:
                engine->need_to_reload = 1;
                break;
            case SIGNAL_SHUTDOWN:
                engine->need_to_exit = 1;
                break;
            default:
                se_log_warning("invalid signal captured: %d, keep running",
                    engine->signal);
                engine->signal = SIGNAL_RUN;
                break;
        }

        if (single_run) {
                engine->need_to_exit = 1;
        } else if (engine->signal == SIGNAL_RUN) {
           se_log_debug("engine taking a break");
           lock_basic_sleep(&engine->signal_cond, &engine->signal_lock, 3600);
        }
        lock_basic_unlock(&engine->signal_lock);
    }
    se_log_debug("engine halt");
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

    se_log_assert(engine);
    se_log_assert(engine->config);
    se_log_assert(engine->zonelist);
    se_log_debug("update zone list");

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
    zonelist_update(engine->zonelist, engine->tasklist, buf);
    zonelist_unlock(engine->zonelist);
    return 0;
}


/**
 * Update zones.
 *
 */
void
engine_update_zones(engine_type* engine, const char* zone_name, char* buf)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;
    int tmp = 0;
    int unchanged = 0;
    int errors = 0;
    int updated = 0;

    se_log_assert(engine);
    se_log_assert(engine->zonelist);
    se_log_assert(engine->zonelist->zones);

    lock_basic_lock(&engine->tasklist->tasklist_lock);
    engine->tasklist->loading = 1;
    lock_basic_unlock(&engine->tasklist->tasklist_lock);

    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->key;

        lock_basic_lock(&zone->zone_lock);

        if (!zone_name || se_strcmp(zone->name, zone_name) == 0) {
            if (zone_name) {
                se_log_debug("update zone %s (signconf file %s)",
                    zone->name, zone->signconf_filename);
                lock_basic_lock(&engine->tasklist->tasklist_lock);
                tmp = zone_update_signconf(zone, engine->tasklist, buf);
                lock_basic_unlock(&engine->tasklist->tasklist_lock);
                lock_basic_unlock(&zone->zone_lock);
                return;
            }

            lock_basic_lock(&engine->tasklist->tasklist_lock);
            tmp = zone_update_signconf(zone, engine->tasklist, buf);
            lock_basic_unlock(&engine->tasklist->tasklist_lock);

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

    lock_basic_lock(&engine->tasklist->tasklist_lock);
    engine->tasklist->loading = 0;
    lock_basic_unlock(&engine->tasklist->tasklist_lock);

    if (zone_name) {
        se_log_debug("zone %s not found", zone_name);
        if (buf) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s not found.\n", zone_name);
        }
    } else {
        se_log_debug("configurations updated");
        if (buf) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Configurations updated: %i; errors: %i; "
                "unchanged: %i.\n", updated, errors, unchanged);
        }
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
    int result;

    se_log_assert(engine);
    se_log_assert(engine->config);

    if (!engine->config->zonefetch_filename) {
        /* zone fetcher disabled */
        return 0;
    }

    switch ((zfpid = fork())) {
        case -1: /* error */
            se_log_error("failed to fork zone fetcher: %s",
                strerror(errno));
            return 1;
        case 0: /* child */
            break;
        default: /* parent */
            engine->zfpid = zfpid;
            return 0;
    }

    if (setsid() == -1) {
        se_log_error("failed to setsid zone fetcher: %s",
            strerror(errno));
        exit(1);
    }

    se_log_verbose("zone fetcher started (pid=%i)", getpid());

    result = tools_zone_fetcher(engine->config->zonefetch_filename,
        engine->config->zonelist_filename, engine->config->group,
        engine->config->username, engine->config->chroot,
        engine->config->log_filename, engine->config->use_syslog,
        engine->config->verbosity);

    se_log_verbose("zone fetcher stopped", result);

    parent_cleanup(engine, 0);
    xmlCleanupParser();
    xmlCleanupThreads();
    exit(result);

    return 0;
}


/**
 * Stop zonefetcher.
 *
 */
static void
stop_zonefetcher(engine_type* engine)
{
    int result = 0;

    se_log_assert(engine);
    se_log_assert(engine->config);

    if (engine->config->zonefetch_filename) {
        if (engine->zfpid > 0) {
            result = kill(engine->zfpid, SIGHUP);
            if (result == -1) {
                se_log_error("cannot stop zone fetcher: %s", strerror(errno));
            } else {
                se_log_verbose("zone fetcher stopped (pid=%i)", engine->zfpid);
            }
            engine->zfpid = -1;
        } else {
            se_log_error("zone fetcher process id unknown, unable to "
                "stop zone fetcher");
        }
    }
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

    se_log_assert(cfgfile);
    se_log_init(NULL, use_syslog, cmdline_verbosity);
    se_log_verbose("start signer engine");

    /* initialize */
    xmlInitParser();
    engine = engine_create();
    engine->daemonize = daemonize;

    /* configure */
    engine->config = engine_config(cfgfile, cmdline_verbosity);
    if (engine_check_config(engine->config) != 0) {
        se_log_error("cfgfile %s has errors", cfgfile);
        engine->need_to_exit = 1;
    }
    if (info) {
        engine_config_print(stdout, engine->config);
        xmlCleanupParser();
        xmlCleanupThreads();
        engine_cleanup(engine);
        engine = NULL;
        return;
    }

    /* open log */
    se_log_init(engine->config->log_filename, engine->config->use_syslog,
       engine->config->verbosity);

    /* setup */
    tzset(); /* for portability */
    if (engine_setup(engine) != 0) {
        se_log_error("signer engine setup failed");
        engine->need_to_exit = 1;
    }

    /* run */
    while (engine->need_to_exit == 0) {
        if (engine->need_to_reload) {
            se_log_verbose("reload engine");
            engine->need_to_reload = 0;
        } else {
            se_log_debug("signer engine started");
        }

        if (engine_update_zonelist(engine, NULL) == 0) {
            engine_update_zones(engine, NULL, NULL);
        }

        if (start_zonefetcher(engine) != 0) {
            se_log_error("cannot start zonefetcher");
            engine->need_to_exit = 1;
            break;
        }

        engine_start_workers(engine);
        engine_run(engine, single_run);
        engine_stop_workers(engine);

	stop_zonefetcher(engine);
    }

    /* shutdown */
    se_log_verbose("shutdown signer engine");
    hsm_close();
    if (engine->cmdhandler != NULL) {
        engine_stop_cmdhandler(engine);
    }
    (void)unlink(engine->config->pid_filename);
    (void)unlink(engine->config->clisock_filename);
    engine_cleanup(engine);
    engine = NULL;
    se_log_close();
    xmlCleanupParser();
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

    if (engine) {
        se_log_debug("clean up engine");
        if (engine->workers) {
            for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
                worker_cleanup(engine->workers[i]);
            }
            se_free((void*) engine->workers);
        }
        if (engine->tasklist) {
            tasklist_cleanup(engine->tasklist);
            engine->tasklist = NULL;
        }
        if (engine->zonelist) {
            zonelist_cleanup(engine->zonelist);
            engine->zonelist = NULL;
        }
        parent_cleanup(engine, 1);
        lock_basic_destroy(&engine->signal_lock);
        lock_basic_off(&engine->signal_cond);
        se_free((void*) engine);
    } else {
        se_log_warning("cleanup empty engine");
    }
    return;
}
