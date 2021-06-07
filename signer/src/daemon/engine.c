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
#include "duration.h"
#include "file.h"
#include "str.h"
#include "hsm.h"
#include "locks.h"
#include "log.h"
#include "privdrop.h"
#include "status.h"
#include "util.h"
#include "signer/zonelist.h"
#include "wire/tsig.h"
#include "libhsm.h"
#include "signertasks.h"
#include "signercommands.h"

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

static engine_type* engine = NULL;

/**
 * Create engine.
 *
 */
static engine_type*
engine_create(void)
{
    engine_type* engine;
    CHECKALLOC(engine = (engine_type*) malloc(sizeof(engine_type)));
    engine->config = NULL;
    engine->workers = NULL;
    engine->cmdhandler = NULL;
    engine->dnshandler = NULL;
    engine->xfrhandler = NULL;
    engine->taskq = NULL;
    engine->pid = -1;
    engine->uid = -1;
    engine->gid = -1;
    engine->daemonize = 0;
    engine->need_to_exit = 0;
    engine->need_to_reload = 0;
    pthread_mutex_init(&engine->signal_lock, NULL);
    pthread_cond_init(&engine->signal_cond, NULL);
    engine->zonelist = zonelist_create();
    if (!engine->zonelist) {
        engine_cleanup(engine);
        return NULL;
    }
    if (!(engine->taskq = schedule_create())) {
        engine_cleanup(engine);
        return NULL;
    }
    schedule_registertask(engine->taskq, TASK_CLASS_SIGNER, TASK_SIGNCONF, do_readsignconf);
    schedule_registertask(engine->taskq, TASK_CLASS_SIGNER, TASK_FORCESIGNCONF, do_forcereadsignconf);
    schedule_registertask(engine->taskq, TASK_CLASS_SIGNER, TASK_READ, do_readzone);
    schedule_registertask(engine->taskq, TASK_CLASS_SIGNER, TASK_FORCEREAD, do_forcereadzone);
    schedule_registertask(engine->taskq, TASK_CLASS_SIGNER, TASK_SIGN, do_signzone);
    schedule_registertask(engine->taskq, TASK_CLASS_SIGNER, TASK_WRITE, do_writezone);
    return engine;
}

static void
engine_start_cmdhandler(engine_type* engine)
{
    ods_log_debug("[%s] start command handler", engine_str);
    janitor_thread_create(&engine->cmdhandler->thread_id, workerthreadclass, (janitor_runfn_t)cmdhandler_start, engine->cmdhandler);
}

/**
 * Start/stop dnshandler.
 *
 */
static void
engine_start_dnshandler(engine_type* engine)
{
    if (!engine || !engine->dnshandler) {
        return;
    }
    ods_log_debug("[%s] start dnshandler", engine_str);
    engine->dnshandler->engine = engine;
    janitor_thread_create(&engine->dnshandler->thread_id, handlerthreadclass, (janitor_runfn_t)dnshandler_start, engine->dnshandler);
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
    janitor_thread_join(engine->dnshandler->thread_id);
    engine->dnshandler->engine = NULL;
}


static void
engine_start_xfrhandler(engine_type* engine)
{
    if (!engine || !engine->xfrhandler) {
        return;
    }
    ods_log_debug("[%s] start xfrhandler", engine_str);
    engine->xfrhandler->engine = engine;
    /* This might be the wrong place to mark the xfrhandler started but
     * if its isn't done here we might try to shutdown and stop it before
     * it has marked itself started
     */
    engine->xfrhandler->started = 1;
    janitor_thread_create(&engine->xfrhandler->thread_id, handlerthreadclass, (janitor_runfn_t)xfrhandler_start, engine->xfrhandler);
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
    	janitor_thread_join(engine->xfrhandler->thread_id);
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
    char* name;
    int i;
    int numTotalWorkers;
    int threadCount = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    numTotalWorkers = engine->config->num_worker_threads + engine->config->num_signer_threads;
    CHECKALLOC(engine->workers = (worker_type**) malloc(numTotalWorkers * sizeof(worker_type*)));
    for (i=0; i < engine->config->num_worker_threads; i++) {
        asprintf(&name, "worker[%d]", i+1);
        engine->workers[threadCount++] = worker_create(name, engine->taskq);
    }
    for (i=0; i < engine->config->num_signer_threads; i++) {
        asprintf(&name, "drudger[%d]", i+1);
        engine->workers[threadCount++] = worker_create(name, engine->taskq);
    }
}

static void
engine_start_workers(engine_type* engine)
{
    int i;
    int threadCount = 0;
    struct worker_context* context;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] start workers", engine_str);
    for (i=0; i < engine->config->num_worker_threads; i++,threadCount++) {
        CHECKALLOC(context = malloc(sizeof(struct worker_context)));
        context->engine = engine;
        context->worker = engine->workers[threadCount];
        context->signq = engine->taskq->signq;
        engine->workers[threadCount]->need_to_exit = 0;
        engine->workers[threadCount]->context = context;
        janitor_thread_create(&engine->workers[threadCount]->thread_id, workerthreadclass, (janitor_runfn_t)worker_start, engine->workers[threadCount]);
    }
    for (i=0; i < engine->config->num_signer_threads; i++,threadCount++) {
        engine->workers[threadCount]->need_to_exit = 0;
        janitor_thread_create(&engine->workers[threadCount]->thread_id, workerthreadclass, (janitor_runfn_t)drudge, engine->workers[threadCount]);
    }
}

static void
engine_stop_threads(engine_type* engine)
{
    int i;
    int numTotalWorkers;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] stop workers and drudgers", engine_str);
    numTotalWorkers = engine->config->num_worker_threads + engine->config->num_signer_threads;
    for (i=0; i < numTotalWorkers; i++) {
        engine->workers[i]->need_to_exit = 1;
    }
    ods_log_debug("[%s] notify workers and drudgers", engine_str);
    schedule_release_all(engine->taskq);

    for (i=0; i < numTotalWorkers; i++) {
        ods_log_debug("[%s] join worker %d", engine_str, i+1);
        janitor_thread_join(engine->workers[i]->thread_id);
        free(engine->workers[i]->context);
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
    schedule_release_all(engine->taskq);
}

static void *
signal_handler(sig_atomic_t sig)
{
    switch (sig) {
        case SIGHUP:
            if (engine) {
                engine->need_to_reload = 1;
                pthread_mutex_lock(&engine->signal_lock);
                pthread_cond_signal(&engine->signal_cond);
                pthread_mutex_unlock(&engine->signal_lock);
            }
            break;
        case SIGINT:
        case SIGTERM:
            if (engine) {
                engine->need_to_exit = 1;
                pthread_mutex_lock(&engine->signal_lock);
                pthread_cond_signal(&engine->signal_cond);
                pthread_mutex_unlock(&engine->signal_lock);
            }
            break;
        default:
            break;
    }
    return NULL;
}

/**
 * Set up engine.
 *
 */
static ods_status
engine_setup(void)
{
    ods_status status = ODS_STATUS_OK;
    struct sigaction action;
    int sockets[2] = {0,0};
    int pipefd[2];
    char buff = '\0';
    int fd, error;

    ods_log_debug("[%s] setup signer engine", engine_str);
    if (!engine || !engine->config) {
        return ODS_STATUS_ASSERT_ERR;
    }
    /* set edns */
    edns_init(&engine->edns, EDNS_MAX_MESSAGE_LEN);

    /* create command handler (before chowning socket file) */
    engine->cmdhandler = cmdhandler_create(engine->config->clisock_filename, signercommands, engine, NULL, NULL);
    if (!engine->cmdhandler) {
        return ODS_STATUS_CMDHANDLER_ERR;
    }
    engine->dnshandler = dnshandler_create(engine->config->interfaces);
    engine->xfrhandler = xfrhandler_create();
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
        if (pipe(pipefd)) {
            ods_log_error("[%s] unable to pipe: %s", engine_str, strerror(errno));
            return ODS_STATUS_PIPE_ERR;
        }
        switch ((engine->pid = fork())) {
            case -1: /* error */
                ods_log_error("[%s] setup: unable to fork daemon (%s)",
                    engine_str, strerror(errno));
                return ODS_STATUS_FORK_ERR;
            case 0: /* child */
                close(pipefd[0]);
                break;
            default: /* parent */
                engine_cleanup(engine);
                engine = NULL;
                xmlCleanupParser();
                xmlCleanupGlobals();
                close(pipefd[1]);
                while (read(pipefd[0], &buff, 1) != -1) {
                    if (buff <= 1) break;
                    printf("%c", buff);
                }
                close(pipefd[0]);
                if (buff == '\1') {
                    ods_log_debug("[%s] signerd started successfully", engine_str);
                    exit(0);
                }
                ods_log_error("[%s] fail to start signerd completely", engine_str);
                exit(1);
        }
        if (setsid() == -1) {
            ods_log_error("[%s] setup: unable to setsid daemon (%s)",
                engine_str, strerror(errno));
            const char *err = "unable to setsid daemon: ";
            ods_writen(pipefd[1], err, strlen(err));
            ods_writeln(pipefd[1], strerror(errno));
            write(pipefd[1], "\0", 1);
            close(pipefd[1]);
            return ODS_STATUS_SETSID_ERR;
        }
    }
    engine->pid = getpid();
    /* write pidfile */
    if (util_write_pidfile(engine->config->pid_filename, engine->pid) == -1) {
        if (engine->daemonize) {
            ods_writeln(pipefd[1], "Unable to write pid file");
            write(pipefd[1], "\0", 1);
            close(pipefd[1]);
        }
        return ODS_STATUS_WRITE_PIDFILE_ERR;
    }
    /* setup done */
    ods_log_verbose("[%s] running as pid %lu", engine_str,
        (unsigned long) engine->pid);
    /* catch signals */
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
    /* start cmd/dns/xfr handlers */
    engine_start_cmdhandler(engine);
    engine_start_dnshandler(engine);
    engine_start_xfrhandler(engine);
    tsig_handler_init();
    if (engine->daemonize) {
        write(pipefd[1], "\1", 1);
        close(pipefd[1]);
    }
    return ODS_STATUS_OK;
}


/**
 * Run engine, run!.
 *
 */
static void
engine_run(engine_type* engine)
{
    if (!engine) {
        return;
    }
    engine_start_workers(engine);

    while (!engine->need_to_exit && !engine->need_to_reload) {
        /* We must use locking here to avoid race conditions. We want
         * to sleep indefinitely and want to wake up on signal. This
         * is to make sure we never mis the signal. */
        pthread_mutex_lock(&engine->signal_lock);
        if (!engine->need_to_exit && !engine->need_to_reload) {
            /* TODO: this silly. We should be handling the commandhandler
             * connections. No reason to spawn that as a thread.
             * Also it would be easier to wake up the command hander
             * as signals will reach it if it is the main thread! */
            ods_log_debug("[%s] taking a break", engine_str);
            pthread_cond_wait(&engine->signal_cond, &engine->signal_lock);
        }
        pthread_mutex_unlock(&engine->signal_lock);
    }
    ods_log_debug("[%s] signer halted", engine_str);
    engine_stop_threads(engine);
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
        ods_str_trim((char*) str2, 1);
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
    ods_status status = ODS_STATUS_OK;
    unsigned wake_up = 0;
    int warnings = 0;

    if (!engine || !engine->zonelist || !engine->zonelist->zones) {
        return;
    }

    ods_log_debug("[%s] commit zone list changes", engine_str);
    pthread_mutex_lock(&engine->zonelist->zl_lock);
    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->data;

        if (zone->zl_status == ZONE_ZL_REMOVED) {
            node = ldns_rbtree_next(node);
            pthread_mutex_lock(&zone->zone_lock);
            zonelist_del_zone(engine->zonelist, zone);
            schedule_unscheduletask(engine->taskq, schedule_WHATEVER, zone->name);
            pthread_mutex_unlock(&zone->zone_lock);
            netio_remove_handler(engine->xfrhandler->netio,
                &zone->xfrd->handler);
            zone_cleanup(zone);
            zone = NULL;
            continue;
        } else if (zone->zl_status == ZONE_ZL_ADDED) {
            pthread_mutex_lock(&zone->zone_lock);
            /* set notify nameserver command */
            if (engine->config->notify_command && !zone->notify_ns) {
                set_notify_ns(zone, engine->config->notify_command);
            }
            pthread_mutex_unlock(&zone->zone_lock);
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
            schedule_scheduletask(engine->taskq, TASK_SIGNCONF, zone->name, zone, &zone->zone_lock, 0);
        } else if (zl_changed == ODS_STATUS_OK) {
            schedule_scheduletask(engine->taskq, TASK_FORCESIGNCONF, zone->name, zone, &zone->zone_lock, 0);
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
    pthread_mutex_unlock(&engine->zonelist->zl_lock);
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

    pthread_mutex_lock(&engine->zonelist->zl_lock);
    /* [LOCK] zonelist */
    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->data;

        ods_log_assert(zone->zl_status == ZONE_ZL_ADDED);
        pthread_mutex_lock(&zone->zone_lock);
        status = zone_recover2(engine, zone);
        if (status == ODS_STATUS_OK) {
            ods_log_assert(zone->db);
            ods_log_assert(zone->signconf);
            /* notify nameserver */
            if (engine->config->notify_command && !zone->notify_ns) {
                set_notify_ns(zone, engine->config->notify_command);
            }
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] unable to schedule task for zone %s: %s",
                    engine_str, zone->name, ods_status2str(status));
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
        pthread_mutex_unlock(&zone->zone_lock);
        node = ldns_rbtree_next(node);
    }
    /* [UNLOCK] zonelist */
    pthread_mutex_unlock(&engine->zonelist->zl_lock);
    return result;
}


/**
 * Start engine.
 *
 */
int
engine_start(const char* cfgfile, int cmdline_verbosity, int daemonize, int info)
{
    ods_status zl_changed = ODS_STATUS_UNCHANGED;
    ods_status status = ODS_STATUS_OK;

    engine = engine_create();
    if (!engine) {
        ods_fatal_exit("[%s] create failed", engine_str);
        return 1;
    }
    engine->daemonize = daemonize;

    /* config */
    engine->config = engine_config(cfgfile, cmdline_verbosity);
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
    /* setup */
    status = engine_setup();
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] setup failed: %s", engine_str,
            ods_status2str(status));
        goto earlyexit;
    }

    /* run */
    while (engine->need_to_exit == 0) {
        /* update zone list */
        pthread_mutex_lock(&engine->zonelist->zl_lock);
        zl_changed = zonelist_update(engine->zonelist,
            engine->config->zonelist_filename);
        engine->zonelist->just_removed = 0;
        engine->zonelist->just_added = 0;
        engine->zonelist->just_updated = 0;
        pthread_mutex_unlock(&engine->zonelist->zl_lock);
        /* start/reload */
        if (engine->need_to_reload) {
            ods_log_info("[%s] signer reloading", engine_str);
            engine->need_to_reload = 0;
        } else {
            ods_log_info("[%s] signer started (version %s), pid %u",
                engine_str, PACKAGE_VERSION, engine->pid);
            if (hsm_open2(engine->config->repositories, hsm_check_pin) != HSM_OK) {
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
        if (hsm_open2(engine->config->repositories, hsm_check_pin) != HSM_OK) {
            char* error =  hsm_get_error(NULL);
            if (error != NULL) {
                ods_log_error("[%s] %s", "hsm", error);
                free(error);
            }
            ods_log_error("[%s] opening hsm failed (for engine run)", engine_str);
            break;
        }
        engine_run(engine);
        hsm_close();
    }

    /* shutdown */
    ods_log_info("[%s] signer shutdown", engine_str);
    cmdhandler_stop(engine->cmdhandler);
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

    return status;
}


/**
 * Clean up engine.
 *
 */
void
engine_cleanup(engine_type* engine)
{
    int i;
    int numTotalWorkers;

    if (!engine) {
        return;
    }
    if (engine->config) {
        numTotalWorkers = engine->config->num_worker_threads + engine->config->num_signer_threads;
        if (engine->workers) {
            for (i=0; i < (size_t) numTotalWorkers; i++) {
                worker_cleanup(engine->workers[i]);
            }
            free(engine->workers);
        }
        zonelist_cleanup(engine->zonelist);
        schedule_cleanup(engine->taskq);
        cmdhandler_cleanup(engine->cmdhandler);
        dnshandler_cleanup(engine->dnshandler);
        xfrhandler_cleanup(engine->xfrhandler);
        engine_config_cleanup(engine->config);
        pthread_mutex_destroy(&engine->signal_lock);
        pthread_cond_destroy(&engine->signal_cond);
    }
    free(engine);
}
