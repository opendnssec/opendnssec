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
#include "daemon/cmdhandler.h"
#include "daemon/clientpipe.h"
#include "daemon/engine.h"
#include "daemon/signal.h"
#include "daemon/worker.h"
#include "daemon/orm.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/locks.h"
#include "shared/log.h"
#include "shared/privdrop.h"
#include "shared/status.h"
#include "shared/util.h"
#include "shared/protobuf.h"
#include "db/db_configuration.h"
#include "db/db_connection.h"
#include "db/database_version.h"
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
#include <fcntl.h>

static const char* engine_str = "engine";


/**
 * Create engine.
 *
 */
engine_type*
engine_alloc(void)
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

    lock_basic_init(&engine->signal_lock);
    lock_basic_init(&engine->enforce_lock);
    lock_basic_set(&engine->signal_cond);

    engine->taskq = schedule_create(engine->allocator);
    if (!engine->taskq) {
        allocator_deallocate(allocator, (void*) engine);
        return NULL;
    }
    engine->signq = fifoq_create(engine->allocator);
    if (!engine->signq) {
        schedule_cleanup(engine->taskq);
        allocator_deallocate(allocator, (void*) engine);
        allocator_cleanup(allocator);
        return NULL;
    }
    return engine;
}

void
engine_dealloc(engine_type* engine)
{
    allocator_type* allocator = engine->allocator;
    schedule_cleanup(engine->taskq);
    fifoq_cleanup(engine->signq);
    lock_basic_destroy(&engine->enforce_lock);
    lock_basic_destroy(&engine->signal_lock);
    lock_basic_off(&engine->signal_cond);
    allocator_deallocate(allocator, (void*) engine);
    allocator_cleanup(allocator);
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
        engine->workers[i] = worker_create(engine->allocator, i);
    }
    return;
}

static void*
worker_thread_start(void* arg)
{
    worker_type* worker = (worker_type*) arg;

    ods_thread_blocksigs();
    worker->dbconn = get_database_connection(worker->engine->dbcfg_list);
    if (!worker->dbconn) {
        ods_log_crit("Failed to start worker, could not connect to database");
        return NULL;
    }
    worker_start(worker);
    db_connection_free(worker->dbconn);
    return NULL;
}

void
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

void
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

db_connection_t*
get_database_connection(db_configuration_list_t* dbcfg_list)
{
    db_connection_t* dbconn;

    if (!(dbconn = db_connection_new())
        || db_connection_set_configuration_list(dbconn, dbcfg_list)
        || db_connection_setup(dbconn)
        || db_connection_connect(dbconn))
    {
        db_connection_free(dbconn);
        ods_log_crit("database connection failed");
        return NULL;
    }
    return dbconn;
}

/*
 * Try to open a connection to the database and close it again.
 * \param dbcfg_list, database configuration list
 * \return 0 on success, 1 on failure.
 */
static int
probe_database(db_configuration_list_t* dbcfg_list)
{
    db_connection_t *conn;
    int version;

    conn = get_database_connection(dbcfg_list);
    if (!conn) return 1;
    version = database_version_get_version(conn);
    db_connection_free(conn);
    return !version;
}

/*
 * Prepare for database connections and store dbcfg_list in engine
 * if successfull the counterpart desetup_database() must be called
 * when quitting the daemon.
 * \param engine engine config where configuration list is stored
 * \return 0 on succes, 1 on failure
 */
static int
setup_database(engine_type* engine)
{
    db_configuration_t* dbcfg;

    if (!(engine->dbcfg_list = db_configuration_list_new())) {
        fprintf(stderr, "db_configuraiton_list_new failed\n");
        return 1;
    }
    if (!(dbcfg = db_configuration_new())
        || db_configuration_set_name(dbcfg, "backend")
        || db_configuration_set_value(dbcfg, "sqlite")
        || db_configuration_list_add(engine->dbcfg_list, dbcfg))
    {
        db_configuration_free(dbcfg);
        db_configuration_list_free(engine->dbcfg_list);
        fprintf(stderr, "setup configuration backend failed\n");
        return 1;
    }
    if (!(dbcfg = db_configuration_new())
        || db_configuration_set_name(dbcfg, "file")
        || db_configuration_set_value(dbcfg, engine->config->datastore)
        || db_configuration_list_add(engine->dbcfg_list, dbcfg))
    {
        db_configuration_free(dbcfg);
        db_configuration_list_free(engine->dbcfg_list);
        fprintf(stderr, "setup configuration file failed\n");
        return 1;
    }
    dbcfg = NULL;
    return 0;
}

/*
 * destroy database configuration. Call only after all connections
 * are closed.
 * \param engine engine config where configuration list is stored
 */
static void
desetup_database(engine_type* engine)
{
    db_configuration_list_free(engine->dbcfg_list);
    engine->dbcfg_list = NULL;
}

/**
 * Set up engine and return the setup status.
 *
 */
ods_status
engine_setup(engine_type* engine)
{
    int fd;

    ods_log_debug("[%s] enforcer setup", engine_str);

    ods_log_init(engine->config->log_filename, 
        engine->config->use_syslog, engine->config->verbosity);

    engine->pid = getpid(); /* We need to do this again after fork() */

    if (!util_pidfile_avail(engine->config->pid_filename)) {
        ods_log_error("[%s] Pidfile exists and process with PID is running", engine_str);
        return ODS_STATUS_WRITE_PIDFILE_ERR;
    }
    /* setup database configuration */
    if (setup_database(engine)) return ODS_STATUS_DB_ERR;
    /* Probe the database, can we connect to it? */
    if (probe_database(engine->dbcfg_list)) {
        ods_log_crit("Could not connect to database or database not set"
            " up properly.");
        return ODS_STATUS_DB_ERR;
    }

    /* create command handler (before chowning socket file) */
    engine->cmdhandler = cmdhandler_create(engine->config->clisock_filename);
    if (!engine->cmdhandler) {
        ods_log_error("[%s] create command handler to %s failed",
            engine_str, engine->config->clisock_filename);
        return ODS_STATUS_CMDHANDLER_ERR;
    }

    if (!engine->init_setup_done) {
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
            switch (fork()) {
                case -1: /* error */
                    ods_log_error("[%s] unable to fork daemon: %s",
                        engine_str, strerror(errno));
                    return ODS_STATUS_FORK_ERR;
                case 0: /* child */
                    if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
                        (void)dup2(fd, STDIN_FILENO);
                        (void)dup2(fd, STDOUT_FILENO);
                        (void)dup2(fd, STDERR_FILENO);
                        if (fd > 2) (void)close(fd);
                    }
                    engine->daemonize = 0; /* don't fork again on reload */
                    break;
                default: /* parent */
                    exit(0);
            }
            if (setsid() == -1) {
                ods_log_error("[%s] unable to setsid daemon (%s)",
                    engine_str, strerror(errno));
                return ODS_STATUS_SETSID_ERR;
            }
        }
    }
    engine->init_setup_done = 1;
    
    engine->pid = getpid();
    ods_log_info("[%s] running as pid %lu", engine_str,
        (unsigned long) engine->pid);

    /* create workers */
    engine_create_workers(engine);

    /* start command handler */
    engine->cmdhandler_done = 0;

    /* write pidfile */
    if (util_write_pidfile(engine->config->pid_filename, engine->pid) == -1) {
        hsm_close();
        ods_log_error("[%s] unable to write pid file", engine_str);
        return ODS_STATUS_WRITE_PIDFILE_ERR;
    }

    return ODS_STATUS_OK;
}

/**
 * Clean up engine.
 *
 */
void
engine_teardown(engine_type* engine)
{
    size_t i = 0;

    if (!engine) return;
    if (engine->config) {
        if (engine->config->pid_filename) {
            (void)unlink(engine->config->pid_filename);
        }
        if (engine->config->clisock_filename) {
            (void)unlink(engine->config->clisock_filename);
        }
    }
    if (engine->workers && engine->config) {
        for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
            worker_cleanup(engine->workers[i]);
        }
        allocator_deallocate(engine->allocator, (void*) engine->workers);
    }
    cmdhandler_cleanup(engine->cmdhandler);
    engine->cmdhandler = NULL;
    desetup_database(engine);
}

void
engine_init(engine_type* engine, int daemonize)
{
    struct sigaction action;

    engine->config = NULL;
    engine->workers = NULL;
    engine->cmdhandler = NULL;
    engine->cmdhandler_done = 1;
    engine->init_setup_done = 0;
    engine->pid = getpid(); /* We need to do this again after fork() */
    engine->uid = -1;
    engine->gid = -1;
    engine->need_to_exit = 0;
    engine->need_to_reload = 0;
    engine->daemonize = daemonize;
    /* catch signals */
    signal_set_engine(engine);
    action.sa_handler = signal_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    engine->dbcfg_list = NULL;
}

/**
 * Run engine, run!.
 *
 */
int
engine_run(engine_type* engine, start_cb_t start, int single_run)
{
    int error;
    task_type *task;
    ods_log_assert(engine);
    ods_log_info("[%s] enforcer started", engine_str);
    
    error = hsm_open(engine->config->cfg_filename, hsm_prompt_pin);
    if (error != HSM_OK) {
        char* errorstr =  hsm_get_error(NULL);
        if (errorstr != NULL) {
            ods_log_error("[%s] %s", engine_str, errorstr);
            free(errorstr);
        } else {
            ods_log_crit("[%s] error opening libhsm (errno %i)", engine_str,
                error);
        }
        return 1;
    }
    
    engine->need_to_reload = 0;
    engine_start_cmdhandler(engine);
    engine_start_workers(engine);

    /* call the external start callback function */
    start(engine);
    
    while (!engine->need_to_exit && !engine->need_to_reload) {
        if (single_run) {
            engine->need_to_exit = 1;
            /* FIXME: all tasks need to terminate, then set need_to_exit to 1 */
        }

        lock_basic_lock(&engine->signal_lock);
        /* [LOCK] signal, recheck reload and lock */
        if (!engine->need_to_exit && !engine->need_to_reload && !single_run) {
           ods_log_debug("[%s] taking a break", engine_str);
           lock_basic_sleep(&engine->signal_cond, &engine->signal_lock, 0);
        }
        /* [UNLOCK] signal */
        lock_basic_unlock(&engine->signal_lock);
    }
    ods_log_debug("[%s] enforcer halted", engine_str);
    engine_stop_workers(engine);
    cmdhandler_stop(engine);
    /* Remove old tasks in queue */
    while ((task = schedule_pop_task(engine->taskq))) {
        ods_log_verbose("popping task \"%s\" from queue", task->who);
    }
    (void) hsm_close();
    return 0;
}

void
flush_all_tasks(int sockfd, engine_type* engine)
{
    ods_log_debug("[%s] flushing all tasks...", engine_str);
    client_printf(sockfd,"flushing all tasks...\n");

    ods_log_assert(engine);
    ods_log_assert(engine->taskq);
    lock_basic_lock(&engine->taskq->schedule_lock);
    /* [LOCK] schedule */
    schedule_flush(engine->taskq, TASK_NONE);
    /* [UNLOCK] schedule */
    lock_basic_unlock(&engine->taskq->schedule_lock);
    engine_wakeup_workers(engine);
}
