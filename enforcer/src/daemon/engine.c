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

#include <pthread.h>

#include "cfg.h"
#include "daemon/enforcercommands.h"
#include "clientpipe.h"
#include "cmdhandler.h"
#include "locks.h"
#include "daemon/engine.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "file.h"
#include "log.h"
#include "privdrop.h"
#include "status.h"
#include "util.h"
#include "db/db_configuration.h"
#include "db/db_connection.h"
#include "db/database_version.h"
#include "hsmkey/hsm_key_factory.h"
#include "libhsm.h"
#include "locks.h"

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

static engine_type* engine = NULL;

/**
 * Create engine.
 *
 */
engine_type*
engine_alloc(void)
{
    engine = (engine_type*) malloc(sizeof(engine_type));
    if (!engine) return NULL;

    pthread_mutex_init(&engine->signal_lock, NULL);
    pthread_cond_init(&engine->signal_cond, NULL);

    engine->dbcfg_list = NULL;
    engine->taskq = schedule_create();
    if (!engine->taskq) {
        free(engine);
        return NULL;
    }
    return engine;
}

void
engine_dealloc(engine_type* engine)
{
    schedule_cleanup(engine->taskq);
    pthread_mutex_destroy(&engine->signal_lock);
    pthread_cond_destroy(&engine->signal_cond);
    if (engine->dbcfg_list) {
        db_configuration_list_free(engine->dbcfg_list);
    }
    hsm_key_factory_deinit();
    free(engine);
}

static void
engine_start_cmdhandler(engine_type* engine)
{
    ods_log_assert(engine);
    ods_log_debug("[%s] start command handler", engine_str);
    janitor_thread_create(&engine->cmdhandler->thread_id, workerthreadclass, (janitor_runfn_t)cmdhandler_start, engine->cmdhandler);
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

    if (engine->config->username_enforcer && engine->config->group_enforcer) {
        ods_log_verbose("[%s] drop privileges to user %s, group %s",
           engine_str, engine->config->username_enforcer, engine->config->group_enforcer);
    } else if (engine->config->username_enforcer) {
        ods_log_verbose("[%s] drop privileges to user %s", engine_str,
           engine->config->username_enforcer);
    } else if (engine->config->group_enforcer) {
        ods_log_verbose("[%s] drop privileges to group %s", engine_str,
           engine->config->group_enforcer);
    }
    if (engine->config->chroot_enforcer) {
        ods_log_verbose("[%s] chroot to %s", engine_str,
            engine->config->chroot_enforcer);
    }
    status = privdrop(engine->config->username_enforcer, engine->config->group_enforcer,
        engine->config->chroot_enforcer, &uid, &gid);
    engine->uid = uid;
    engine->gid = gid;
    privclose(engine->config->username_enforcer, engine->config->group_enforcer);
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
    int i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    engine->workers = (worker_type**) malloc(
        (size_t)engine->config->num_worker_threads_enforcer * sizeof(worker_type*));
    for (i=0; i < (size_t) engine->config->num_worker_threads_enforcer; i++) {
        asprintf(&name, "worker[%d]", i+1);
        engine->workers[i] = worker_create(name, engine->taskq);
    }
}

void
engine_start_workers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] start workers", engine_str);
    for (i=0; i < (size_t) engine->config->num_worker_threads_enforcer; i++) {
        engine->workers[i]->need_to_exit = 0;
        engine->workers[i]->context = get_database_connection(engine);
        if (!engine->workers[i]->context) {
            ods_log_crit("Failed to start worker, could not connect to database");
        } else {
            janitor_thread_create(&engine->workers[i]->thread_id, workerthreadclass, (janitor_runfn_t)worker_start, engine->workers[i]);
        }
    }
}

void
engine_stop_workers(engine_type* engine)
{
    int i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] stop workers", engine_str);
    /* tell them to exit and wake up sleepyheads */
    for (i=0; i < engine->config->num_worker_threads_enforcer; i++) {
        engine->workers[i]->need_to_exit = 1;
    }
    engine_wakeup_workers(engine);
    /* head count */
    for (i=0; i < engine->config->num_worker_threads_enforcer; i++) {
        ods_log_debug("[%s] join worker %i", engine_str, i+1);
        janitor_thread_join(engine->workers[i]->thread_id);
        db_connection_free(engine->workers[i]->context);
    }
}

/**
 * Wake up all workers.
 *
 */
void
engine_wakeup_workers(engine_type* engine)
{
    ods_log_assert(engine);
    ods_log_debug("[%s] wake up workers", engine_str);
    schedule_release_all(engine->taskq);
}

db_connection_t*
get_database_connection(engine_type* engine)
{
    db_connection_t* dbconn;

    if (!(dbconn = db_connection_new())
        || db_connection_set_configuration_list(dbconn, engine->dbcfg_list)
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
probe_database(engine_type* engine)
{
    db_connection_t *conn;
    int version;

    conn = get_database_connection(engine);
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
    if (engine->config->db_type == ENFORCER_DATABASE_TYPE_SQLITE) {
        if (!(dbcfg = db_configuration_new())
            || db_configuration_set_name(dbcfg, "backend")
            || db_configuration_set_value(dbcfg, "sqlite")
            || db_configuration_list_add(engine->dbcfg_list, dbcfg))
        {
            db_configuration_free(dbcfg);
            db_configuration_list_free(engine->dbcfg_list);
            engine->dbcfg_list = NULL;
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
            engine->dbcfg_list = NULL;
            fprintf(stderr, "setup configuration file failed\n");
            return 1;
        }
        dbcfg = NULL;
    }
    else if (engine->config->db_type == ENFORCER_DATABASE_TYPE_MYSQL) {
        if (!(dbcfg = db_configuration_new())
            || db_configuration_set_name(dbcfg, "backend")
            || db_configuration_set_value(dbcfg, "mysql")
            || db_configuration_list_add(engine->dbcfg_list, dbcfg))
        {
            db_configuration_free(dbcfg);
            db_configuration_list_free(engine->dbcfg_list);
            engine->dbcfg_list = NULL;
            fprintf(stderr, "setup configuration backend failed\n");
            return 1;
        }
        if (!(dbcfg = db_configuration_new())
            || db_configuration_set_name(dbcfg, "host")
            || db_configuration_set_value(dbcfg, engine->config->db_host)
            || db_configuration_list_add(engine->dbcfg_list, dbcfg))
        {
            db_configuration_free(dbcfg);
            db_configuration_list_free(engine->dbcfg_list);
            engine->dbcfg_list = NULL;
            fprintf(stderr, "setup configuration file failed\n");
            return 1;
        }
        dbcfg = NULL;
        if (engine->config->db_port) {
            char str[32];
            if (snprintf(&str[0], sizeof(str), "%d", engine->config->db_port) >= (int)sizeof(str)) {
                db_configuration_list_free(engine->dbcfg_list);
                engine->dbcfg_list = NULL;
                fprintf(stderr, "setup configuration file failed\n");
                return 1;
            }
            if (!(dbcfg = db_configuration_new())
                || db_configuration_set_name(dbcfg, "port")
                || db_configuration_set_value(dbcfg, str)
                || db_configuration_list_add(engine->dbcfg_list, dbcfg))
            {
                db_configuration_free(dbcfg);
                db_configuration_list_free(engine->dbcfg_list);
                engine->dbcfg_list = NULL;
                fprintf(stderr, "setup configuration file failed\n");
                return 1;
            }
            dbcfg = NULL;
        }
        if (!(dbcfg = db_configuration_new())
            || db_configuration_set_name(dbcfg, "user")
            || db_configuration_set_value(dbcfg, engine->config->db_username)
            || db_configuration_list_add(engine->dbcfg_list, dbcfg))
        {
            db_configuration_free(dbcfg);
            db_configuration_list_free(engine->dbcfg_list);
            engine->dbcfg_list = NULL;
            fprintf(stderr, "setup configuration file failed\n");
            return 1;
        }
        dbcfg = NULL;
        if (!(dbcfg = db_configuration_new())
            || db_configuration_set_name(dbcfg, "pass")
            || db_configuration_set_value(dbcfg, engine->config->db_password)
            || db_configuration_list_add(engine->dbcfg_list, dbcfg))
        {
            db_configuration_free(dbcfg);
            db_configuration_list_free(engine->dbcfg_list);
            engine->dbcfg_list = NULL;
            fprintf(stderr, "setup configuration file failed\n");
            return 1;
        }
        dbcfg = NULL;
        if (!(dbcfg = db_configuration_new())
            || db_configuration_set_name(dbcfg, "db")
            || db_configuration_set_value(dbcfg, engine->config->datastore)
            || db_configuration_list_add(engine->dbcfg_list, dbcfg))
        {
            db_configuration_free(dbcfg);
            db_configuration_list_free(engine->dbcfg_list);
            engine->dbcfg_list = NULL;
            fprintf(stderr, "setup configuration file failed\n");
            return 1;
        }
        dbcfg = NULL;
    }
    else {
        return 1;
    }
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
 * Set up engine and return the setup status.
 *
 */
ods_status
engine_setup()
{
    int fd, error;
    int pipefd[2];
    char buff = '\0';
    const char *err = "unable to setsid daemon: ";

    ods_log_debug("[%s] enforcer setup", engine_str);

    engine->pid = getpid(); /* We need to do this again after fork() */

    if (!util_pidfile_avail(engine->config->pid_filename_enforcer)) {
        ods_log_error("[%s] Pidfile exists and process with PID is running", engine_str);
        return ODS_STATUS_WRITE_PIDFILE_ERR;
    }
    /* setup database configuration */
    if (setup_database(engine)) return ODS_STATUS_DB_ERR;
    /* Probe the database, can we connect to it? */
    if (probe_database(engine)) {
        ods_log_crit("Could not connect to database or database not set"
            " up properly.");
        return ODS_STATUS_DB_ERR;
    }

    /* create command handler (before chowning socket file) */
    engine->cmdhandler = cmdhandler_create(engine->config->clisock_filename_enforcer, enforcercommands, engine, (void*(*)(void*)) (void(*)(void*))&get_database_connection, (void(*)(void*))&db_connection_free);
    if (!engine->cmdhandler) {
        ods_log_error("[%s] create command handler to %s failed",
            engine_str, engine->config->clisock_filename_enforcer);
        return ODS_STATUS_CMDHANDLER_ERR;
    }

    if(pipe(pipefd)) {
        ods_log_error("[%s] unable to pipe: %s", engine_str, strerror(errno));
        return ODS_STATUS_PIPE_ERR;
    }

    if (!engine->init_setup_done) {
        /* privdrop */
        engine->uid = privuid(engine->config->username_enforcer);
        engine->gid = privgid(engine->config->group_enforcer);
        /* TODO: does piddir exists? */
        /* remove the chown stuff: piddir? */
        ods_chown(engine->config->pid_filename_enforcer, engine->uid, engine->gid, 1);
        ods_chown(engine->config->clisock_filename_enforcer, engine->uid, engine->gid, 0);
        ods_chown(engine->config->working_dir_enforcer, engine->uid, engine->gid, 0);
        if (engine->config->log_filename && !engine->config->use_syslog) {
            ods_chown(engine->config->log_filename, engine->uid, engine->gid, 0);
        }
        if (engine->config->working_dir_enforcer &&
            chdir(engine->config->working_dir_enforcer) != 0) {
            ods_log_error("[%s] chdir to %s failed: %s", engine_str,
                engine->config->working_dir_enforcer, strerror(errno));
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
                    close(pipefd[0]);
                    break;
                default: /* parent */
                    close(pipefd[1]);
                    /* Print messages the child may have send us. */
                    while (read(pipefd[0], &buff, 1) != -1) {
                        if (buff <= 1) break;
                        printf("%c", buff);
                    }
                    close(pipefd[0]);
                    if (buff != '\1') {
                        ods_log_error("[%s] fail to start enforcerd completely", engine_str);
                        exit(1);
                    }
                    ods_log_debug("[%s] enforcerd started successfully", engine_str);
                    exit(0);
            }
            if (setsid() == -1) {
                ods_log_error("[%s] unable to setsid daemon (%s)",
                    engine_str, strerror(errno));
                ods_writen(pipefd[1], err, strlen(err));
                ods_writeln(pipefd[1], strerror(errno));
                write(pipefd[1], "\0", 1);
                close(pipefd[1]);
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

    /* write pidfile */
    if (util_write_pidfile(engine->config->pid_filename_enforcer, engine->pid) == -1) {
        hsm_close();
        ods_log_error("[%s] unable to write pid file", engine_str);
        if (engine->daemonize) {
            ods_writeln(pipefd[1], "unable to write pid file");
            write(pipefd[1], "\0", 1);
            close(pipefd[1]);
        }
        return ODS_STATUS_WRITE_PIDFILE_ERR;
    }
    ods_log_info("[%s] enforcer started", engine_str);
    error = hsm_open2(engine->config->repositories, hsm_prompt_pin);
    if (error != HSM_OK) {
        char* errorstr =  hsm_get_error(NULL);
        if (!errorstr)
            (void)asprintf(&errorstr, "error opening libhsm (errno %i)", error);
        if (errorstr)
            ods_log_error("[%s] %s", engine_str, errorstr);
        if (engine->daemonize) {
            if (errorstr) ods_writeln(pipefd[1], errorstr);
            write(pipefd[1], "\0", 1);
            close(pipefd[1]);
        }
        free(errorstr);
        return ODS_STATUS_HSM_ERR;
    }
    engine->need_to_reload = 0;
    engine_start_cmdhandler(engine);

    write(pipefd[1], "\1", 1);
    close(pipefd[1]);
    if (!engine->daemonize) close(pipefd[0]);
    engine->daemonize = 0; /* don't fork again on reload */
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
        if (engine->config->pid_filename_enforcer) {
            (void)unlink(engine->config->pid_filename_enforcer);
        }
        if (engine->config->clisock_filename_enforcer) {
            (void)unlink(engine->config->clisock_filename_enforcer);
        }
    }
    if (engine->workers && engine->config) {
        for (i=0; i < (size_t) engine->config->num_worker_threads_enforcer; i++) {
            worker_cleanup(engine->workers[i]);
        }
        free(engine->workers);
        engine->workers = NULL;
    } 
    if (engine->cmdhandler) {
        cmdhandler_cleanup(engine->cmdhandler);
        engine->cmdhandler = NULL;
    }
    desetup_database(engine);
}

void
engine_init(engine_type* engine, int daemonize)
{
    struct sigaction action;

    engine->config = NULL;
    engine->workers = NULL;
    engine->cmdhandler = NULL;
    engine->init_setup_done = 0;
    engine->pid = getpid(); /* We need to do this again after fork() */
    engine->uid = -1;
    engine->gid = -1;
    engine->need_to_exit = 0;
    engine->need_to_reload = 0;
    engine->daemonize = daemonize;
    /* catch signals */
    action.sa_handler = (void (*)(int))signal_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGPIPE, &action, NULL);
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
    ods_log_assert(engine);

    engine_start_workers(engine);

    /* call the external start callback function */
    start(engine);

    while (!engine->need_to_exit && !engine->need_to_reload) {
        if (single_run) {
            engine->need_to_exit = 1;
            /* FIXME: all tasks need to terminate, then set need_to_exit to 1 */
        }

        /* We must use locking here to avoid race conditions. We want
         * to sleep indefinitely and want to wake up on signal. This
         * is to make sure we never mis the signal. */
        pthread_mutex_lock(&engine->signal_lock);
        if (!engine->need_to_exit && !engine->need_to_reload && !single_run) {
            /* TODO: this silly. We should be handling the commandhandler
             * connections. No reason to spawn that as a thread.
             * Also it would be easier to wake up the command hander
             * as signals will reach it if it is the main thread! */
            ods_log_debug("[%s] taking a break", engine_str);
            pthread_cond_wait(&engine->signal_cond, &engine->signal_lock);
        }
        pthread_mutex_unlock(&engine->signal_lock);
    }
    ods_log_debug("[%s] enforcer halted", engine_str);
    engine_stop_workers(engine);
    cmdhandler_stop(engine->cmdhandler);
    schedule_purge(engine->taskq); /* Remove old tasks in queue */
    hsm_close();
    return 0;
}
