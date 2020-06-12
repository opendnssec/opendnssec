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

#ifndef DAEMON_ENGINE_H
#define DAEMON_ENGINE_H

#include "config.h"
#include <signal.h>

typedef struct engine_struct engine_type;

#include "cfg.h"
#include "cmdhandler.h"
#include "scheduler/task.h"
#include "scheduler/schedule.h"
#include "db/dbw.h"

struct engine_struct {
    engineconfig_type* config;

    pid_t pid;
    uid_t uid;
    gid_t gid;

    int daemonize;
    int need_to_exit;
    int need_to_reload;
    int init_setup_done;

    worker_type** workers;
    schedule_type* taskq;
    cmdhandler_type* cmdhandler;

    /* Main thread blocks on this condition when there is nothing to do */
    pthread_cond_t signal_cond;
    pthread_mutex_t signal_lock;
};

/**
 * Try to open a connection to the database.
 * \param engine, the engine containing database configuration
 * \return connection on success, NULL on failure.
 */
db_connection_t* get_database_connection(engine_type* engine);

/**
 * Setup the engine started by engine_create
 * \param[in] engine the engine returned from engine_start
 * \param[in] commands NULL terminated list of command functions for 
 *            the engine that the command handler can run.
 * \param[in] help NULL terminated list of help functions that print help 
 *            for the command to a socket.
 */

ods_status engine_setup(void);

/**
 * Clean up engine.
 * \param[in] engine engine
 *
 */
void engine_teardown(engine_type* engine);

void engine_init(engine_type* engine, int daemonize);

typedef void (*start_cb_t)(engine_type* engine);

/**
 * Run the engine after setting it up using engine_setup.
 * When this function returns the runloop has finished and
 * the engine is ready to stop.
 * \param[in] engine the engine returned from engine_start
 * \param[in] single_run run once
 * \return 0 if terminated normally, 1 on unrecoverable error.
 *
 */
int engine_run(engine_type* engine, start_cb_t start, int single_run);

/**
 * Stop the engine after engine_runloop returns.
 * \param[in] engine engine
 *
 */
void engine_stop(engine_type* engine);

/**
 * Wake up workers.
 * \param[in] engine engine
 *
 */
void engine_wakeup_workers(engine_type* engine);
/** signal all workers to stop. Blocks until all workers are joined.
 * \param[in] engine engine */
void engine_stop_workers(engine_type* engine);
/** start all workers.
 * \param[in] engine engine */
void engine_start_workers(engine_type* engine);

engine_type* engine_alloc(void);
void engine_dealloc(engine_type* engine);

#endif /* DAEMON_ENGINE_H */
