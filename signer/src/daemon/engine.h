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

#ifndef DAEMON_ENGINE_H
#define DAEMON_ENGINE_H

#include "config.h"
#include "daemon/cmdhandler.h"
#include "daemon/config.h"
#include "daemon/worker.h"
#include "scheduler/locks.h"
#include "scheduler/task.h"
#include "signer/zonelist.h"

#include <signal.h>

#define SIGNAL_RUN 0
#define SIGNAL_INIT 1
#define SIGNAL_RELOAD 2
#define SIGNAL_SHUTDOWN 3

/**
 * Engine stuff.
 *
 */
typedef struct engine_struct engine_type;
struct engine_struct {
    engineconfig_type* config;
    cmdhandler_type* cmdhandler;
    worker_type** workers;
    zonelist_type* zonelist;
    tasklist_type* tasklist;
    int cmdhandler_done;

    sig_atomic_t signal;
    cond_basic_type signal_cond;
    lock_basic_type signal_lock;

    pid_t pid;
    pid_t zfpid;
    uid_t uid;
    gid_t gid;

    int daemonize;
    int need_to_exit;
    int need_to_reload;
};

/**
 * Create engine.
 * \return engine_type* created engine
 *
 */
engine_type* engine_create(void);

/**
 * Start engine.
 * \param[in] cfgfile configuration file
 * \param[in] cmdline_verbosity how many -v on the command line
 * \param[in] daemonize to run as daemon or not
 * \param[in] info print info and exit
 * \param[in] single_run run once
 *
 */
void engine_start(const char* cfgfile, int cmdline_verbosity,
    int daemonize, int info, int single_run);

/**
 * Update zone list.
 * \param[in] the signer engine
 * \param[in] buf response message
 * \return int 0 if zonelist changed, 1 otherwise
 *
 */
int engine_update_zonelist(engine_type* engine, char* buf);

/**
 * Update zones.
 * \param[in] the signer engine
 * \paran[in] zone_name update only this zone
 * \param[in] buf response message
 *
 */
void engine_update_zones(engine_type* engine, const char* zone_name, char* buf);


/**
 * Clean up engine.
 * \param[in] engine engine
 *
 */
void engine_cleanup(engine_type* engine);

#endif /* DAEMON_ENGINE_H */
