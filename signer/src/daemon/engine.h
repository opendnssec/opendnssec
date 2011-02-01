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
#include "daemon/cfg.h"
#include "daemon/cmdhandler.h"
#include "daemon/worker.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "shared/allocator.h"
#include "shared/locks.h"
#include "signer/zonelist.h"

#include <signal.h>

/**
 * Engine stuff.
 *
 */
typedef struct engine_struct engine_type;
struct engine_struct {
    allocator_type* allocator;
    engineconfig_type* config;
    worker_type** workers;
    zonelist_type* zonelist;
    schedule_type* taskq;
    cmdhandler_type* cmdhandler;
    int cmdhandler_done;

    pid_t pid;
    pid_t zfpid;
    uid_t uid;
    gid_t gid;

    int daemonize;
    int need_to_exit;
    int need_to_reload;

    sig_atomic_t signal;
    cond_basic_type signal_cond;
    lock_basic_type signal_lock;
};

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
 * Wake up workers.
 * \param[in] engine engine
 *
 */
void engine_wakeup_workers(engine_type* engine);

/**
 * Parse notify command.
 * \param[in] zone zone
 * \param[in] cmd notify command.
 *
 */
void set_notify_ns(zone_type* zone, const char* cmd);

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
 * \param[in] engine the signer engine
 *
 */
void engine_update_zones(engine_type* engine);

/**
 * Search for zone in workers
 * \param[in] engine the signer engine
 * \paran[in] zone_name search for this zone
 * \return int 1 if zone was not found
 *
 */
int engine_search_workers(engine_type* engine, const char* zone_name);

/**
 * Clean up engine.
 * \param[in] engine engine
 *
 */
void engine_cleanup(engine_type* engine);

#endif /* DAEMON_ENGINE_H */
