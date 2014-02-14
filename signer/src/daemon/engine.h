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
#include "daemon/dnshandler.h"
#include "daemon/xfrhandler.h"
#include "daemon/worker.h"
#include "scheduler/fifoq.h"
#include "scheduler/schedule.h"
#include "shared/allocator.h"
#include "shared/locks.h"
#include "signer/zonelist.h"
#include "wire/edns.h"

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
    worker_type** drudgers;
    zonelist_type* zonelist;
    schedule_type* taskq;
    fifoq_type* signq;
    cmdhandler_type* cmdhandler;
    dnshandler_type* dnshandler;
    xfrhandler_type* xfrhandler;
    edns_data_type edns;
    int cmdhandler_done;

    pid_t pid;
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
 * \return 0 if successful, 1 on error
 *
 */
int engine_start(const char* cfgfile, int cmdline_verbosity,
    int daemonize, int info, int single_run);

/**
 * Start drudgers.
 * \param[in] engine engine
 *
 */
void engine_start_drudgers(engine_type* engine);

/**
 * Stop drudgers.
 * \param[in] engine engine
 *
 */
void engine_stop_drudgers(engine_type* engine);

/**
 * Wake up workers.
 * \param[in] engine engine
 *
 */
void engine_wakeup_workers(engine_type* engine);

/**
 * Update zones.
 * \param[in] engine engine
 * \param[in] zl_changed whether the zonelist has changed or not
 *
 */
void engine_update_zones(engine_type* engine, ods_status zl_changed);

/**
 * Clean up engine.
 * \param[in] engine engine
 *
 */
void engine_cleanup(engine_type* engine);

#endif /* DAEMON_ENGINE_H */
