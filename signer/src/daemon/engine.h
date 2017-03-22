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

#include "daemon/cfg.h"
#include "cmdhandler.h"
#include "daemon/dnshandler.h"
#include "daemon/xfrhandler.h"
#include "scheduler/worker.h"
#include "scheduler/schedule.h"
#include "status.h"
#include "locks.h"
#include "signer/zonelist.h"
#include "wire/edns.h"

struct engine_struct {
    engineconfig_type* config;
    worker_type** workers;
    schedule_type* taskq;
    cmdhandler_type* cmdhandler;

    pid_t pid;
    uid_t uid;
    gid_t gid;

    int daemonize;
    int need_to_exit;
    int need_to_reload;

    /* Main thread blocks on this condition when there is nothing to do */
    pthread_cond_t signal_cond;
    pthread_mutex_t signal_lock;

    zonelist_type* zonelist;
    dnshandler_type* dnshandler;
    xfrhandler_type* xfrhandler;
    edns_data_type edns;
};

engine_type* engine_create(void);
ods_status engine_setup_preconfig(engine_type* engine, const char* cfgfile);
ods_status engine_setup_config(engine_type* engine, const char* cfgfile, int cmdline_verbosity, int daemonize);
ods_status engine_setup_initialize(engine_type* engine, int* fdptr);
ods_status engine_setup_signals(engine_type* engine);
ods_status engine_setup_workstart(engine_type* engine);
ods_status engine_setup_netwstart(engine_type* engine);
ods_status engine_setup_finish(engine_type* engine, int fd);
int engine_start(engine_type*);
ods_status engine_setup_signals(engine_type* engine);

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
