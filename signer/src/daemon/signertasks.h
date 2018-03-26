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

#ifndef SIGNERTASKS_H
#define SIGNERTASKS_H

#include "config.h"
#include <time.h>

#include "scheduler/task.h"
#include "scheduler/fifoq.h"
#include "status.h"
#include "locks.h"

struct worker_context {
    engine_type* engine;
    worker_type* worker;
    fifoq_type* signq;
    time_t clock_in;
    zone_type* zone;
    names_view_type* view;
};

void drudge(worker_type* worker);

time_t do_readsignconf(task_type* task, const char* zonename, void* zonearg, void *contextarg);
time_t do_forcereadsignconf(task_type* task, const char* zonename, void* zonearg, void *contextarg);
time_t do_signzone(task_type* task, const char* zonename, void* zonearg, void *contextarg);
time_t do_readzone(task_type* task, const char* zonename, void* zonearg, void *contextarg);
time_t do_forcereadzone(task_type* task, const char* zonename, void* zonearg, void *contextarg);
time_t do_writezone(task_type* task, const char* zonename, void* zonearg, void *contextarg);

#endif /* SIGNERTASKS_H */
