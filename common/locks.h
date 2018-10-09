/*
 * Copyright (c) 2009-2018 NLNet Labs.
 * All rights reserved.
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
 */

#ifndef SCHEDULER_LOCKS_H
#define SCHEDULER_LOCKS_H

#include "config.h"
#include "log.h"
#include "janitor.h"

#include <errno.h>
#include <stdlib.h>

#include <pthread.h>

/** ods-signerd will crash if the thread stacksize is too small */
#define ODS_MINIMUM_STACKSIZE 524288

/** thread creation */
typedef janitor_thread_t ods_thread_type;

int ods_thread_wait(pthread_cond_t* cond, pthread_mutex_t* lock, time_t wait);

void ods_janitor_initialize(char*argv0);
extern janitor_threadclass_t detachedthreadclass;
extern janitor_threadclass_t workerthreadclass;
extern janitor_threadclass_t handlerthreadclass;
extern janitor_threadclass_t cmdhandlerthreadclass;

#endif /* SHARED_LOCKS_H */
