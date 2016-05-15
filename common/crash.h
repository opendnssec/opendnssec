/*
 * Copyright (c) 2016 NLNet Labs. All rights reserved.
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

#ifndef DEBUG_H
#define DEBUG_H

#include <pthread.h>

struct crash_thread_struct;
typedef struct crash_thread_struct* crash_thread_t;

typedef void (*crash_runfn_t)(void *);

typedef void (*crash_alertfn_t)(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

extern void crash_initialize(crash_alertfn_t fatalalertfn, crash_alertfn_t problemalertfn);

struct crash_threadclass_struct;
typedef struct crash_threadclass_struct* crash_threadclass_t;
#define crash_threadclass_DEFAULT (NULL)

extern int crash_threadclass_create(crash_threadclass_t* threadclassptr, char* name);
extern char* crash_threadclass_name(crash_threadclass_t threadclass);
extern void crash_threadclass_destroy(crash_threadclass_t threadclass);
extern void crash_threadclass_setdetached(crash_threadclass_t threadclass);
extern void crash_threadclass_setautorun(crash_threadclass_t threadclass);
extern void crash_threadclass_setblockedsignals(crash_threadclass_t threadclass);
extern void crash_threadclass_setminstacksize(crash_threadclass_t threadclass, size_t minstacksize);

extern int crash_thread_create(crash_thread_t* thread, crash_threadclass_t threadclass, crash_runfn_t func, void*data);
extern void crash_thread_start(crash_thread_t thread);
extern void crash_thread_join(crash_thread_t thread, void* data);

extern int crash_disablecoredump(void);
extern int crash_trapsignals(char* argv0);

extern void crash_thread_signal(crash_thread_t thread);

extern crash_threadclass_t detachedthreadclass;
extern crash_threadclass_t workerthreadclass;
extern crash_threadclass_t vanillathreadclass;

#endif
