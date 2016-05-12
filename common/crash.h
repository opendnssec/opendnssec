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

typedef void (*daemonutil_alertfn_t)(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

extern void crash_initialize(daemonutil_alertfn_t fatalalertfn, daemonutil_alertfn_t problemalertfn);

extern int  crash_thread_create(crash_thread_t* thread, void*(*func)(void*),void*data);
extern void crash_thread_start(crash_thread_t thread);
extern void crash_thread_join(crash_thread_t thread, void* data);

extern int crash_disablecoredump(void);
extern int crash_trapsignals(char* argv0);

extern int crash_thread_createrunning(crash_thread_t* thread,void*(*func)(void*),void*data);
extern int crash_thread_createrunningdetached(crash_thread_t* thread,void*(*func)(void*),void*data);
extern void crash_thread_detach(crash_thread_t thread);
extern void crash_thread_signal(crash_thread_t thread);

#endif
