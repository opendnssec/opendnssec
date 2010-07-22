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
 * Threading and locking.
 *
 */

#ifndef SCHEDULER_LOCKS_H
#define SCHEDULER_LOCKS_H

#include "config.h"
#include "util/log.h"

#include <errno.h>
#include <stdlib.h>

#define LOCKRET(func) do { \
	int err; \
	if ( (err=(func)) != 0) \
		se_log_error("%s at %d could not " #func ": %s", \
		__FILE__, __LINE__, strerror(err)); \
	} while(0)

#if defined(HAVE_PTHREAD)

#include <pthread.h>

/** use pthread mutex for basic lock */
typedef pthread_mutex_t lock_basic_type;
/** use pthread cond for basic condition */
typedef pthread_cond_t cond_basic_type;

/** small front for pthread init func, NULL is default attrs. */
#define lock_basic_init(lock) LOCKRET(pthread_mutex_init(lock, NULL))
#define lock_basic_destroy(lock) LOCKRET(pthread_mutex_destroy(lock))
#define lock_basic_lock(lock) LOCKRET(pthread_mutex_lock(lock))
#define lock_basic_unlock(lock) LOCKRET(pthread_mutex_unlock(lock))

/** our own alarm clock */
#define lock_basic_set(cond) LOCKRET(pthread_cond_init(cond, NULL))
#define lock_basic_sleep(cond, lock, sleep) LOCKRET(se_thread_wait(cond, lock, sleep))
#define lock_basic_alarm(cond) LOCKRET(pthread_cond_signal(cond))
#define lock_basic_off(cond) LOCKRET(pthread_cond_destroy(cond))

int se_thread_wait(cond_basic_type* cond, lock_basic_type* lock, time_t wait);

/** thread creation */
typedef pthread_t se_thread_type;
/** Pass where to store tread_t in thr. Use default NULL attributes. */
#define se_thread_create(thr, func, arg) LOCKRET(pthread_create(thr, NULL, func, arg))
#define se_thread_detach(thr) LOCKRET(pthread_detach(thr))
#define se_thread_self() pthread_self()
#define se_thread_join(thr) LOCKRET(pthread_join(thr, NULL))

int se_thread_wait(cond_basic_type* cond, lock_basic_type* lock, time_t wait);
void se_thread_blocksigs(void);

#else /* !HAVE_PTHREAD */

/* we do not have PTHREADS */
#define PTHREADS_DISABLED 1

typedef int lock_basic_type;
#define lock_basic_init(lock) 		/* nop */
#define lock_basic_destroy(lock) 	/* nop */
#define lock_basic_lock(lock) 		/* nop */
#define lock_basic_unlock(lock) 	/* nop */

#define lock_basic_set(cond)       /* nop */
#define lock_basic_sleep(cond, lock, sleep) /* nop */
#define lock_basic_alarm(cond)     /* nop */
#define lock_basic_off(cond)       /* nop */

typedef pid_t se_thread_type;
#define se_thread_create(thr, func, arg) se_thr_fork_create(thr, func, arg)
#define se_thread_detach(thr)      /* nop */
#define se_thread_self() getpid()
#define se_thread_join(thr) se_thr_fork_wait(thr)

void se_thr_fork_create(se_thread_type* thr, void* (*func)(void*), void* arg);
void se_thr_fork_wait(se_thread_type thread);

#endif /* HAVE_PTHREAD */

void se_thread_blocksigs(void);

#endif /* SCHEDULER_LOCKS_H */
