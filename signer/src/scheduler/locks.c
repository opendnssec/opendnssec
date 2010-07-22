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

#include "config.h"
#include "scheduler/locks.h"
#include "util/log.h"

#include <errno.h>
#include <signal.h> /* sigfillset(), sigprocmask() */
#include <string.h> /* strerror() */
#include <time.h> /* clock_gettime() */

#if !defined(HAVE_PTHREAD)
#include <sys/wait.h> /* waitpid() */
#include <sys/types.h> /* getpid(), waitpid() */
#include <unistd.h> /* fork(), getpid() */


/**
 * No threading available: fork a new process.
 * This means no shared data structure, and no locking.
 * Only the main thread ever returns. Exits on errors.
 * @param thr: the location where to store the thread-id.
 * @param func: function body of the thread. Return value of func is lost.
 * @param arg: user argument to func.
 */
void
se_thr_fork_create(se_thread_type* thr, void* (*func)(void*), void* arg)
{
    pid_t pid = fork();

    switch (pid) {
    	default: /* main */
			*thr = (se_thread_type)pid;
			return;
		case 0: /* child */
			*thr = (se_thread_type)getpid();
			(void)(*func)(arg);
			exit(0);
		case -1: /* error */
			se_fatal_exit("unable to fork thread: %s", strerror(errno));
	}
}


/**
 * There is no threading. Wait for a process to terminate.
 * Note that ub_thread_t is defined as pid_t.
 * @param thread: the process id to wait for.
 */
void se_thr_fork_wait(se_thread_type thread)
{
    int status = 0;

	if (waitpid((pid_t)thread, &status, 0) == -1)
		se_log_error("waitpid(%d): %s", (int)thread, strerror(errno));
	if (status != 0)
		se_log_warning("process %d abnormal exit with status %d",
			(int)thread, status);
}

#else /* defined(HAVE_PTHREAD) */


int
se_thread_wait(cond_basic_type* cond, lock_basic_type* lock, time_t wait)
{
    struct timespec ts;
    int ret = 0;

    /* If timeshift is enabled, we don't care about threads. No need
     & to take the timeshift into account here */
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        se_log_error("clock_gettime() error: %s", strerror(errno));
        return 1;
    }

    if (wait > 0) {
        ts.tv_sec = ts.tv_sec + wait;
        ret = pthread_cond_timedwait(cond, lock, &ts);
    } else {
        ret = pthread_cond_wait(cond, lock);
    }

    if (ret == ETIMEDOUT) {
        return 0;
    }
    return ret;
}

#endif /* defined(HAVE_PTHREAD) */


void
se_thread_blocksigs(void)
{
    int err = 0;
    sigset_t sigset;
    sigfillset(&sigset);

#ifndef HAVE_PTHREAD
    if((err=pthread_sigmask(SIG_SETMASK, &sigset, NULL)))
        se_fatal_exit("pthread_sigmask: %s", strerror(err));
#else /* !HAVE_PTHREAD */
    /* have nothing, do single process signal mask */
    if((err=sigprocmask(SIG_SETMASK, &sigset, NULL)))
        se_fatal_exit("sigprocmask: %s", strerror(errno));
#endif /* HAVE_PTHREAD */
}
