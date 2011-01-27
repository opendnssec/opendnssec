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
#include "shared/log.h"

#include <errno.h>
#include <signal.h> /* sigfillset(), sigprocmask() */
#include <string.h> /* strerror() */
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h> /* gettimeofday() */
#endif
#ifdef HAVE_TIME_H
#include <time.h> /* gettimeofday() */
#endif

static const char* locks_str = "locks";

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
            ods_fatal_exit("[%s] unable to fork thread: %s", locks_str, strerror(errno));
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
        ods_log_error("[%s] waitpid(%d): %s", locks_str, (int)thread, strerror(errno));
	if (status != 0)
        ods_log_warning("[%s] process %d abnormal exit with status %d",
            locks_str, (int)thread, status);
}

#else /* defined(HAVE_PTHREAD) */


int
se_thread_wait(cond_basic_type* cond, lock_basic_type* lock, time_t wait)
{
    struct timespec ts;
    int ret = 0;

    /* If timeshift is enabled, we don't care about threads. No need
     * to take the timeshift into account here */

#ifndef HAVE_CLOCK_GETTIME
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) {
        ods_log_error("[%s] gettimeofday() error: %s", locks_str, strerror(errno));
        return 1;
    }
    ts.tv_sec = tv.tv_sec;
    ts.tv_nsec = (tv.tv_usec/1000);
#else /* HAVE_CLOCK_GETTIME */
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        ods_log_error("[%s] clock_gettime() error: %s", locks_str, strerror(errno));
        return 1;
    }
#endif /* !HAVE_CLOCK_GETTIME */

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
        ods_fatal_exit("[%s] pthread_sigmask: %s", locks_str, strerror(err));
#else /* !HAVE_PTHREAD */
    /* have nothing, do single process signal mask */
    if((err=sigprocmask(SIG_SETMASK, &sigset, NULL)))
        ods_fatal_exit("[%s] sigprocmask: %s", locks_str, strerror(errno));
#endif /* HAVE_PTHREAD */
}
