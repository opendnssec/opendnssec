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
 * Threading and locking.
 *
 */

#include "config.h"
#include "locks.h"
#include "log.h"

#include <errno.h>
#include <signal.h> /* sigfillset(), sigprocmask() */
#include <string.h> /* strerror() */
#include <time.h> /* gettimeofday() */

static const char* lock_str = "lock";

int
ods_thread_create(pthread_t *thr, void *(*func)(void *), void *arg)
{
    int ret, attr_set;
    pthread_attr_t attr;
    size_t stacksize;

    attr_set = (
           !pthread_attr_init(&attr)
        && !pthread_attr_getstacksize(&attr, &stacksize)
        && stacksize < ODS_MINIMUM_STACKSIZE
        && !pthread_attr_setstacksize(&attr, ODS_MINIMUM_STACKSIZE)
    );

    ret = pthread_create(thr, attr_set?&attr:NULL, func, arg);
    if (attr_set)
        (void) pthread_attr_destroy(&attr);

    if ( ret != 0) {
        ods_log_error("%s at %d could not pthread_create(thr, &attr, func, arg): %s",
        __FILE__, __LINE__, strerror(ret));
    }

    return ret;
}

int
ods_thread_wait(pthread_cond_t* cond, pthread_mutex_t* lock, time_t wait)
{
    struct timespec ts;

    if (wait <= 0)
        return pthread_cond_wait(cond, lock);

    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        ods_log_error("[%s] clock_gettime() error: %s", lock_str,
            strerror(errno));
        return 1;
    }

    ts.tv_sec += wait;
    return pthread_cond_timedwait(cond, lock, &ts);
}

void
ods_thread_blocksigs(void)
{
    int err = 0;
    sigset_t sigset;
    sigfillset(&sigset);

    if((err=pthread_sigmask(SIG_SETMASK, &sigset, NULL)))
        ods_fatal_exit("[%s] pthread_sigmask: %s", lock_str, strerror(err));
}
