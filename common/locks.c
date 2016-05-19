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

#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h> /* sigfillset(), sigprocmask() */
#include <string.h> /* strerror() */
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h> /* gettimeofday() */
#endif
#ifdef HAVE_TIME_H
#include <time.h> /* gettimeofday() */
#endif

static const char* lock_str = "lock";

int
ods_thread_wait(cond_basic_type* cond, lock_basic_type* lock, time_t wait)
{
    struct timespec ts;
    int ret = 0;

#ifndef HAVE_CLOCK_GETTIME
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) {
        ods_log_error("[%s] clock_gettime() error: %s", lock_str,
            strerror(errno));
        return 1;
    }
    ts.tv_sec = tv.tv_sec;
    ts.tv_nsec = (tv.tv_usec/1000);
#else /* HAVE_CLOCK_GETTIME */
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        ods_log_error("[%s] clock_gettime() error: %s", lock_str,
            strerror(errno));
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

crash_threadclass_t detachedthreadclass;
crash_threadclass_t workerthreadclass;
crash_threadclass_t handlerthreadclass;

struct alertbuffer_struct {
    char buffer[1024];
    int index;
};
static void alert(struct alertbuffer_struct* buffer, const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 2, 3)))
#endif
;
static void alertsyslog(const char* format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
;

inline static int
alertoutput(struct alertbuffer_struct* buffer, int ch)
{
    if (buffer->index < sizeof(buffer->buffer)) {
        buffer->buffer[buffer->index++] = ch;
        return 0;
    } else
        return -1;
}

static void
alertinteger(struct alertbuffer_struct* buffer, unsigned long value, int base)
{
    char ch;
    if (value > base - 1)
        alertinteger(buffer, value / base, base);
    ch = "0123456789abcdef"[value % base];
    alertoutput(buffer, ch);
}

static void
valert(struct alertbuffer_struct* buffer, const char* format, va_list args)
{
    int idx, len;
    const char* stringarg;
    void* pointerarg;
    int integerarg;
    long longarg;
    idx = 0;
    while (format[idx]) {
        if (format[idx] == '%') {
            switch (format[idx + 1]) {
                case '%':
                    alertoutput(buffer, '%');
                    idx += 2;
                    break;
                case 's':
                    stringarg = va_arg(args, char*);
                    if (stringarg == NULL)
                        stringarg = "(null)";
                    while(stringarg)
                        if(alertoutput(buffer, *(stringarg++)))
                            break;
                    idx += 2;
                    break;
                case 'p':
                    pointerarg = va_arg(args, void*);
                    if (pointerarg == NULL) {
                        stringarg = "(null)";
                        while(stringarg)
                            alertoutput(buffer, *(stringarg++));
                    } else {
                        alertoutput(buffer, '0');
                        alertoutput(buffer, 'x');
                        alertinteger(buffer, (unsigned long) pointerarg, 16);
                    }
                    idx += 2;
                    break;
                case 'l':
                    switch (format[idx + 2]) {
                        case 'd':
                            longarg = va_arg(args, long);
                            if (longarg < 0) {
                                alertoutput(buffer, '-');
                                alertinteger(buffer, 1UL + ~((unsigned long) longarg), 10);
                            } else
                                alertinteger(buffer, longarg, 10);
                            idx += 3;
                            break;
                        case '\0':
                            alertoutput(buffer, format[idx++]);
                            break;
                        default:
                            alertoutput(buffer, format[idx++]);
                            alertoutput(buffer, format[idx++]);
                            alertoutput(buffer, format[idx++]);
                    }
                    break;
                case 'd':
                    integerarg = va_arg(args, int);
                    alertinteger(buffer, (long) integerarg, 10);
                    idx += 2;
                    break;
                case '\0':
                    alertoutput(buffer, '%');
                    idx += 1;
                    break;
                default:
                    alertoutput(buffer, format[idx++]);
                    alertoutput(buffer, format[idx++]);
            }
        } else {
            alertoutput(buffer, format[idx++]);
        }
    }
}

static void
alertsyslog(const char* format, ...)
{
    va_list args;
    struct alertbuffer_struct buffer;
    va_start(args, format);
    buffer.index = 0;
    valert(&buffer, format, args);
    va_end(args);
    if (buffer.index < sizeof(buffer.buffer)) {
        buffer.buffer[buffer.index] = '\0';
    } else {
        strcpy(&buffer.buffer[buffer.index - strlen("...\n") -1], "...\n");
    }
    write(2, buffer.buffer, strlen(buffer.buffer));
    syslog(LOG_CRIT, "%s", buffer.buffer);
}

void
ods_crash_initialize(char*argv0)
{
    crash_initialize(alertsyslog, ods_log_error);
    crash_threadclass_create(&detachedthreadclass, "daemonthreads");
    crash_threadclass_setautorun(detachedthreadclass);
    crash_threadclass_setblockedsignals(detachedthreadclass);
    crash_threadclass_setdetached(detachedthreadclass);
    crash_threadclass_create(&workerthreadclass, "workerthreads");
    crash_threadclass_setautorun(workerthreadclass);
    crash_threadclass_setblockedsignals(workerthreadclass);
    crash_threadclass_create(&handlerthreadclass, "handlerthreads");
    crash_threadclass_setautorun(handlerthreadclass);
    crash_trapsignals(argv0);
}
