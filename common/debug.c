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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _GNU_SOURCE
#define __USE_GNU
#endif

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <dlfcn.h>
#include <pthread.h>
#ifdef HAVE_BACKTRACE_FULL
#include <backtrace.h>
#endif
#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#endif
#ifdef HAVE_LIBUNWIND
#include <libunwind.h>
#endif

#include "debug.h"

static char* alertbuffer[1024];

static void alertinteger(long value);
void alert(const char *format, ...);

static struct sigaction original_usr1_action;
static struct sigaction original_abrt_action;
static struct sigaction original_segv_action;
static struct sigaction original_fpe_action;
static struct sigaction original_ill_action;
static struct sigaction original_bus_action;
static struct sigaction original_sys_action;

static void alertinteger(long value) {
    char s[1];
    s[0] = '0';
    if (value < 0) {
        write(2, "-", 1);
        value = -value;
    }
    if (value > 9)
        alertinteger(value / 10);
    *s += value % 10;
    write(2, s, 1);
}

void alert(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int startidx, currentidx, len;
    const char* stringarg;
    int integerarg;
    long longarg;
    startidx = 0;
    while (format[startidx]) {
        currentidx = startidx;
        while (format[currentidx] && format[currentidx] != '%')
            ++currentidx;
        if (currentidx - startidx > 0)
            write(2, &format[startidx], currentidx - startidx);
        if (format[currentidx] == '%') {
            switch (format[currentidx + 1]) {
                case '%':
                    write(2, "%", 1);
                    currentidx += 2;
                    break;
                case 's':
                    stringarg = va_arg(args, char*);
                    if (stringarg == NULL)
                        stringarg = "(null)";
                    len = strlen(stringarg);
                    write(2, stringarg, len);
                    currentidx += 2;
                    break;
                case 'l':
                    switch (format[currentidx + 2]) {
                        case 'd':
                            longarg = va_arg(args, long);
                            alertinteger(longarg);
                            currentidx += 3;
                            break;
                        default:
                            write(2, &format[startidx], 2);
                            currentidx += 2;
                    }
                    break;
                case 'd':
                    integerarg = va_arg(args, int);
                    alertinteger((long) integerarg);
                    currentidx += 2;
                    break;
                case '\0':
                    write(2, "%", 1);
                    currentidx += 1;
                    break;
                default:
                    write(2, &format[startidx], 2);
                    currentidx += 2;
            }
        }
        startidx = currentidx;
    }
    va_end(args);
}

void
fail(const char* file, int line, const char* func, const char* expr, int stat)
{
    alert("Failure %d in %s at %s:%d of %s\n",stat,func,file,line,expr);
}

void
log_message(int level, const char* file, int line, const char* func, const char* format, ...)
{
    va_list args;
    const char* levelmsg;
    va_start(args, format);
    switch(level) {
        case log_FATAL: levelmsg = "fatal";   break;
        case log_ERROR: levelmsg = "error";   break;
        case log_WARN:  levelmsg = "warning"; break;
        case log_INFO:  levelmsg = "info";    break;
        case log_DEBUG: levelmsg = "debug";   break;
        case log_TRACE: levelmsg = "trace";   break;
        default:        levelmsg = "unknown";
    }
    fprintf(stderr, "%s:%d %s() %s:", file, line, func, levelmsg);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
}

struct thread_struct {
    struct thread_struct* next;
    struct thread_struct* prev;
    pthread_t thread;
    void* (*runfunc)(void*);
    void* rundata;
    int isstarted;
    pthread_barrier_t startbarrier;
};
static pthread_mutex_t threadlock = PTHREAD_MUTEX_INITIALIZER;
static struct thread_struct *threadlist = NULL;
static pthread_once_t threadlocatorinitializeonce = PTHREAD_ONCE_INIT;
static pthread_key_t threadlocator;
static int threadcount;
static pthread_cond_t threadblock = PTHREAD_COND_INITIALIZER;

void
uninstallthread(struct thread_struct* info)
{
    if(info == NULL)
        return;
    pthread_mutex_lock(&threadlock);
    if(threadlist != NULL) {
        info->next->prev = info->prev;
        info->prev->next = info->next;
        if(threadlist == info) {
            if(info->next == info) {
                threadlist = NULL;
            } else {
                threadlist = info->next;
            }
        }
        info->next = info->prev = NULL;
        free(info);
        pthread_barrier_destroy(&info->startbarrier);
        if(--threadcount <= 0) {
            pthread_cond_signal(&threadblock);
        }
    }
    pthread_mutex_unlock(&threadlock);
}

static void*
runthread(void* data)
{
    struct thread_struct* info;
    info = (struct thread_struct*) data;
    pthread_barrier_wait(&info->startbarrier);
    data = info->runfunc(info->rundata);
    uninstallthread(info);
    return data;
}

static void
threadlocatorinitialize(void)
{
    pthread_key_create(&threadlocator, NULL);
}

void
createthread(thread_t* thread, void*(*func)(void*),void*data)
{
    struct thread_struct* info;
    info = malloc(sizeof(struct thread_struct));
    info->runfunc = func;
    info->rundata = data;
    info->isstarted = 0;
    pthread_barrier_init(&info->startbarrier, NULL, 2);
    pthread_create(&info->thread, NULL, runthread, info);
    pthread_mutex_lock(&threadlock);
    pthread_once(&threadlocatorinitializeonce, threadlocatorinitialize);
    pthread_setspecific(threadlocator, info);
    if(threadlist != NULL) {
        info->next = threadlist;
        info->prev = threadlist->prev;
        threadlist->next->prev = info;
        threadlist->next = info;
    } else {
        info->next = info->prev = info;
    }
    threadlist = info;
    pthread_mutex_unlock(&threadlock);
    *thread = info;
}

void
startthread(thread_t thread)
{
    int isstarted;
    pthread_mutex_lock(&threadlock);
    isstarted = thread->isstarted;
    thread->isstarted = 1;
    pthread_mutex_unlock(&threadlock);
    if(!isstarted) {
        pthread_barrier_wait(&thread->startbarrier);
    }
}

static void
exitfunction(void)
{
    struct thread_struct* list;
    pthread_mutex_lock(&threadlock);
    list = threadlist;
    threadlist = NULL;
    pthread_mutex_unlock(&threadlock);
    if(list)
        list->prev->next = NULL;
    while(list) {
        /* deliberate no free of list structure, memory may be corrupted */
        list = list->next;
    }
}

void
dumpthreads(void)
{
    struct thread_struct* info;
    struct thread_struct* list;
    threadcount = 0;
    alert("dumpthreads");
    pthread_mutex_lock(&threadlock);
    info = pthread_getspecific(threadlocator);
    list = threadlist;
    if(list) {
        threadcount = 0;
        do {
            if(list != info) {
                pthread_kill(list->thread, SIGUSR2);
                list = list->next;
                threadcount += 1;
            }
        } while(list != threadlist);
        if(threadcount > 0) {
            pthread_cond_wait(&threadblock, &threadlock);
        }
    }
    pthread_mutex_unlock(&threadlock);
}

void
installexit()
{
    atexit(exitfunction);
}

#ifdef HAVE_BACKTRACE_FULL
static struct backtrace_state *state;

static int callback(void* data, uintptr_t pc, const char *filename, int lineno, const char *function);
static void errorhandler(void* data, const char *msg, int errno);

static int callback(void* data, uintptr_t pc, const char *filename, int lineno, const char *function) {
    if (filename == NULL && lineno == 0 && function == NULL) {
        alert("\tinlined method\n");
    } else {
        alert("\t%s:%d in %s()\n", filename, lineno, function);
    }
    if (function && !strcmp(function, "main"))
        return 1;
    else
        return 0;
}

static void errorhandler(void* data, const char *msg, int errno) {
    int len = strlen(msg);
    write(2, msg, len);
    write(2, "\n", 1);
}
#endif

static void
handlesignal(int signal, siginfo_t* info, void* data) {
    const char* signalname;
    Dl_info btinfo;
    thread_t thrinfo;
    (void)signal;
    (void)data;
#ifndef HAVE_BACKTRACE_FULL
#ifdef HAVE_BACKTRACE
    void *bt[20];
    int count, i;
#endif
#endif
#ifdef HAVE_LIBUNWIND
    unw_context_t ctx;
    unw_cursor_t cursor;
    char symbol[256];
    unw_word_t offset;
#endif
    switch (info->si_signo) {
        case SIGUSR2:
            signalname = "Interrupted";
            break;
        case SIGABRT:
            sigaction(info->si_signo, &original_abrt_action, NULL);
            signalname = "Aborted";
            break;
        case SIGSEGV:
            sigaction(info->si_signo, &original_segv_action, NULL);
            signalname = "Segmentation fault";
            break;
        case SIGFPE:
            sigaction(info->si_signo, &original_fpe_action, NULL);
            signalname = "Floating point error";
            break;
        case SIGILL:
            sigaction(info->si_signo, &original_ill_action, NULL);
            signalname = "Illegal instruction";
            break;
        case SIGBUS:
            sigaction(info->si_signo, &original_bus_action, NULL);
            signalname = "Bus error";
            break;
        case SIGSYS:
            sigaction(info->si_signo, &original_sys_action, NULL);
            signalname = "System error";
            break;
        default:
            signalname = "Unknown error";
    }
    if (dladdr(info->si_addr, &btinfo) != 0)
        alert("%s in %s", signalname, btinfo.dli_sname);
    else
        alert("%s", signalname);
#ifdef HAVE_BACKTRACE_FULL
    alert(":\n");
    backtrace_full(state, 2, callback, errorhandler, NULL);
#else
#ifdef HAVE_BACKTRACE
    alert(":\n");
    count = backtrace(bt, sizeof (bt) / sizeof (void*));
    for (i = 2; i < count; i++) {
        dladdr(bt[i], &btinfo);
        if (btinfo.dli_sname != NULL) {
            alert("\t%s\n", btinfo.dli_sname);
            if (!strcmp(btinfo.dli_sname, "main"))
                break;
        } else
            alert("\tunknown\n");
    }
#else
#ifdef HAVE_LIBUNWIND
    alert(":\n");
    unw_getcontext(&ctx);
    unw_init_local(&cursor, &ctx);
    if (unw_step(&cursor)) {
        /* skip the first one */
        while (unw_step(&cursor)) {
            unw_get_proc_name(&cursor, symbol, sizeof (symbol) - 1, &offset);
            alert("\t%s\n", symbol);
            if (!strcmp(symbol, "main"))
                break;
        }
    }
#else
    alert("\n");
#endif
#endif
#endif
    uninstallthread(pthread_getspecific(threadlocator));
    if (info->si_signo == SIGUSR2) {
        pthread_mutex_lock(&threadlock);
        if(--threadcount <= 0) {
            pthread_cond_signal(&threadblock);
        }
        pthread_mutex_unlock(&threadlock);
    } else {
        dumpthreads();
    }
}

int
installcrashhandler(char* argv0) {
    sigset_t mask;
    stack_t ss;
    struct sigaction newsigaction;

#ifdef HAVE_BACKTRACE_FULL
    CHECKFAIL((state = backtrace_create_state(argv0, 0, &errorhandler, NULL)) == NULL);
#else
    (void)argv0;
#endif

    ss.ss_sp = malloc(SIGSTKSZ);
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    CHECKFAIL(sigaltstack(&ss, NULL) == -1);

    sigfillset(&mask);
    newsigaction.sa_sigaction = handlesignal;
    newsigaction.sa_flags = SA_SIGINFO | SA_ONSTACK;
    newsigaction.sa_mask = mask;
    CHECKFAIL(sigaction(SIGUSR2, &newsigaction, &original_usr1_action));
    CHECKFAIL(sigaction(SIGABRT, &newsigaction, &original_abrt_action));
    CHECKFAIL(sigaction(SIGSEGV, &newsigaction, &original_segv_action));
    CHECKFAIL(sigaction(SIGFPE, &newsigaction, &original_fpe_action));
    CHECKFAIL(sigaction(SIGILL, &newsigaction, &original_ill_action));
    CHECKFAIL(sigaction(SIGBUS, &newsigaction, &original_bus_action));
    CHECKFAIL(sigaction(SIGSYS, &newsigaction, &original_sys_action));
    return 0;
fail:
    return -1;
}

int
installcoreprevent(void) {
    struct rlimit rlim;
    rlim.rlim_cur = 0;
    rlim.rlim_max = 0;

    CHECKFAIL(setrlimit(RLIMIT_CORE, &rlim));
    return 0;

fail:
    return -1;
}
