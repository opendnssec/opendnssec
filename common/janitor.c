/*
 * Copyright (c) 2016-2018 NLNet Labs.
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
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
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

#include "janitor.h"

static struct sigaction original_quit_action;
static struct sigaction original_abrt_action;
static struct sigaction original_segv_action;
static struct sigaction original_fpe_action;
static struct sigaction original_ill_action;
static struct sigaction original_bus_action;
static struct sigaction original_sys_action;

static janitor_alertfn_t alert;
static janitor_alertfn_t report;

struct janitor_threadclass_struct {
    char* name;
    int detached;
    int autorun;
    int blocksignals;
    int hasattr;
    pthread_attr_t attr;
};

int
janitor_threadclass_create(janitor_threadclass_t* threadclass, const char* name)
{
    *threadclass = malloc(sizeof(struct janitor_threadclass_struct));
    (*threadclass)->name = strdup(name);
    (*threadclass)->detached = 0;
    (*threadclass)->autorun = 0;
    (*threadclass)->blocksignals = 0;
    (*threadclass)->hasattr = 0;
    return 0;
}

char*
janitor_threadclass_name(janitor_threadclass_t threadclass)
{
    return threadclass->name;
}

void
janitor_threadclass_destroy(janitor_threadclass_t threadclass)
{
    if (threadclass->hasattr) {
        pthread_attr_destroy(&threadclass->attr);
    }
    free(threadclass->name);
    free(threadclass);
}

void
janitor_threadclass_setdetached(janitor_threadclass_t threadclass)
{
    threadclass->detached = 1;
    if (!threadclass->hasattr) {
        pthread_attr_init(&threadclass->attr);
    }
    pthread_attr_setdetachstate(&threadclass->attr, PTHREAD_CREATE_DETACHED);
}

void
janitor_threadclass_setautorun(janitor_threadclass_t threadclass)
{
    threadclass->autorun = 1;
}

void
janitor_threadclass_setblockedsignals(janitor_threadclass_t threadclass)
{
    threadclass->blocksignals = 1;
}

void
janitor_threadclass_setminstacksize(janitor_threadclass_t threadclass, size_t minstacksize)
{
    size_t stacksize;
    if (!threadclass->hasattr) {
        pthread_attr_init(&threadclass->attr);
    }
    pthread_attr_getstacksize(&threadclass->attr, &stacksize);
    if (stacksize < minstacksize) {
        pthread_attr_setstacksize(&threadclass->attr, minstacksize);
        threadclass->hasattr = 1;
    }
}

static void fail(const char* file, int line, const char* func, const char* expr, int stat);
#define CHECKFAIL(EX) do { int CHECKFAIL; if((CHECKFAIL = (EX))) { fail(__FILE__,__LINE__,__func__,#EX,CHECKFAIL); goto fail; } } while(0)

static void
fail(const char* file, int line, const char* func, const char* expr, int stat)
{
    report("Failure %d in %s at %s:%d of %s\n", stat, func, file, line, expr);
}

void
janitor_initialize(janitor_alertfn_t alertfn, janitor_alertfn_t reportfn)
{
    report = reportfn;
    alert = alertfn;
}

struct janitor_thread_struct {
    struct janitor_thread_struct* next;
    struct janitor_thread_struct* prev;
    pthread_t thread;
    janitor_runfn_t runfunc;
    void* rundata;
    int isstarted;
    int blocksignals;
    pthread_barrier_t startbarrier;
    janitor_threadclass_t threadclass;
};

static pthread_mutex_t threadlock = PTHREAD_MUTEX_INITIALIZER;
static struct janitor_thread_struct *threadlist = NULL; /* running threads */
static struct janitor_thread_struct *finishedthreadlist = NULL; /* threads waiting to be joined */
static pthread_once_t threadlocatorinitializeonce = PTHREAD_ONCE_INIT;
static pthread_key_t threadlocator;
static pthread_cond_t threadblock = PTHREAD_COND_INITIALIZER;

static void
threadlocatorinitialize(void)
{
    pthread_key_create(&threadlocator, NULL);
}

static void
janitor_thread_unregister(janitor_thread_t info)
{
    int err, errcount;
    if (info == NULL)
        return;
    CHECKFAIL(pthread_mutex_lock(&threadlock));
    if (threadlist != NULL) {
        if (threadlist == info) {
            if (info->next == info) {
                threadlist = NULL;
            } else {
                threadlist = info->next;
            }
        }
        info->next->prev = info->prev;
        info->prev->next = info->next;
        info->next = info->prev = NULL;
        /* The implementation on FreeBSD10 of pthreads is pretty brain dead.
         * If two threads enter a barrier with count 2, then the barrier
         * is satisfied and thus not really being waited upon.  If now one
         * of the threads tries to destroy the thread, while the other thread
         * did not have its turn yet on the CPU, then still the destroy call
         * will return EBUSY.  Although valid, this is really a brain dead
         * implementation causing pain to application developers to do the
         * following every time:
         */
        errcount = 0;
        do {
            err = pthread_barrier_destroy(&info->startbarrier);
            if (err == EBUSY) {
                ++errcount;
                sleep(1);
            }
        } while(err == EBUSY && errcount <= 3);
        CHECKFAIL(pthread_cond_signal(&threadblock));
    }
    CHECKFAIL(pthread_mutex_unlock(&threadlock));
fail:
    ;
}

static void
janitor_thread_dispose(janitor_thread_t info)
{
    if (info == NULL)
        return;
    if (!info->threadclass || !info->threadclass->detached) {
        pthread_mutex_lock(&threadlock);
        if (finishedthreadlist != NULL) {
            if (finishedthreadlist == info) {
                if (info->next == info) {
                    finishedthreadlist = NULL;
                } else {
                    finishedthreadlist = info->next;
                }
            }
            if(info->next && info->next->prev == info)
                info->next->prev = info->prev;
            if(info->prev && info->prev->next == info)
                info->prev->next = info->next;
            info->next = info->prev = NULL;
        }
        pthread_mutex_unlock(&threadlock);
    }
    free(info);
}

static void
janitor_thread_register(janitor_thread_t info)
{
    pthread_mutex_lock(&threadlock);
    pthread_once(&threadlocatorinitializeonce, threadlocatorinitialize);
    if (threadlist != NULL) {
        info->next = threadlist;
        info->prev = threadlist->prev;
        threadlist->prev->next = info;
        threadlist->prev = info;
    } else {
        info->next = info->prev = info;
    }
    threadlist = info;
    pthread_mutex_unlock(&threadlock);
}

static void
janitor_thread_finished(janitor_thread_t info)
{
    if (!info->threadclass->detached) {
        pthread_mutex_lock(&threadlock);
        if (finishedthreadlist != NULL) {
            info->next = finishedthreadlist;
            info->prev = finishedthreadlist->prev;
            finishedthreadlist->prev->next = info;
            finishedthreadlist->prev = info;
        } else {
            info->next = info->prev = info;
        }
        finishedthreadlist = info;
        pthread_mutex_unlock(&threadlock);
    } else {
        pthread_detach(pthread_self());
        janitor_thread_dispose(info);
    }
}

static void*
runthread(void* data)
{
    int err;
    sigset_t sigset;
    struct janitor_thread_struct* info;
    stack_t ss;
    stack_t prevss;
    info = (struct janitor_thread_struct*) data;
    pthread_setspecific(threadlocator, info);
    ss.ss_sp = malloc(SIGSTKSZ);
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    sigaltstack(&ss, &prevss);
    pthread_barrier_wait(&info->startbarrier);
    if (info->blocksignals) {
        sigfillset(&sigset);
        sigdelset(&sigset, SIGQUIT);
        sigdelset(&sigset, SIGABRT);
        sigdelset(&sigset, SIGSEGV);
        sigdelset(&sigset, SIGFPE);
        sigdelset(&sigset, SIGILL);
        sigdelset(&sigset, SIGBUS);
        sigdelset(&sigset, SIGSYS);
        if ((err = pthread_sigmask(SIG_SETMASK, &sigset, NULL)))
            report("pthread_sigmask: %s (%d)", strerror(err), err);
    }
    info->runfunc(info->rundata);
    sigaltstack(&prevss, NULL);
    free(ss.ss_sp); /* libxml has/had problems when freeing this as it tries to access it */
    janitor_thread_unregister(info);
    janitor_thread_finished(info);
    return NULL;
}

int
janitor_thread_create(janitor_thread_t* thread, janitor_threadclass_t threadclass, janitor_runfn_t func, void*data)
{
    struct janitor_thread_struct* info;
    info = malloc(sizeof (struct janitor_thread_struct));
    info->runfunc = func;
    info->rundata = data;
    info->blocksignals = 0;
    info->isstarted = 0;
    info->threadclass = threadclass;
    CHECKFAIL(pthread_barrier_init(&info->startbarrier, NULL, 2));
    CHECKFAIL(pthread_create(&info->thread, ((threadclass && threadclass->hasattr) ? &threadclass->attr : NULL), runthread, info));
    janitor_thread_register(info);
    *thread = info;
    if(threadclass && threadclass->autorun) {
        janitor_thread_start(info);
    }
    return 0;
fail:
    return 1;
}

void janitor_thread_signal(janitor_thread_t thread)
{
    pthread_kill(thread->thread, SIGHUP);
}

void
janitor_thread_start(janitor_thread_t thread)
{
    int isstarted;

    pthread_mutex_lock(&threadlock);
    isstarted = thread->isstarted;
    thread->isstarted = 1;
    pthread_mutex_unlock(&threadlock);

    if (!isstarted) {
        pthread_barrier_wait(&thread->startbarrier);
    }
}

int
janitor_thread_join(janitor_thread_t thread)
{
    int status;
    status = pthread_join(thread->thread, NULL);
    janitor_thread_dispose(thread);
    return status;
}

int
janitor_thread_tryjoinall(janitor_threadclass_t threadclass)
{
    struct janitor_thread_struct* thread;
    struct janitor_thread_struct* foundthread;

    do {
        foundthread = NULL;
        pthread_mutex_lock(&threadlock);
        thread = finishedthreadlist;
        if (thread) {
            do {
                if (thread->threadclass == threadclass) {
                    foundthread = thread;
                    break;
                }
                thread = thread->next;
            } while (thread != finishedthreadlist);
        }
        pthread_mutex_unlock(&threadlock);
        if (foundthread) {
            janitor_thread_join(foundthread);
        }
    } while(foundthread);

    pthread_mutex_lock(&threadlock);
    foundthread = NULL;
    thread = finishedthreadlist;
    if (thread) {
        do {
            if (thread->threadclass == threadclass) {
                foundthread = thread;
                break;
            }
            thread = thread->next;
        } while (thread != finishedthreadlist);
    }
    thread = threadlist;
    if (!foundthread && thread) {
        do {
            if (thread->threadclass == threadclass) {
                foundthread = thread;
                break;
            }
            thread = thread->next;
        } while (thread != threadlist);
    }
    pthread_mutex_unlock(&threadlock);
    if (foundthread) {
        return 1;
    } else {
        return 0;
    }
}

void
janitor_thread_joinall(janitor_threadclass_t threadclass)
{
    int moreleft;
    do {
        moreleft = janitor_thread_tryjoinall(threadclass);
    } while(moreleft);
}

static void
dumpthreads(void)
{
    struct janitor_thread_struct* info;
    struct janitor_thread_struct* list;
    pthread_mutex_lock(&threadlock);
    info = pthread_getspecific(threadlocator);
    list = threadlist;
    if (list) {
        do {
            if (list != info) {
                pthread_kill(list->thread, SIGQUIT);
                pthread_cond_wait(&threadblock, &threadlock);
            }
            list = list->next;
        } while (list != threadlist);
    }
    pthread_mutex_unlock(&threadlock);
}

#ifdef HAVE_BACKTRACE_FULL
static struct backtrace_state *state  = NULL;
static struct backtrace_state *frames = NULL;
static pthread_mutex_t frameslock = PTHREAD_MUTEX_INITIALIZER;

static int
callback(void* data, uintptr_t pc, const char *filename, int lineno, const char *function)
{
    if (filename == NULL && lineno == 0 && function == NULL) {
        alert("  inlined method\n");
    } else {
        alert("  %s:%d in %s()\n", filename, lineno, function);
    }
    if (function && !strcmp(function, "main"))
        return 1;
    else
        return 0;
}

static void
errorhandler(void* data, const char *msg, int xerrno)
{
    int len = strlen(msg);
    (void) (write(2, msg, len));
    (void) (write(2, "\n", 1));
}
#endif

static void
outputbacktrace(int skips, void *workaround)
{
#ifdef HAVE_BACKTRACE_FULL
    struct backtrace_state *state = (struct backtrace_state*) workaround;
#else
#ifdef HAVE_BACKTRACE
    Dl_info btinfo;
    void *bt[20];
    int count, i;
#else
#ifdef HAVE_LIBUNWIND
    unw_context_t ctx;
    unw_cursor_t cursor;
    char symbol[256];
    unw_word_t offset;
#endif
#endif
#endif
#ifdef HAVE_BACKTRACE_FULL
    backtrace_full(state, skips, (backtrace_full_callback) callback, (backtrace_error_callback) errorhandler, NULL);
#else
#ifdef HAVE_BACKTRACE
    count = backtrace(bt, sizeof (bt) / sizeof (void*));
    for (i = skips; i < count; i++) {
        dladdr(bt[i], &btinfo);
        if (btinfo.dli_sname != NULL) {
            alert("  %s\n", btinfo.dli_sname);
            if (!strcmp(btinfo.dli_sname, "main"))
                break;
        } else
            alert("  unknown\n");
    }
#else
#ifdef HAVE_LIBUNWIND
    unw_getcontext(&ctx);
    unw_init_local(&cursor, &ctx);
    if (unw_step(&cursor)) {
        /* skip the first one */
        while (unw_step(&cursor)) {
            unw_get_proc_name(&cursor, symbol, sizeof (symbol) - (skips-1), &offset);
            alert("  %s\n", symbol);
            if (!strcmp(symbol, "main"))
                break;
        }
    }
#endif
#endif
#endif
}

static void
handlesignal(int signal, siginfo_t* info, void* data)
{
    const char* signalname;
    Dl_info btinfo;
    janitor_thread_t thrinfo;
    (void) signal;
    (void) data;
#ifndef HAVE_BACKTRACE_FULL
#ifdef HAVE_BACKTRACE
    void *bt[20];
    int count, i;
#else
#ifdef HAVE_LIBUNWIND
    unw_context_t ctx;
    unw_cursor_t cursor;
    char symbol[256];
    unw_word_t offset;
#endif
#endif
#endif
    switch (info->si_signo) {
        case SIGQUIT:
            signalname = "Threaddump";
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
#else
#ifdef HAVE_BACKTRACE
    alert(":\n");
#else
#ifdef HAVE_LIBUNWIND
    alert(":\n");
#else
    alert("\n");
#endif
#endif
#endif
#ifdef HAVE_BACKTRACE_FULL
    outputbacktrace(2, state);
#else
    outputbacktrace(2, NULL);
#endif
    if (info->si_signo == SIGQUIT) {
        pthread_mutex_lock(&threadlock);
        pthread_cond_signal(&threadblock);
        pthread_mutex_unlock(&threadlock);
    } else {
        dumpthreads();
        raise(info->si_signo);
    }
}

void
janitor_backtrace(void)
{
#ifdef HAVE_BACKTRACE_FULL
    if(frames == NULL) {
        frames = backtrace_create_state(NULL, 0, (backtrace_error_callback) errorhandler, NULL);
    }
    pthread_mutex_lock(&frameslock);
    outputbacktrace(1, frames);
    pthread_mutex_unlock(&frameslock);
#else
    outputbacktrace(1, NULL);
#endif
}

static int
callbackstring(void* data, uintptr_t pc, const char *filename, int lineno, const char *function)
{
    int siz, len;
    char** ptr = data;
    if (filename != NULL || lineno != 0 || function == NULL) {
        siz = snprintf(NULL, 0, "  %s:%d in %s()\n", filename, lineno, function);
        if (*ptr != NULL) {
            len = strlen(*ptr);
            siz += len + 1;
            *ptr = realloc(*ptr, siz);
        } else {
            len = 0;
            siz += 1;
            *ptr = malloc(siz);
        }
        snprintf(&(*ptr)[len], siz-len, "  %s:%d in %s()\n", filename, lineno, function);
    }
    if (function && !strcmp(function, "main"))
        return 1;
    else
        return 0;
}

char*
janitor_backtrace_string(void)
{
    char* string = NULL;
#ifdef HAVE_BACKTRACE
    Dl_info btinfo;
    void *bt[20];
    const char* symb;
    int count, i, siz, len;
#endif

#ifdef HAVE_BACKTRACE_FULL
    if(frames == NULL) {
        frames = backtrace_create_state(NULL, 0, (backtrace_error_callback) errorhandler, NULL);
    }
    pthread_mutex_lock(&frameslock);
    backtrace_full(frames, 1, (backtrace_full_callback) callbackstring, (backtrace_error_callback) errorhandler, &string);
    pthread_mutex_unlock(&frameslock);
#else
#ifdef HAVE_BACKTRACE
    count = backtrace(bt, sizeof (bt) / sizeof (void*));
    for (i = 1; i < count; i++) {
        dladdr(bt[i], &btinfo);
        if (btinfo.dli_sname != NULL) {
            symb = btinfo.dli_sname;
            if (!strcmp(btinfo.dli_sname, "main"))
                break;
        } else
            symb = "unknown";
        siz = 2 + strlen(symb) + 1;
        if (string != NULL) {
            len = strlen(string);
            siz += len + 1;
            string = realloc(string, siz);
        } else {
            len = 0;
            siz += 1;
            string = malloc(siz);
        }
        snprintf(&(string[len]), siz-len, "  %s\n", symb);
    }
#endif
#endif
    return string;
}

void
janitor_backtrace_all(void)
{
    dumpthreads();
}

int
janitor_trapsignals(char* argv0)
{
    sigset_t mask;
    stack_t ss;
    struct sigaction newsigaction;
    static struct backtrace_state *frames;

#ifdef HAVE_BACKTRACE_FULL
    CHECKFAIL((state  = backtrace_create_state(argv0, 0, (backtrace_error_callback)errorhandler, NULL)) == NULL);
    CHECKFAIL((frames = backtrace_create_state(argv0, 0, (backtrace_error_callback)errorhandler, NULL)) == NULL);
#else
    (void) argv0;
#endif

    /*ss.ss_sp = malloc(SIGSTKSZ);
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    CHECKFAIL(sigaltstack(&ss, NULL) == -1);*/

    sigfillset(&mask);
    sigdelset(&mask, SIGQUIT);
    newsigaction.sa_sigaction = handlesignal;
    newsigaction.sa_flags = SA_SIGINFO | SA_ONSTACK;
    newsigaction.sa_mask = mask;
    CHECKFAIL(sigaction(SIGQUIT, &newsigaction, &original_quit_action));
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
janitor_disablecoredump(void)
{
    struct rlimit rlim;
    rlim.rlim_cur = 0;
    rlim.rlim_max = 0;

    CHECKFAIL(setrlimit(RLIMIT_CORE, &rlim));
    return 0;
fail:
    return -1;
}

struct janitor_pthread_barrier_struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    unsigned int waiting;
    unsigned int count;
};

int
janitor_pthread_barrier_init(pthread_barrier_t* barrier, const pthread_barrierattr_t* attr, unsigned int count)
{
    struct janitor_pthread_barrier_struct* b;
    b = malloc(sizeof(struct janitor_pthread_barrier_struct));
    if(count == 0 || attr != NULL) {
        errno = EINVAL;
        return -1;
    }
    if(pthread_mutex_init(&b->mutex, 0) < 0) {
        free(b);
        return -1;
    }
    if(pthread_cond_init(&b->cond, 0) < 0) {
        pthread_mutex_destroy(&b->mutex);
        free(b);
        return -1;
    }
    b->count = count;
    b->waiting = 0;
    *(void**)barrier = b;
    return 0;
}

int
janitor_pthread_barrier_destroy(pthread_barrier_t* barrier)
{
    struct janitor_pthread_barrier_struct* b = *(void**)barrier;
    pthread_mutex_lock(&b->mutex);
    if(b->count > 0) {
        pthread_mutex_unlock(&b->mutex);
        errno = EBUSY;
        return -1;
    }
    *(void**)barrier = NULL;
    pthread_mutex_unlock(&b->mutex);
    pthread_cond_destroy(&b->cond);
    pthread_mutex_destroy(&b->mutex);
    free(b);
    return 0;
}

int
janitor_pthread_barrier_wait(pthread_barrier_t* barrier)
{
    struct janitor_pthread_barrier_struct* b = *(void**)barrier;
    pthread_mutex_lock(&b->mutex);
    b->waiting += 1;
    if(b->waiting == b->count) {
        b->count = 0;
        pthread_cond_broadcast(&b->cond);
        pthread_mutex_unlock(&b->mutex);
        return PTHREAD_BARRIER_SERIAL_THREAD;
    } else {
        pthread_cond_wait(&b->cond, &b->mutex);
        pthread_mutex_unlock(&b->mutex);
        return 0;
    }
}
