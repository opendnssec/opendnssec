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

static void alertinteger(long value);
void alert(char *format, ...);

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

void alert(char *format, ...) {
    va_list args;
    va_start(args, format);
    int startidx, currentidx, len;
    char* stringarg;
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
}
#endif

static void
handlesignal(int signal, siginfo_t* info, void* data) {
    char* signalname;
    Dl_info btinfo;
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
        alert("%s in %s\n", signalname, btinfo.dli_sname);
    else
        alert("%s\n", signalname);
#ifdef HAVE_BACKTRACE_FULL
    backtrace_full(state, 2, callback, errorhandler, NULL);
#else
#ifdef HAVE_BACKTRACE
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
#endif
#endif
#endif
}

int
installcrashhandler(char* argv0) {
    sigset_t mask;
    stack_t ss;
    struct sigaction newsigaction;

#ifdef HAVE_BACKTRACE_FULL
    if ((state = backstrace_create_state(argv0, 0, &errorhandler, NULL)) == NULL)
        printf("bad boy\n");
#else
    (void)argv0;
#endif

    ss.ss_sp = malloc(SIGSTKSZ);
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) == -1)
        write(2, "BAD\n", 4);

    sigfillset(&mask);
    newsigaction.sa_sigaction = handlesignal;
    newsigaction.sa_flags = SA_SIGINFO | SA_ONSTACK;
    newsigaction.sa_mask = mask;
    if (sigaction(SIGABRT, &newsigaction, &original_abrt_action))
        write(2, "1\n", 2);
    if (sigaction(SIGSEGV, &newsigaction, &original_segv_action))
        write(2, "2\n", 2);
    if (sigaction(SIGFPE, &newsigaction, &original_fpe_action))
        write(2, "2\n", 2);
    if (sigaction(SIGILL, &newsigaction, &original_ill_action))
        write(2, "2\n", 2);
    if (sigaction(SIGBUS, &newsigaction, &original_bus_action))
        write(2, "2\n", 2);
    if (sigaction(SIGSYS, &newsigaction, &original_sys_action))
        write(2, "2\n", 2);
    return 0;
}

int
installcoreprevent(void) {
    struct rlimit rlim;
    rlim.rlim_cur = 0;
    rlim.rlim_max = 0;

    if (setrlimit(RLIMIT_CORE, &rlim))
        write(2, "3\n", 3);

    return 0;
}
