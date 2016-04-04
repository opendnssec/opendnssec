#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#define __USE_GNU
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <dlfcn.h>
#include <execinfo.h>

#include "debug.h"

static struct sigaction oldsigaction_segv;
static struct sigaction oldsigaction_abrt;
static struct sigaction oldsigaction_user;

static void
handlesignal(int signal, siginfo_t* info, void* data)
{
}

int
stacktrace_install(int signal)
{
    sigset_t mask;
    struct sigaction newsigaction;

    sigfillset(&mask);
    newsigaction.sa_sigaction = handlesignal;
    newsigaction.sa_flags = SA_SIGINFO | SA_ONSTACK;
    newsigaction.sa_mask = mask;
    if(signal == 0) {
        if (sigaction(SIGABRT, &newsigaction, &oldsigaction_user))
            fprintf(stderr,"failed to install signal handler for signal %d\n",signal);
    } else {
        if (sigaction(SIGABRT, &newsigaction, &oldsigaction_abrt))
            fprintf(stderr,"failed to install signal handler for ABORT signal\n");
        if (sigaction(SIGSEGV, &newsigaction, &oldsigaction_segv))
            fprintf(stderr,"failed to install signal handler for SIGSEGV signal\n");
    }
}
