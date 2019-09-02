/*
 * Copyright (c) 2018 NLNet Labs.
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

#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <pthread.h>
#include "logging.h"

#undef logger_message

struct logger_chain_struct {
    const char* name;
    int minlvl;
    logger_procedure logger;

};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
struct logger_setup_struct logger_setup = { 0, 0, NULL };
static logger_cls_type logger = LOGGER_INITIALIZE(__FILE__);

logger_ctx_type logger_noctx = NULL;
logger_ctx_type logger_ctx;
logger_cls_type logger_cls = LOGGER_INITIALIZE("");
logger_cls_type logger_cls_performance = LOGGER_INITIALIZE("performance");

int
logger_enabled(logger_cls_type* cls, logger_ctx_type ctx, logger_lvl_type lvl)
{
    (void)ctx;
    if(cls->setupserial != logger_setup.serial)
        logger_resetup(cls);
    if(lvl <= cls->minlvl)
        return 1;
    else
        return 0;
}

void
logger_message(logger_cls_type* cls, logger_ctx_type ctx, logger_lvl_type lvl, const char* fmt, ...)
{
    va_list ap;
    if(!logger_enabled(cls, ctx, lvl))
        return;
    va_start(ap, fmt);
    if(cls && cls->chain && cls->chain->logger)
        cls->chain->logger(cls,ctx,lvl,fmt,ap);
    va_end(ap);
}

void
logger_vmessage(logger_cls_type* cls, logger_ctx_type ctx, logger_lvl_type lvl, const char* fmt, va_list ap)
{
    if(!logger_enabled(cls, ctx, lvl))
        return;
    if(cls && cls->chain && cls->chain->logger)
        cls->chain->logger(cls,ctx,lvl,fmt,ap);
}

void
logger_messageinternal(logger_cls_type* cls, logger_ctx_type ctx, logger_lvl_type lvl, const char* fmt, ...)
{
    va_list ap;
    va_start(ap,fmt);
    if(cls && cls->chain && cls->chain->logger)
        cls->chain->logger(cls,ctx,lvl,fmt,ap);
    va_end(ap);
}

static pthread_key_t currentctx;

struct logger_ctx_struct {
    struct logger_ctx_struct* prev;
    const char* label;
};

const char*
logger_getcontext(logger_ctx_type ctx)
{
    if(ctx == logger_ctx) {
        ctx = pthread_getspecific(currentctx);
    }
    if(ctx != logger_noctx) {
        return ctx->label;
    } else {
        return NULL;
    }
}

logger_result_type
logger_log_syslog(const logger_cls_type* cls, const logger_ctx_type ctx, const logger_lvl_type lvl, const char* format, va_list ap)
{
    int priority;
    (void)cls;
    (void)ctx;
    switch(lvl) {
        case logger_FATAL:  priority = LOG_ALERT;    break;
        case logger_ERROR:  priority = LOG_ERR;      break;
        case logger_WARN:   priority = LOG_WARNING;  break;
        case logger_INFO:   priority = LOG_NOTICE;   break;
        case logger_DEBUG:  priority = LOG_INFO;     break;
        case logger_DIAG:   priority = LOG_DEBUG;    break;
        default:
            priority = LOG_ERR;
    }
    vsyslog(priority, format, ap);
    return logger_CONT;
}

static logger_result_type
logger_stdhelper(FILE* fp, const char* location, const char* context, const logger_lvl_type lvl, const char* format, va_list ap)
{
    const char* priority;
    char* message;
    switch(lvl) {
        case logger_FATAL:  priority = "fatal error: ";  break;
        case logger_ERROR:  priority = "error: ";        break;
        case logger_WARN:   priority = "warning: ";      break;
        case logger_INFO:   priority = "";               break;
        case logger_DEBUG:  priority = "";               break;
        case logger_DIAG:   priority = "";               break;
        default:
            priority = "unknown problem: ";
    }
    vasprintf(&message, format, ap);
    if(message[strlen(message)-1] == '\n') {
        message[strlen(message)-1] = '\0';
    }
    fprintf(fp,"%s%s%s%s%s%s%s%s\n",priority,(location?"[":""),(location?location:""),(location?"] ":""),message,(context?" (":""), (context?context:""), (context?")":""));
    free(message);
    return logger_CONT;
}

logger_result_type
logger_log_stderr(const logger_cls_type* cls, const logger_ctx_type ctx, const logger_lvl_type lvl, const char* format, va_list ap)
{
    const char* location;
    const char* context;
    context = logger_getcontext(ctx);
    location = cls->name;
    return logger_stdhelper(stderr,location,context,lvl,format,ap);
}

logger_result_type
logger_log_stdout(const logger_cls_type* cls, const logger_ctx_type ctx, const logger_lvl_type lvl, const char* format, va_list ap)
{
    const char* location;
    const char* context;
    context = logger_getcontext(ctx);
    location = cls->name;
    return logger_stdhelper(stdout,location,context,lvl,format,ap);
}

void
logger_log_syslog_open(const char* argv0)
{
    openlog(argv0, LOG_NDELAY, LOG_DAEMON);
}

void
logger_log_syslog_close(void)
{
    closelog();
}

static void
destroyctx(void* arg)
{
    logger_ctx_type ctx = (logger_ctx_type)arg;
    logger_destroycontext(ctx);
}

void
logger_initialize(const char* programname)
{
    logger_setup.serial += 1;
    logger_setup.nchains = 1;
    logger_setup.chains = malloc(sizeof(struct logger_chain_struct) * logger_setup.nchains);
    logger_setup.chains[0].name = "";
    logger_setup.chains[0].minlvl = logger_ERROR;
    logger_setup.chains[0].logger = logger_log_stderr;
    logger_log_syslog_open(programname);
    //logger_setup.chains[0].logger = logger_log_syslog;
    logger_message(&logger, logger_noctx, logger_INFO, "%s started",programname);
    pthread_key_create(&currentctx, destroyctx);
    logger_ctx = logger_newcontext();
}

void
logger_finalize(void)
{
    pthread_key_delete(currentctx);
}

void
logger_resetup(logger_cls_type* cls)
{
    pthread_mutex_lock(&mutex);
    if(cls->setupserial == 1) {
        logger_initialize(NULL);
    }
    cls->setupserial = logger_setup.serial;
    cls->minlvl = logger_setup.chains[0].minlvl;
    cls->chain = &logger_setup.chains[0];
    for (int i=1; i<logger_setup.nchains; i++) {
        if (logger_setup.chains[i].name == NULL || !strcmp(cls->name, logger_setup.chains[i].name)) {
            cls->minlvl = logger_setup.chains[i].minlvl;
            cls->chain = &logger_setup.chains[i];
        }
    }
    pthread_mutex_unlock(&mutex);
}

void
logger_configurecls(const char* name, logger_lvl_type minlvl, logger_procedure proc)
{
    pthread_mutex_lock(&mutex);
    logger_setup.nchains += 1;
    logger_setup.chains = realloc(logger_setup.chains, sizeof(struct logger_chain_struct) * logger_setup.nchains);
    logger_setup.chains[logger_setup.nchains-1].name = strdup(name);
    logger_setup.chains[logger_setup.nchains-1].minlvl = minlvl;
    logger_setup.chains[logger_setup.nchains-1].logger = proc;
    logger_setup.serial += 1;
    pthread_mutex_unlock(&mutex);
}


logger_ctx_type
logger_newcontext(void)
{
    logger_ctx_type ctx;
    ctx = malloc(sizeof(struct logger_ctx_struct));
    ctx->prev = NULL;
    ctx->label = NULL;
    return ctx;
}

void
logger_destroycontext(logger_ctx_type ctx)
{
    free((void*)ctx->label);
    free((void*)ctx);
}

void
logger_setcontext(logger_ctx_type ctx)
{
    pthread_setspecific(currentctx, ctx);
}

void
logger_pushcontext(logger_ctx_type ctx)
{
    logger_ctx_type prev;
    if(ctx == logger_noctx) {
        ctx = logger_newcontext();
    } else if (ctx == logger_ctx) {
        ctx = logger_newcontext();
        ctx->label = (ctx->label ? strdup(ctx->label) : NULL);
    }
    prev = pthread_getspecific(currentctx);
    ctx->prev = prev;
    pthread_setspecific(currentctx, ctx);
}

void
logger_popcontext(void)
{
    logger_ctx_type prev, ctx;
    ctx = pthread_getspecific(currentctx);
    prev = ctx->prev;
    logger_destroycontext(ctx);
    pthread_setspecific(currentctx, prev);
}

void
logger_clearcontext(void)
{
    logger_ctx_type prev, ctx;
    for(ctx=pthread_getspecific(currentctx); ctx; ctx=prev) {
        prev = ctx->prev;
        logger_destroycontext(ctx);
    }
    pthread_setspecific(currentctx, NULL);
}

void
logger_putcontext(logger_ctx_type ctx, const char* key, const char* value)
{
    char* newdesc;
    if(ctx->label) {
        if(key) {
            asprintf(&newdesc,"%s,%s=%s",ctx->label,key,value);
        } else {
            asprintf(&newdesc,"%s,%s",ctx->label,value);
        }
    } else {
        if(key) {
            asprintf(&newdesc,"%s=%s",key,value);
        } else {
            asprintf(&newdesc,"%s",value);
        }
    }
    free((void*)ctx->label);
    ctx->label = newdesc;
}


static int markcount = 0;
static int marktime;
static intptr_t markbrk;

int
logger_mark_performance(const char* message)
{
    time_t t;
    intptr_t b;
    if(markcount == 0) {
        t = marktime = time(NULL);
        b = markbrk = (intptr_t) sbrk(0);
    } else {
        t = time(NULL);
        b = (intptr_t) sbrk(0);
    }
fprintf(stderr, "MARK#%02d %2ld %4ld %s\n", markcount, (long)(t-marktime), (long)((b-markbrk+1048576/2)/1048576), message);
    logger_message(&logger_cls_performance, logger_ctx, logger_INFO, "MARK#%02d %2ld %4ld %s\n", markcount, (long)(t-marktime), (long)((b-markbrk+1048576/2)/1048576), message);
    ++markcount;
    return 0;
}
