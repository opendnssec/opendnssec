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

#ifndef LOGGING_H
#define LOGGING_H

#include "config.h"

struct logger_chain_struct;

struct logger_setup_struct {
    int serial;
    int nchains;
    struct logger_chain_struct* chains;
};
extern struct logger_setup_struct logger_setup;

typedef enum logger_lvl_enum { logger_FATAL, logger_ERROR, logger_WARN, logger_INFO, logger_DEBUG, logger_DIAG } logger_lvl_type;
#define logger_TRACE logger_DIAG
#define logger_ALERT logger_ERROR
#define logger_NOTICE logger_WARN

struct logger_cls_struct {
    const char* name;
    int setupserial;
    logger_lvl_type minlvl;
    struct logger_chain_struct* chain;
};

typedef enum logger_result { logger_DONE, logger_CONT, logger_QUIT } logger_result_type;

typedef struct logger_ctx_struct* logger_ctx_type;
typedef struct logger_cls_struct logger_cls_type;
typedef logger_result_type (*logger_procedure)(const logger_cls_type*, const logger_ctx_type, const logger_lvl_type, const char*, va_list ap);

#define LOGGER_INITIALIZE(N) { N, 0, 0, NULL }

extern logger_ctx_type logger_noctx;
extern logger_ctx_type logger_ctx;
extern logger_cls_type logger_cls;

void logger_initialize(const char* programname);
void logger_resetup(logger_cls_type* cls);
void logger_configurecls(const char* name, logger_lvl_type minlvl, logger_procedure proc);
logger_result_type logger_log_syslog(const logger_cls_type* cls, const logger_ctx_type ctx, const logger_lvl_type lvl, const char* format, va_list ap);
logger_result_type logger_log_stderr(const logger_cls_type* cls, const logger_ctx_type ctx, const logger_lvl_type lvl, const char* format, va_list ap);

logger_ctx_type logger_newcontext(void);
void logger_destroycontext(logger_ctx_type);
void logger_setcontext(logger_ctx_type);
void logger_pushcontext(logger_ctx_type);
void logger_popcontext(void);
void logger_clearcontext(void);
void logger_putcontext(logger_ctx_type, const char* key, const char* value);
const char* logger_getcontext(logger_ctx_type);

int logger_enabled(logger_cls_type* cls, logger_ctx_type ctx, logger_lvl_type lvl);

void
logger_messageinternal(logger_cls_type* cls, logger_ctx_type ctx, logger_lvl_type lvl, const char* fmt,...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 4, 5)))
#endif
;

void
logger_message(logger_cls_type* cls, logger_ctx_type ctx, logger_lvl_type lvl, const char* fmt,...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 4, 5)))
#endif
;

int logger_mark_performance(const char* message);

#define logger_messagex(CLS,CTX,LVL,FMT,...) \
    do { \
        logger_cls_type* logger_cls_var = (CLS); \
        logger_lvl_type logger_lvl_var = (LVL); \
        if(logger_cls_var->setupserial != logger_setup.serial) \
            logger_resetup(logger_cls_var); \
        if(logger_lvl_var <= logger_cls_var->minlvl) \
            logger_messageinternal(logger_cls_var,(CTX),logger_lvl_var,FMT,__VA_ARGS__); \
    } while(0)

#ifndef DEPRECATE

#ifdef HAVE_SYSLOG_H
#include <strings.h> /* strncasecmp() */
#include <syslog.h> /* openlog(), closelog(), syslog() */
#else /* !HAVE_SYSLOG_H */
#define LOG_EMERG   0 /* ods_fatal_exit */
#define LOG_ALERT   1 /* ods_log_alert */
#define LOG_CRIT    2 /* ods_log_crit */
#define LOG_ERR     3 /* ods_log_error */
#define LOG_WARNING 4 /* ods_log_warning */
#define LOG_NOTICE  5 /* ods_log_info */
#define LOG_INFO    6 /* ods_log_verbose */
#define LOG_DEBUG   7 /* ods_log_debug */
#endif /* HAVE_SYSLOG_H */
#define LOG_DEEEBUG 8 /* ods_log_deeebug */

void ods_log_deeebug(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

void ods_log_debug(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

void ods_log_verbose(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

void ods_log_info(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

void ods_log_warning(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

void ods_log_error(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

void ods_log_verror(const char *format, va_list args);

void ods_log_crit(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

void ods_log_alert(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

void ods_fatal_exit(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

#define ods_log_assert(x) \
        do { if(!(x)) \
                ods_fatal_exit("%s:%d: %s: assertion %s failed", \
                __FILE__, __LINE__, __func__, #x); \
        } while(0);

#endif

#endif
