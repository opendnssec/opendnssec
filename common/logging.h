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

#define LOGGER_INITIALIZE(N) { N, 0, 0, NULL }

extern logger_ctx_type logger_noctx;
extern logger_ctx_type logger_ctx;
extern logger_cls_type logger_cls;

void logger_initialize(const char* programname);
void logger_resetup(logger_cls_type* cls);

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

#define logger_message(CLS,TXT,LVL,FMT,...) \
    do { \
        logger_cls_type* logger_cls_var = (CLS); \
        logger_lvl_type logger_lvl_var = (VAR); \
        if(logger_cls_var->setupserial != logger_setup.serial) \
            logger_resetup(logger_cls_var); \
        if(logger_lvl_var <= logger_cls_var->minlvl) \
            logger_messageinternal(logger_cls_var,(CTX),logger_lvl_var,__VA_ARGS__); \
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
