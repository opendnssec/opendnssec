/*
 * Copyright (c) 2009-2018 NLnet Labs.
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

/**
 * Logging.
 *
 */

#include "config.h"
#include "duration.h"
#include "file.h"
#include "log.h"
#include "util.h"

#ifdef HAVE_SYSLOG_H
static int logging_to_syslog = 0;
#endif /* !HAVE_SYSLOG_H */

#include <stdarg.h> /* va_start(), va_end()  */
#include <stdio.h> /* fflush, fprintf(), vsnprintf() */
#include <stdlib.h> /* exit() */
#include <string.h> /* strlen() */
#include <pthread.h>

#define LOG_DEEEBUG 8 /* ods_log_deeebug */

static FILE* logfile = NULL;
static int log_level = LOG_CRIT;

#define CTIME_LENGTH 26

/**
 * Use _r() functions on platforms that have. They are thread safe versions of
 * the normal syslog functions. Platforms without _r() usually have thread safe
 * normal functions.
 */
#if defined(HAVE_SYSLOG_R) && defined(HAVE_OPENLOG_R) && defined(HAVE_CLOSELOG_R)
struct syslog_data sdata = SYSLOG_DATA_INIT;
#else
#undef HAVE_SYSLOG_R
#undef HAVE_OPENLOG_R
#undef HAVE_CLOSELOG_R
#endif

/* TODO:
   - prepend ods_ in common library ?
   - log_init should have program_name variable
   - wrap special case logging onto generic one
   - check if xml-specific logging functions are still neeeded (enforcer)
   -
*/

static const char* log_str = "log";
static char* log_ident = NULL;

/**
 * Initialize logging.
 */
void
ods_log_init(const char *programname, int use_syslog, const char *targetname, int verbosity)
{
#ifdef HAVE_SYSLOG_H
    int facility;
    int error = 0;
#endif /* HAVE_SYSLOG_H */
    if(logfile && logfile != stderr && logfile != stdout) {
            ods_fclose(logfile);
    }
    if(log_ident) {
        free(log_ident);
        log_ident = NULL;
    }
    log_level = verbosity + 2;

#ifdef HAVE_SYSLOG_H
    if(logging_to_syslog) {
#ifdef HAVE_CLOSELOG_R
    	closelog_r(&sdata);
#else
        closelog();
#endif
        logging_to_syslog = 0;
    }
    if(use_syslog) {
       facility = ods_log_get_facility(targetname, &error);
#ifdef HAVE_OPENLOG_R
       openlog_r(programname, LOG_NDELAY, facility, &sdata);
#else
       openlog(programname, LOG_NDELAY, facility);
#endif
       logging_to_syslog = 1;
       if (error == 1) {
        ods_log_warning("[%s] syslog facility %s not supported, logging to "
                   "log_daemon", log_str, targetname);
       }
       ods_log_verbose("[%s] switching log to syslog verbosity %i (log level %i)",
          log_str, verbosity, verbosity+2);
       return;
    }
#endif /* HAVE_SYSLOG_H */

    log_ident = strdup(programname);
    if(targetname && targetname[0]) {
        logfile = ods_fopen(targetname, NULL, "a");
        if (logfile) {
            ods_log_debug("[%s] new logfile %s", log_str, targetname);
            return;
        }
        logfile = stderr;
        ods_log_warning("[%s] cannot open %s for appending, logging to "
            "stderr", log_str, targetname);
    } else {
        logfile = stderr;
        targetname = "stderr";
    }
    ods_log_verbose("[%s] switching log to %s verbosity %i (log level %i)",
          log_str, targetname, verbosity, verbosity+2);

}

int
ods_log_verbosity(void)
{
	return log_level-2;
}

void
ods_log_setverbosity(int verbosity)
{
    log_level = verbosity + 2;
}

/**
 * Close logging.
 *
 */
void
ods_log_close(void)
{
    ods_log_debug("[%s] close log", log_str);
    ods_log_init("", 0, NULL, 0);
}


/**
 * Get facility by string.
 * ods_log_get_user
 * ods_log_get_facility
 * return error, LOG_*** as a parameter
 *
 */
#ifdef HAVE_SYSLOG_H
int
ods_log_get_facility(const char* facility, int* error)
{
    int length;

    if (!facility) {
        return LOG_DAEMON;
    }
    length = strlen(facility);

    if (length == 4 && strncasecmp(facility, "KERN", 4) == 0)
        return LOG_KERN;
    else if (length == 4 && strncasecmp(facility, "USER", 4) == 0)
        return LOG_USER;
    else if (length == 4 && strncasecmp(facility, "MAIL", 4) == 0)
        return LOG_MAIL;
    else if (length == 6 && strncasecmp(facility, "DAEMON", 6) == 0)
        return LOG_DAEMON;
    else if (length == 4 && strncasecmp(facility, "AUTH", 4) == 0)
        return LOG_AUTH;
    else if (length == 3 && strncasecmp(facility, "LPR", 3) == 0)
        return LOG_LPR;
    else if (length == 4 && strncasecmp(facility, "NEWS", 4) == 0)
        return LOG_NEWS;
    else if (length == 4 && strncasecmp(facility, "UUCP", 4) == 0)
        return LOG_UUCP;
    else if (length == 4 && strncasecmp(facility, "CRON", 4) == 0)
        return LOG_CRON;
    else if (length == 6 && strncasecmp(facility, "LOCAL0", 6) == 0)
        return LOG_LOCAL0;
    else if (length == 6 && strncasecmp(facility, "LOCAL1", 6) == 0)
        return LOG_LOCAL1;
    else if (length == 6 && strncasecmp(facility, "LOCAL2", 6) == 0)
        return LOG_LOCAL2;
    else if (length == 6 && strncasecmp(facility, "LOCAL3", 6) == 0)
        return LOG_LOCAL3;
    else if (length == 6 && strncasecmp(facility, "LOCAL4", 6) == 0)
        return LOG_LOCAL4;
    else if (length == 6 && strncasecmp(facility, "LOCAL5", 6) == 0)
        return LOG_LOCAL5;
    else if (length == 6 && strncasecmp(facility, "LOCAL6", 6) == 0)
        return LOG_LOCAL6;
    else if (length == 6 && strncasecmp(facility, "LOCAL7", 6) == 0)
        return LOG_LOCAL7;
    *error = 1;
    return LOG_DAEMON;

}
#endif /* HAVE_SYSLOG_H */

/**
 * Get the log level.
 *
 */
int
ods_log_get_level()
{
    return log_level;
}

/**
 * Log message wrapper.
 *
 */
static void
ods_log_vmsg(int priority, const char* t, const char* s, va_list args)
{
    char message[ODS_SE_MAXLINE];
    static char nowstr[CTIME_LENGTH];
    time_t now = time_now();

    vsnprintf(message, sizeof(message), s, args);

#ifdef HAVE_SYSLOG_H
    if (logging_to_syslog) {
#ifdef HAVE_SYSLOG_R
        syslog_r(priority, &sdata, "%s", message);
#else
        syslog(priority, "%s", message);
#endif
        return;
    }
#endif /* HAVE_SYSLOG_H */

    if (!logfile) {
        fprintf(stdout, "%s\n", message);
        return;
    }

    (void) ctime_r(&now, nowstr);
    nowstr[CTIME_LENGTH-2] = '\0'; /* remove trailing linefeed */

    fprintf(logfile, "[%s] %s[%i] %s: %s\n", nowstr,
        log_ident, priority, t, message);
    fflush(logfile);
}


/**
 * Heavy debug logging.
 *
 */
void
ods_log_deeebug(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_DEEEBUG) {
        ods_log_vmsg(LOG_DEBUG, "debug  ", format, args);
    }
    va_end(args);
}


/**
 * Log debug.
 *
 */
void
ods_log_debug(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_DEBUG) {
        ods_log_vmsg(LOG_DEBUG, "debug  ", format, args);
    }
    va_end(args);
}


/**
 * Log verbose.
 *
 */
void
ods_log_verbose(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_INFO) {
        ods_log_vmsg(LOG_INFO, "verbose", format, args);
    }
    va_end(args);
}


/**
 * Log info.
 *
 */
void
ods_log_info(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_NOTICE) {
        ods_log_vmsg(LOG_NOTICE, "msg    ", format, args);
    }
    va_end(args);
}


/**
 * Log warning.
 *
 */
void
ods_log_warning(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_WARNING) {
        ods_log_vmsg(LOG_WARNING, "warning", format, args);
    }
    va_end(args);
}


/**
 * Log error.
 *
 */
void
ods_log_error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_ERR) {
        ods_log_vmsg(LOG_ERR, "error  ", format, args);
    }
    va_end(args);
}

/**
 * Log error.
 *
 */
void
ods_log_verror(const char *format, va_list args)
{
    if (log_level >= LOG_ERR) {
        ods_log_vmsg(LOG_ERR, "error  ", format, args);
    }
}

/**
 * Log critical.
 *
 */
void
ods_log_crit(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_CRIT) {
        ods_log_vmsg(LOG_CRIT, "crit   ", format, args);
    }
    va_end(args);
}


/**
 * Log alert.
 *
 */
void
ods_log_alert(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_ALERT) {
        ods_log_vmsg(LOG_ALERT, "alert  ", format, args);
    }
    va_end(args);
}


/**
 * Log emergency and exit.
 *
 */
void
ods_fatal_exit(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_CRIT) {
        ods_log_vmsg(LOG_CRIT, "fatal  ", format, args);
    }
    va_end(args);
    abort();
}
