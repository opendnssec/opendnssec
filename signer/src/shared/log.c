/*
 * $Id: log.c 3845 2010-08-31 14:19:24Z matthijs $
 *
 * Copyright (c) 2009 NLnet Labs. All rights reserved.
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
 * Logging.
 *
 */

#include "config.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/util.h"

#include <stdarg.h> /* va_start(), va_end()  */
#include <stdio.h> /* fflush, fprintf(), vsnprintf() */
#include <stdlib.h> /* exit() */
#include <string.h> /* strlen() */

#ifdef HAVE_SYSLOG_H
#include <strings.h> /* strncasecmp() */
#include <syslog.h> /* openlog(), closelog(), syslog() */
static int logging_to_syslog = 0;
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

static FILE* logfile = NULL;
static int log_level = LOG_CRIT;

#define CTIME_LENGTH 26


/* TODO:
   - log_init should have program_name variable
   - wrap special case logging onto generic one
   - check if xml-specific logging functions are still neeeded (enforcer)
   -
*/

#define MY_PACKAGE_TARNAME "ods-signerd"

static const char* log_str = "log";

/**
 * Initialize logging.
 *
 */
void
ods_log_init(const char *filename, int use_syslog, int verbosity)
{
#ifdef HAVE_SYSLOG_H
    int facility;
#endif /* HAVE_SYSLOG_H */
    ods_log_verbose("[%s] switching log to %s verbosity %i (log level %i)",
        log_str, use_syslog?"syslog":(filename&&filename[0]?filename:"stderr"),
        verbosity, verbosity+2);
    if (logfile && logfile != stderr) {
            ods_fclose(logfile);
	}
    log_level = verbosity + 2;

#ifdef HAVE_SYSLOG_H
    if(logging_to_syslog) {
        closelog();
        logging_to_syslog = 0;
    }
    if(use_syslog) {
       facility = ods_log_get_facility(filename);
       openlog(MY_PACKAGE_TARNAME, LOG_NDELAY, facility);
       logging_to_syslog = 1;
       return;
    }
#endif /* HAVE_SYSLOG_H */

    if(filename && filename[0]) {
        logfile = ods_fopen(filename, NULL, "a");
        if (logfile) {
            ods_log_debug("[%s] new logfile %s", log_str, filename);
            return;
        }
        logfile = stderr;
        ods_log_warning("[%s] cannot open %s for appending, logging to "
            "stderr", log_str, filename);
    } else {
        logfile = stderr;
    }
    return;
}


/**
 * Close logging.
 *
 */
void
ods_log_close(void)
{
    ods_log_debug("[%s] close log", log_str);
    ods_log_init(NULL, 0, 0);
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
ods_log_get_facility(const char* facility)
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
    ods_log_warning("[%s] syslog facility %s not supported, logging to "
                   "log_daemon", log_str, facility);
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
        syslog(priority, "%s", message);
        return;
    }
#endif /* HAVE_SYSLOG_H */

    if (!logfile) {
        return;
    }

    (void) ctime_r(&now, nowstr);
    nowstr[CTIME_LENGTH-2] = '\0'; /* remove trailing linefeed */

    fprintf(logfile, "[%s] %s[%i] %s: %s\n", nowstr,
        MY_PACKAGE_TARNAME, priority, t, message);
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
