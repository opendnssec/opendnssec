/*
 * $Id$
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
#include "util/duration.h"
#include "util/file.h"
#include "util/log.h"

#include <stdarg.h> /* va_start(), va_end()  */
#include <stdio.h> /* fflush, fprintf(), vsnprintf() */
#include <stdlib.h> /* exit() */
#include <string.h> /* strlen() */

#ifdef HAVE_SYSLOG_H
#include <strings.h> /* strncasecmp() */
#include <syslog.h> /* openlog(), closelog(), syslog() */
static int logging_to_syslog = 0;
#else /* !HAVE_SYSLOG_H */
#define LOG_EMERG   0 /* se_fatal_exit */
#define LOG_ALERT   1 /* se_log_alert */
#define LOG_CRIT    2 /* se_log_crit */
#define LOG_ERR     3 /* se_log_error */
#define LOG_WARNING 4 /* se_log_warning */
#define LOG_NOTICE  5 /* se_log_info */
#define LOG_INFO    6 /* se_log_verbose */
#define LOG_DEBUG   7 /* se_log_debug */
#endif /* HAVE_SYSLOG_H */

static FILE* logfile = NULL;
static int log_level = LOG_CRIT;


/* TODO:
   - prepend ods_ in common library
   - log_init should have program_name variable)
   - wrap special case logging onto generic one
   - check if xml-specific logging functions are still neeeded (enforcer)
   -
*/


/**
 * Initialize logging.
 *
 */
void
se_log_init(const char *filename, int use_syslog, int verbosity)
{
#ifdef HAVE_SYSLOG_H
    int facility;
#endif /* HAVE_SYSLOG_H */
    se_log_verbose("switching log to %s verbosity %i (log level %i)",
        use_syslog?"syslog":(filename&&filename[0]?filename:"stderr"),
        verbosity, verbosity+2);
    if (logfile && logfile != stderr) {
            se_fclose(logfile);
	}
    log_level = verbosity + 2;

#ifdef HAVE_SYSLOG_H
    if(logging_to_syslog) {
        closelog();
        logging_to_syslog = 0;
    }
    if(use_syslog) {
       facility = se_log_get_facility(filename);
       openlog(PACKAGE_TARNAME, LOG_NDELAY, facility);
       logging_to_syslog = 1;
       return;
    }
#endif /* HAVE_SYSLOG_H */

    if(filename && filename[0]) {
        logfile = se_fopen(filename, NULL, "a");
        if (logfile) {
            se_log_debug("new logfile %s", filename);
            return;
        }
        logfile = stderr;
        se_log_warning("cannot open %s for appending, logging to "
                       "stderr", filename);
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
se_log_close(void)
{
    se_log_debug("close log");
    se_log_init(NULL, 0, 0);
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
se_log_get_facility(const char* facility)
{
    if (!facility) {
        return LOG_DAEMON;
    }

    if (strncasecmp(facility, "KERN", 4) && strlen(facility) == 4)
        return LOG_KERN;
    else if (strncasecmp(facility, "USER", 4) && strlen(facility) == 4)
        return LOG_USER;
    else if (strncasecmp(facility, "MAIL", 4) && strlen(facility) == 4)
        return LOG_MAIL;
    else if (strncasecmp(facility, "DAEMON", 6) && strlen(facility) == 6)
        return LOG_DAEMON;
    else if (strncasecmp(facility, "AUTH", 4) && strlen(facility) == 4)
        return LOG_AUTH;
    else if (strncasecmp(facility, "LPR", 3) && strlen(facility) == 3)
        return LOG_LPR;
    else if (strncasecmp(facility, "NEWS", 4) && strlen(facility) == 4)
        return LOG_NEWS;
    else if (strncasecmp(facility, "UUCP", 4) && strlen(facility) == 4)
        return LOG_UUCP;
    else if (strncasecmp(facility, "CRON", 4) && strlen(facility) == 4)
        return LOG_CRON;
    else if (strncasecmp(facility, "LOCAL0", 6) && strlen(facility) == 6)
        return LOG_LOCAL0;
    else if (strncasecmp(facility, "LOCAL1", 6) && strlen(facility) == 6)
        return LOG_LOCAL1;
    else if (strncasecmp(facility, "LOCAL2", 6) && strlen(facility) == 6)
        return LOG_LOCAL2;
    else if (strncasecmp(facility, "LOCAL3", 6) && strlen(facility) == 6)
        return LOG_LOCAL3;
    else if (strncasecmp(facility, "LOCAL4", 6) && strlen(facility) == 6)
        return LOG_LOCAL4;
    else if (strncasecmp(facility, "LOCAL5", 6) && strlen(facility) == 6)
        return LOG_LOCAL5;
    else if (strncasecmp(facility, "LOCAL6", 6) && strlen(facility) == 6)
        return LOG_LOCAL6;
    else if (strncasecmp(facility, "LOCAL7", 6) && strlen(facility) == 6)
        return LOG_LOCAL7;
    se_log_warning("syslog facility %s not supported, logging to "
                   "log_daemon", facility);
    return LOG_DAEMON;

}
#endif /* HAVE_SYSLOG_H */


/**
 * Log message wrapper.
 *
 */
static void
se_log_vmsg(int priority, const char* t, const char* s, va_list args)
{
    char message[ODS_SE_MAXLINE];
    time_t now = time_now();
    char* strtime = NULL;

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
    strtime = ctime(&now);
    strtime[strlen(strtime)-1] = '\0';

    fprintf(logfile, "[%s] %s[%i] %s: %s\n", strtime,
        PACKAGE_TARNAME, priority, t, message);
    fflush(logfile);
}


/**
 * Log debug.
 *
 */
void
se_log_debug(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_DEBUG) {
        se_log_vmsg(LOG_DEBUG, "debug", format, args);
    }
    va_end(args);
}


/**
 * Log verbose.
 *
 */
void
se_log_verbose(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_INFO) {
        se_log_vmsg(LOG_INFO, "verbose", format, args);
    }
    va_end(args);
}


/**
 * Log info.
 *
 */
void
se_log_info(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_NOTICE) {
        se_log_vmsg(LOG_NOTICE, "msg", format, args);
    }
    va_end(args);
}


/**
 * Log warning.
 *
 */
void
se_log_warning(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_WARNING) {
        se_log_vmsg(LOG_WARNING, "warning", format, args);
    }
    va_end(args);
}


/**
 * Log error.
 *
 */
void
se_log_error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_ERR) {
        se_log_vmsg(LOG_ERR, "error", format, args);
    }
    va_end(args);
}


/**
 * Log critical.
 *
 */
void
se_log_crit(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_CRIT) {
        se_log_vmsg(LOG_CRIT, "critical", format, args);
    }
    va_end(args);
}


/**
 * Log alert.
 *
 */
void
se_log_alert(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_ALERT) {
        se_log_vmsg(LOG_ALERT, "critical", format, args);
    }
    va_end(args);
}


/**
 * Log emergency and exit.
 *
 */
void
se_fatal_exit(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_level >= LOG_CRIT) {
        se_log_vmsg(LOG_CRIT, "fatal error", format, args);
    }
    va_end(args);
    se_log_init(NULL, 0, 0);
    exit(2);
}
