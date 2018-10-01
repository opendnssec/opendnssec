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
 * Log wrapper.
 *
 */

#ifndef SHARED_LOG_H
#define SHARED_LOG_H

#include "config.h"

#include <stdio.h>
#include <stdarg.h>

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

/**
 * Initialize logging.
 * \param[in] program_name identifying name used in logging (normally the running program name)
 * \param[in] use_syslog: use syslog(3)
 * \param[in] target_name name of the facilty in case of logging through syslog or otherwise a filename
 * \param[in] verbosity: log level
 *
 */
void ods_log_init(const char *program_name, int use_syslog, const char *target_name, int verbosity);

/**
 * Current verbosity
 * 
 */
int ods_log_verbosity(void);
void ods_log_setverbosity(int verbosity);

/**
 * Close logging.
 *
 */
void ods_log_close(void);

/**
 * Get the facility by string.
 * \param[in] facility string based facility
 * \return int facility
 *
 */
int ods_log_get_facility(const char* facility, int* error);

/**
 * Get the log level.
 * \return int log_level
 *
 */
int ods_log_get_level(void);

/**
 * Heavy debug loggin.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void ods_log_deeebug(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

/**
 * Log debug.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void ods_log_debug(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

/**
 * Log verbose.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void ods_log_verbose(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

/**
 * Log informational messages.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void ods_log_info(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

/**
 * Log warnings.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void ods_log_warning(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

/**
 * Log errors.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void ods_log_error(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

/**
 * Log errors.
 * \param[in] format printf-style format string, arguments follow
 * \param[in] args list of arguments already started with va_start
 *
 */
void ods_log_verror(const char *format, va_list args);

/**
 * Log criticals.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void ods_log_crit(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

/**
 * Log alerts.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void ods_log_alert(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

/**
 * Log critical errors and exit.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void ods_fatal_exit(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

/**
 * Log assertion.
 *
 */
#define ODS_LOG_DEBUG 1
#ifdef ODS_LOG_DEBUG
#define ods_log_assert(x) \
	do { if(!(x)) \
		ods_fatal_exit("%s:%d: %s: assertion %s failed", \
		__FILE__, __LINE__, __func__, #x); \
	} while(0);

#else
#define ods_log_assert(x)
#endif

#endif /* SHARED_LOG_H */
