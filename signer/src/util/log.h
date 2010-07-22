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
 * Log wrapper.
 *
 */

#ifndef UTIL_LOG_H
#define UTIL_LOG_H

#include "config.h"

#include <stdio.h>
#include <stdarg.h>

/**
 * Initialize logging.
 * \param[in] filename logfile, stderr if NULL.
 * \param[in] use_syslog: use syslog(3) and ingore filename
 * \param[in] verbosity: log level
 *
 */
void se_log_init(const char *filename, int use_syslog, int verbosity);

/**
 * Close logging.
 *
 */
void se_log_close(void);

/**
 * Get the facility by string.
 * \param[in] facility string based facility
 * \return int facility
 *
 */
int se_log_get_facility(const char* facility);

/**
 * Log debug.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void se_log_debug(const char *format, ...);

/**
 * Log verbose.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void se_log_verbose(const char *format, ...);

/**
 * Log informational messages.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void se_log_info(const char *format, ...);

/**
 * Log warnings.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void se_log_warning(const char *format, ...);

/**
 * Log errors.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void se_log_error(const char *format, ...);

/**
 * Log criticals.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void se_log_crit(const char *format, ...);

/**
 * Log alerts.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void se_log_alert(const char *format, ...);

/**
 * Log critical errors and exit.
 * \param[in] format printf-style format string, arguments follow
 *
 */
void se_fatal_exit(const char *format, ...);

/**
 * Log assertion.
 *
 */
#define SE_LOG_DEBUG 1
#ifdef SE_LOG_DEBUG
#define se_log_assert(x) \
	do { if(!(x)) \
		se_fatal_exit("%s:%d: %s: assertion %s failed", \
		__FILE__, __LINE__, __func__, #x); \
	} while(0);

#else
#define se_log_assert(x)
#endif

#endif /* UTIL_LOG_H */
