/*
 * $Id$
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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

#include "logging.h"

#include <string.h>
#include <strings.h>

static int logging_to_syslog = 0;

void
log_open(int facility, const char *program_name)
{
    if (logging_to_syslog)
        closelog();
	openlog(program_name, 0, facility);
    logging_to_syslog = 1;
}

void log_close(void)
{
    if (logging_to_syslog)
        closelog();
    logging_to_syslog = 0;
}

static void
log_vmsg(int priority, const char* s, va_list args)
{
    vsyslog(priority, s, args);
}

void
log_msg(int priority, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    log_vmsg(priority, format, args);
    va_end(args);
}

static void strtoupper(char* string)
{
    char* ptr = string;
    if (ptr) {
        while (*ptr) {
            *ptr = toupper((int) *ptr);
            ++ptr;
        }
    }
    return;
}


int
facility2int(const char* facility, int* fac)
{
    char* dup;

    if (!facility) {
		return 1;
	}

	dup = strdup(facility);
	if (!dup) {
		return 1;
	}
	strtoupper(dup);

    if (strncmp(dup, "USER", 4) == 0 && strlen(dup) == 4)
        *fac = LOG_USER;
#ifdef LOG_KERN
    else if (strncmp(dup, "KERN", 4) == 0 && strlen(dup) == 4)
        *fac = LOG_KERN;
#endif
#ifdef LOG_MAIL
    else if (strncmp(dup, "MAIL", 4) == 0 && strlen(dup) == 4)
        *fac = LOG_MAIL;
#endif
#ifdef LOG_DAEMON
    else if (strncmp(dup, "DAEMON", 6) == 0 && strlen(dup) == 6)
        *fac = LOG_DAEMON;
#endif
#ifdef LOG_AUTH
    else if (strncmp(dup, "AUTH", 4) == 0 && strlen(dup) == 4)
        *fac = LOG_AUTH;
#endif
#ifdef LOG_LPR
    else if (strncmp(dup, "LPR", 3) == 0 && strlen(dup) == 3)
        *fac = LOG_LPR;
#endif
#ifdef LOG_NEWS
    else if (strncmp(dup, "NEWS", 4) == 0 && strlen(dup) == 4)
        *fac = LOG_NEWS;
#endif
#ifdef LOG_UUCP
    else if (strncmp(dup, "UUCP", 4) == 0 && strlen(dup) == 4)
        *fac = LOG_UUCP;
#endif
#ifdef LOG_CRON
    else if (strncmp(dup, "CRON", 4) == 0 && strlen(dup) == 4)
        *fac = LOG_CRON;
#endif
    else if (strncmp(dup, "LOCAL0", 6) == 0 && strlen(dup) == 6)
        *fac = LOG_LOCAL0;
    else if (strncmp(dup, "LOCAL1", 6) == 0 && strlen(dup) == 6)
        *fac = LOG_LOCAL1;
    else if (strncmp(dup, "LOCAL2", 6) == 0 && strlen(dup) == 6)
        *fac = LOG_LOCAL2;
    else if (strncmp(dup, "LOCAL3", 6) == 0 && strlen(dup) == 6)
        *fac = LOG_LOCAL3;
    else if (strncmp(dup, "LOCAL4", 6) == 0 && strlen(dup) == 6)
        *fac = LOG_LOCAL4;
    else if (strncmp(dup, "LOCAL5", 6) == 0 && strlen(dup) == 6)
        *fac = LOG_LOCAL5;
    else if (strncmp(dup, "LOCAL6", 6) == 0 && strlen(dup) == 6)
        *fac = LOG_LOCAL6;
    else if (strncmp(dup, "LOCAL7", 6) == 0 && strlen(dup) == 6)
        *fac = LOG_LOCAL7;

    return 0;
}

