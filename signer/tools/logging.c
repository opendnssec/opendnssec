/*
 * $Id: logging.c 1813 2009-09-16 11:33:29Z matthijs $
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

#include <syslog.h>

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
    char message[ODD_MAXLEN];

    vsnprintf(message, sizeof(message), s, args);

    if (logging_to_syslog)
        syslog(priority, "%s", message);
}

void
log_msg(int priority, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    log_vmsg(priority, format, args);
    va_end(args);
}

