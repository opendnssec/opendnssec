/*
 * Copyright (c) 2016 NLNet Labs. All rights reserved.
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
#ifndef LOGGER_H
#define	LOGGER_H

typedef int log_t;
enum log_level { log_DEFAULT=0, log_FATAL, log_ERROR, log_WARN, log_INFO, log_DEBUG, log_TRACE };

extern void log_initialize(char* argv0);
extern log_t log_getlogger(char* loggingclass);
extern void log_message(log_t logger, enum log_level level, const char* file, int line, const char* func, const char* format, ...);
extern int log_isenabled(log_t logger, enum log_level level);
#define LOG(LEVEL, FORMAT,...) log_message(level, __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)
#define log_fatal(FORMAT,...)  log_message(log_FATAL, __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)
#define log_error(FORMAT,...)  log_message(log_ERROR, __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)
#define log_warn(FORMAT,...)   log_message(log_WARN,  __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)
#define log_info(FORMAT,...)   log_message(log_INFO,  __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)
#define log_debug(FORMAT,...)  log_message(log_DEBUG, __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)
#define log_trace(FORMAT,...)  log_message(log_TRACE, __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)

extern void log_configure_delstderrtarget(void);
extern void log_configure_addsyslogtarget(int facility);

extern void
alert(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;

#endif
