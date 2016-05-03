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

#ifndef DEBUG_H
#define DEBUG_H

extern int installcoreprevent(void);
extern int installcrashhandler(char* argv0);

/* void alert(char *format, ...) */

extern void log_message(int level, const char* file, int line, const char* func, const char* format, ...);
#define log_FATAL (1)
#define log_ERROR (2)
#define log_WARN  (3)
#define log_INFO  (4)
#define log_DEBUG (5)
#define log_TRACE (6)
#define LOG(LEVEL, FORMAT,...) log_message(int level, __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)
#define log_fatal(FORMAT,...)  log_message(log_FATAL, __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)
#define log_error(FORMAT,...)  log_message(log_ERROR, __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)
#define log_warn(FORMAT,...)   log_message(log_WARN,  __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)
#define log_info(FORMAT,...)   log_message(log_INFO,  __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)
#define log_debug(FORMAT,...)  log_message(log_DEBUG, __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)
#define log_trace(FORMAT,...)  log_message(log_TRACE, __FILE__,__LINE__,__FUNCTION__,FORMAT,__VA_ARGS__)

extern void fail(const char* file, int line, const char* func, const char* expr, int stat);
#define CHECKFAIL(EX) do { int CHECKFAIL; if((CHECKFAIL = (EX))) { fail(__FILE__,__LINE__,__FUNCTION__,#EX,CHECKFAIL); goto fail; } } while(0)

#endif
