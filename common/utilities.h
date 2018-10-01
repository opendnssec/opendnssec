/*
 * Copyright (c) 2018 NLNet Labs.
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

#ifndef UTILITIES_H
#define UTILITIES_H

#ifdef NOTDEFINED
#error "never define NOTDEFINED"
#endif

#ifdef __cplusplus
#include <cstdio>
#include <string>
#include <sstream>
#endif
#include <stdarg.h>

#if !defined(__GNUC__) || __GNUC__ < 2 || \
    (__GNUC__ == 2 && __GNUC_MINOR__ < 7) ||\
    defined(NEXT)
#ifndef __attribute__
#define __attribute__(__x)
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern void diagnostic_set(char *file, int line);
extern void diagnostic_print(char *fmt, ...)
     __attribute__ ((__format__ (__printf__, 1, 2)));
#ifdef __cplusplus
}
#endif

#define DIAG(LEVEL,ARG) do { if(DIAGLEVEL >= DIAG##LEVEL) { diagnostic_set(__FILE__,__LINE__); diagnostic_print ARG; } } while(0);
#define DIAGWARN 1
#define DIAGINFO 0
#ifndef DIAGLEVEL
#define DIAGLEVEL DIAGINFO
#endif

#ifdef DEBUG
# define BUG(ARG) ARG
#else
# define BUG(ARG)
#endif

#ifndef CHECK
#define CHECK(EX) do { if(EX) { int err = errno; fprintf(stderr, "operation" \
 " \"%s\" failed on line %d: %s (%d)\n", #EX, __LINE__, strerror(err), err); \
  abort(); }} while(0)
#endif

#ifndef CHECKALLOC
#define CHECKALLOC(PTR) if(!(PTR)) { fprintf(stderr,"Out of memory when executing %s at %s:%d\n", #PTR, __FILE__, __LINE__); }
#endif

extern char* argv0;

typedef void (*functioncast_t)(void);
extern functioncast_t functioncast(void*generic);

unsigned long long int rnd(void);

#endif
