/*
 * Copyright (c) 2021 A.W. van Halderen
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

#define QUOTE(ARG) #ARG

#ifdef __cplusplus
#include <cstdio>
#include <string>
#include <sstream>
#endif
#include <stdarg.h>
#include <stddef.h>

#if !defined(__GNUC__) || __GNUC__ < 2 || \
    (__GNUC__ == 2 && __GNUC_MINOR__ < 7) ||\
    defined(NEXT)
#ifndef __attribute__
#define __attribute__(__x)
#endif
#endif

#ifdef __cplusplus
class mkstring
{
private:
  std::ostringstream os;
public:
  template <class T> mkstring &operator<<(const T &t) {
    os << t;
    return *this;
  }
  mkstring& operator<<(const char* m) {
    os << m;
    return *this;
  }
  mkstring& operator<<(const std::string& s) {
    os << s;
    return *this;
  }
  static std::string format(const char *fmt, va_list ap);
  static std::string format(const char *fmt, ...)
     __attribute__ ((__format__ (__printf__, 1, 2)));
  operator std::string() const { return os.str(); }
  const std::string str() const { return os.str(); };
  const char* c_str() const { return os.str().c_str(); };
};
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

typedef void (*functioncast_type)(void);
extern functioncast_type functioncast(void*generic);

typedef void (*voidfunc)(void);

/**                
 * Clamp an integer value between a lower and an upper bound.
 *
 * In effect a combination of a min() and max() call this function
 * will return the value as long as it lies between the lower and
 * upper bound.  If smaller (or equal) to the lower bound it will
 * return the lower bound and likewise if larger or equal to the
 * upper, the upper bound.  The result may be either lower or
 * upper bound if the upper bound is smaller than the lower bound.
 */
extern int clamp(int value, int lbnd, int ubnd);

extern unsigned long long int rnd(void);

extern int alloc(void* ptr, size_t size, int* countptr, int newcount);

extern char* dupstr(const char* ptr);

#endif
