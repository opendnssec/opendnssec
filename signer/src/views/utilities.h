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
