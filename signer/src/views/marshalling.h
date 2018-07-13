#ifndef MARSHALLLING_H
#define MARSHALLLING_H

#ifdef __cplusplus
extern "C" {
#endif
    
#include <unistd.h>

enum marshall_method { marshall_INPUT, marshall_OUTPUT, marshall_APPEND, marshall_PRINT, marshall_FREE };
typedef struct marshall_struct* marshall_handle;

marshall_handle marshallcreate(enum marshall_method method, ...);
void marshallclose(marshall_handle h);
int marshallself(marshall_handle h, void* member);
int marshallbyte(marshall_handle h, void* member);
int marshallinteger(marshall_handle h, void* member);
int marshallstring(marshall_handle h, void* member);
int marshallldnsrr(marshall_handle h, void* member);
int marshallsigs(marshall_handle h, void* member);
int marshallstringarray(marshall_handle h, void* member);
int marshalling(marshall_handle h, const char* name, void* members, int *membercount, size_t membersize, int (*memberfunction)(marshall_handle,void*));

extern int* marshall_OPTIONAL;

#ifdef __cplusplus
}
#endif

#endif /* MARSHALLLING_H */
