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
