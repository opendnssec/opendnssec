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

#ifndef DBSIMPLE_H
#define DBSIMPLE_H

#include <stddef.h>
#include <sys/types.h>

struct dbsimple_connection_struct;
typedef struct dbsimple_connection_struct* dbsimple_connection_type;
struct dbsimple_session_struct;
typedef struct dbsimple_session_struct* dbsimple_session_type;

#define dbsimple__UNSIGNED        0x100
#define dbsimple_UNDEFINED        0
#define dbsimple_REFERENCE        1
#define dbsimple_BACKREFERENCE    2
#define dbsimple_MASTERREFERENCES 3
#define dbsimple_STUBREFERENCES   4
#define dbsimple_OPENREFERENCES   5
#define dbsimple_STRING           6
#define dbsimple_INT              7
#define dbsimple_LONGINT          8
#define dbsimple_UINT             (dbsimple_INT|dbsimple__UNSIGNED)
#define dbsimple_ULONGINT         (dbsimple_LONGINT|dbsimple__UNSIGNED)

struct dbsimple_field {
    int type;
    struct dbsimple_definition* def;
    ssize_t fieldoffset;
    ssize_t countoffset;
};

#define dbsimple_FLAG_HASREVISION    0x0001
#define dbsimple_FLAG_SINGLETON      0x0002
#define dbsimple_FLAG_EXPLICITREMOVE 0x0004
#define dbsimple_FLAG_AUTOREMOVE     0x0008

struct dbsimple_definition {
    char* name;
    size_t size;
    int flags;
    int nfields;
    struct dbsimple_field* fields;
};

struct dbsimple_fetchplan_struct;
typedef struct dbsimple_fetchplan_struct* dbsimple_fetchplan_type;
typedef struct dbsimple_fetchplan_struct* const*  dbsimple_fetchplan_array[];
typedef struct dbsimple_fetchplan_struct* const** dbsimple_fetchplan_reference;

extern int dbsimple_initialize(void);
extern int dbsimple_finalize(void);
extern int dbsimple_fetchplan(dbsimple_fetchplan_type*, dbsimple_connection_type, char* module, const char* const* queries);
extern int dbsimple_openconnection(char* location, int nplans, dbsimple_fetchplan_array plans,
                            int ndefinitions, struct dbsimple_definition** definitions,
                            dbsimple_connection_type* connectionPtr);
extern int dbsimple_closeconnection(dbsimple_connection_type);
extern int dbsimple_opensession(dbsimple_connection_type connection, dbsimple_session_type* sessionPtr);
extern int dbsimple_closesession(dbsimple_session_type);
extern int dbsimple_sync(dbsimple_session_type, dbsimple_fetchplan_reference, void* data);
extern void* dbsimple_fetch(dbsimple_session_type, dbsimple_fetchplan_reference, ...);

extern int dbsimple_commit(dbsimple_session_type);
extern void dbsimple_dirty(dbsimple_session_type, void *ptr);
extern void dbsimple_delete(dbsimple_session_type, void *ptr);
extern void dbsimple_free(dbsimple_session_type);

#endif
