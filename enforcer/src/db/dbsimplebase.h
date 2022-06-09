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

#ifndef DBSIMPLEBASE_H
#define DBSIMPLEBASE_H

#include <stdarg.h>
#include <setjmp.h>

#include "tree.h"
#include "dbsimple.h"

enum objectstate { OBJNULL=0, OBJUNKNOWN, OBJNEW, OBJCLEAN, OBJREMOVED, OBJMODIFIED };

struct backpatch;
struct object;
struct dbsimple_connectionbase;
struct dbsimple_sessionbase;
struct dbsimple_module;

struct dbsimple_fieldimpl {
    int type;
    struct dbsimple_definitionimpl** def;
    ssize_t fieldoffset;
    ssize_t countoffset;
};

struct dbsimple_definitionimpl {
    char* name;
    size_t size;
    int flags;
    int nfields;
    struct dbsimple_fieldimpl* fields;
};

struct object {
    struct dbsimple_definitionimpl** type;
    char* data;
    long keyid;
    const char* keyname;
    int revision;
    enum objectstate state;
    struct object* next;
    struct backpatch* backpatches;
};

struct dbsimple_connectionbase {
    const struct dbsimple_module* module;
    char* location;
    int nplans;
    dbsimple_fetchplan_reference plans;
    int ndefinitions;
    struct dbsimple_definition** definitions;
};

struct dbsimple_fetchplan_struct {
    struct dbsimple_definitionimpl** definitions;
    int ndefinitions;
    const char* const* queries;
};

struct dbsimple_sessionbase {
    tree_type pointermap;
    tree_type objectmap;
    struct dbsimple_connectionbase* connection;
    const struct dbsimple_module* module;
    struct object* firstmodified;
    jmp_buf exceptionstate;
};

struct dbsimple_module {
    const char* identifier;
    int (*openconnection)(char* location, int, dbsimple_fetchplan_array, dbsimple_connection_type* connectionPtr);
    int (*closeconnection)(dbsimple_connection_type);
    int (*opensession)(dbsimple_connection_type, dbsimple_session_type*);
    int (*closesession)(dbsimple_session_type);
    int (*syncdata)(dbsimple_session_type, struct dbsimple_fetchplan_struct*,  void*);
    void* (*fetchdata)(dbsimple_session_type, struct dbsimple_fetchplan_struct*, va_list);
    int (*commitdata)(dbsimple_session_type);
    void (*fetchobject)(struct dbsimple_definitionimpl**, dbsimple_session_type);
    int (*persistobject)(struct object*, dbsimple_session_type);
};

extern int dbsimple_registermodule(const struct dbsimple_module* bindings);

extern void* dbsimple__fetch(struct dbsimple_sessionbase* session, int ndefinitions, struct dbsimple_definitionimpl** definitionimpls);
extern void dbsimple__assignreference(struct dbsimple_sessionbase* session, struct dbsimple_fieldimpl* field, long id, const char* name, struct object* source);
extern void dbsimple__assignbackreference(struct dbsimple_sessionbase* session, struct dbsimple_definitionimpl** def, int id, const char* name, struct dbsimple_fieldimpl* field, struct object* object);
extern void dbsimple__commit(struct dbsimple_sessionbase* session);
extern void dbsimple__committraverse(struct dbsimple_sessionbase* session, struct object* object);
extern struct object* dbsimple__referencebyptr(struct dbsimple_sessionbase* session, struct dbsimple_definitionimpl** def, void* ptr);
extern struct object* dbsimple__getobject(struct dbsimple_sessionbase* session, enum objectstate state, struct dbsimple_definitionimpl** def, long id, const char* name);

#endif
