/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
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
 *
 */

#ifndef __db_value_h
#define __db_value_h

#ifdef __cplusplus
extern "C" {
#endif

struct db_value;
struct db_value_set;
typedef struct db_value db_value_t;
typedef struct db_value_set db_value_set_t;

#ifdef __cplusplus
}
#endif

#include "db_type.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct db_value {
    db_type_t type;
    void* data;
};

db_value_t* db_value_new();
void db_value_free(db_value_t*);
void db_value_reset(db_value_t*);
db_type_t db_value_type(const db_value_t*);
const void* db_value_data(const db_value_t*);
int db_value_set_type(db_value_t*, db_type_t);
int db_value_set_data(db_value_t*, void*);
int db_value_not_empty(const db_value_t*);
int db_value_to_int(const db_value_t*, int*);
int db_value_to_string(const db_value_t*, char**);
int db_value_from_int(db_value_t*, int);
int db_value_from_string(db_value_t*, const char*);

struct db_value_set {
    db_value_t* values;
    size_t size;
};

db_value_set_t* db_value_set_new(size_t);
void db_value_set_free(db_value_set_t*);
size_t db_value_set_size(const db_value_set_t*);
db_value_t* db_value_set_get(const db_value_set_t*, size_t);

#ifdef __cplusplus
}
#endif

#endif
