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

#ifndef __db_object_h
#define __db_object_h

#ifdef __cplusplus
extern "C" {
#endif

struct db_object;
struct db_object_field;
struct db_object_field_list;
typedef struct db_object db_object_t;
typedef struct db_object_field db_object_field_t;
typedef struct db_object_field_list db_object_field_list_t;

#ifdef __cplusplus
}
#endif

#include "db_connection.h"
#include "db_result.h"
#include "db_join.h"
#include "db_clause.h"
#include "db_type.h"

#ifdef __cplusplus
extern "C" {
#endif

struct db_object_field {
	db_object_field_t* next;
	const char* name;
	db_type_t type;
};

db_object_field_t* db_object_field_new(void);
void db_object_field_free(db_object_field_t*);
const char* db_object_field_name(const db_object_field_t*);
db_type_t db_object_field_type(const db_object_field_t*);
int db_object_field_set_name(db_object_field_t*, const char*);
int db_object_field_set_type(db_object_field_t*, db_type_t);
int db_object_field_not_empty(const db_object_field_t*);
const db_object_field_t* db_object_field_next(const db_object_field_t*);

struct db_object_field_list {
	db_object_field_t* begin;
	db_object_field_t* end;
};

db_object_field_list_t* db_object_field_list_new(void);
void db_object_field_list_free(db_object_field_list_t*);
int db_object_field_list_add(db_object_field_list_t*, db_object_field_t*);
const db_object_field_t* db_object_field_list_begin(const db_object_field_list_t*);

struct db_object {
	const db_connection_t* connection;
	const char* table;
	const char* primary_key_name;
	db_object_field_list_t* object_field_list;
};

db_object_t* db_object_new(void);
void db_object_free(db_object_t*);
const db_connection_t* db_object_connection(const db_object_t*);
const char* db_object_table(const db_object_t*);
const char* db_object_primary_key_name(const db_object_t*);
const db_object_field_list_t* db_object_object_field_list(const db_object_t*);
int db_object_set_connection(db_object_t*, const db_connection_t*);
int db_object_set_table(db_object_t*, const char*);
int db_object_set_primary_key_name(db_object_t*, const char*);
int db_object_set_object_field_list(db_object_t*, db_object_field_list_t*);
int db_object_create(const db_object_t*);
db_result_list_t* db_object_read(const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
int db_object_update(const db_object_t*);
int db_object_delete(const db_object_t*);

#ifdef __cplusplus
}
#endif

#endif
