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

#ifndef __db_clause_h
#define __db_clause_h

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DB_CLAUSE_UNKNOWN,
    DB_CLAUSE_EQUAL,
    DB_CLAUSE_NOT_EQUAL,
    DB_CLAUSE_LESS_THEN,
    DB_CLAUSE_LESS_OR_EQUAL,
    DB_CLAUSE_GREATER_OR_EQUAL,
    DB_CLAUSE_GREATER_THEN,
    DB_CLAUSE_IS_NULL,
    DB_CLAUSE_IS_NOT_NULL,
    DB_CLAUSE_NESTED
} db_clause_type_t;
typedef enum {
    DB_CLAUSE_OPERATOR_UNKNOWN,
    DB_CLAUSE_OPERATOR_AND,
    DB_CLAUSE_OPERATOR_OR
} db_clause_operator_t;
#define DB_CLAUSE_EQ DB_CLAUSE_EQUAL
#define DB_CLAUSE_NE DB_CLAUSE_NOT_EQUAL
#define DB_CLAUSE_LT DB_CLAUSE_LESS_THEN
#define DB_CLAUSE_LE DB_CLAUSE_LESS_OR_EQUAL
#define DB_CLAUSE_GE DB_CLAUSE_GREATER_OR_EQUAL
#define DB_CLAUSE_GT DB_CLAUSE_GREATER_THEN

struct db_clause;
struct db_clause_list;
typedef struct db_clause db_clause_t;
typedef struct db_clause_list db_clause_list_t;

#ifdef __cplusplus
}
#endif

#include "db_value.h"

#ifdef __cplusplus
extern "C" {
#endif

struct db_clause {
    db_clause_t* next;
    char* table;
    char* field;
    db_clause_type_t type;
    db_value_t value;
    db_clause_operator_t clause_operator;
    db_clause_list_t* clause_list;
};

db_clause_t* db_clause_new(void);
void db_clause_free(db_clause_t*);
const char* db_clause_table(const db_clause_t*);
const char* db_clause_field(const db_clause_t*);
db_clause_type_t db_clause_type(const db_clause_t*);
const db_value_t* db_clause_value(const db_clause_t*);
db_clause_operator_t db_clause_operator(const db_clause_t*);
const db_clause_list_t* db_clause_list(const db_clause_t*);
int db_clause_set_table(db_clause_t*, const char*);
int db_clause_set_field(db_clause_t*, const char*);
int db_clause_set_type(db_clause_t*, db_clause_type_t);
int db_clause_set_operator(db_clause_t*, db_clause_operator_t);
int db_clause_set_list(db_clause_t*, db_clause_list_t*);
int db_clause_not_empty(const db_clause_t*);
const db_clause_t* db_clause_next(const db_clause_t*);
db_value_t* db_clause_get_value(db_clause_t*);

struct db_clause_list {
    db_clause_t* begin;
    db_clause_t* end;
};

db_clause_list_t* db_clause_list_new(void);
void db_clause_list_free(db_clause_list_t*);
int db_clause_list_add(db_clause_list_t*, db_clause_t*);
const db_clause_t* db_clause_list_begin(const db_clause_list_t*);

#ifdef __cplusplus
}
#endif

#endif
