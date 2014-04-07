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
#include "db_value.h"
#include "db_enum.h"
#include "db_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * TODO
 */
struct db_object_field {
    db_object_field_t* next;
    const char* name;
    db_type_t type;
    const db_enum_t* enum_set;
};

/**
 * TODO
 * \param[in] void TODO 
 * \return `db_object_field_t*` TODO
 */
db_object_field_t* db_object_field_new(void);

/**
 * TODO
 * \param[in] object_field TODO 
 * \return `void` TODO
 */
void db_object_field_free(db_object_field_t* object_field);

/**
 * TODO
 * \param[in] object_field TODO 
 * \return `const char*` TODO
 */
const char* db_object_field_name(const db_object_field_t* object_field);

/**
 * TODO
 * \param[in] object_field TODO 
 * \return `db_type_t` TODO
 */
db_type_t db_object_field_type(const db_object_field_t* object_field);

/**
 * TODO
 * \param[in] object_field TODO 
 * \return `const db_enum_t*` TODO
 */
const db_enum_t* db_object_field_enum_set(const db_object_field_t* object_field);

/**
 * TODO
 * \param[in] object_field TODO 
 * \param[in] name TODO 
 * \return `int` TODO
 */
int db_object_field_set_name(db_object_field_t* object_field, const char* name);

/**
 * TODO
 * \param[in] object_field TODO 
 * \param[in] type TODO 
 * \return `int` TODO
 */
int db_object_field_set_type(db_object_field_t* object_field, db_type_t type);

/**
 * TODO
 * \param[in] object_field TODO 
 * \param[in] enum_set TODO 
 * \return `int` TODO
 */
int db_object_field_set_enum_set(db_object_field_t* object_field, const db_enum_t* enum_set);

/**
 * TODO
 * \param[in] object_field TODO 
 * \return `int` TODO
 */
int db_object_field_not_empty(const db_object_field_t* object_field);

/**
 * TODO
 * \param[in] object_field TODO 
 * \return `const db_object_field_t*` TODO
 */
const db_object_field_t* db_object_field_next(const db_object_field_t* object_field);

/**
 * TODO
 */
struct db_object_field_list {
    db_object_field_t* begin;
    db_object_field_t* end;
};

/**
 * TODO
 * \param[in] void TODO 
 * \return `db_object_field_list_t*` TODO
 */
db_object_field_list_t* db_object_field_list_new(void);

/**
 * TODO
 * \param[in] object_field_list TODO 
 * \return `void` TODO
 */
void db_object_field_list_free(db_object_field_list_t* object_field_list);

/**
 * TODO
 * \param[in] object_field_list TODO 
 * \param[in] object_field TODO 
 * \return `int` TODO
 */
int db_object_field_list_add(db_object_field_list_t* object_field_list, db_object_field_t* object_field);

/**
 * TODO
 * \param[in] object_field_list TODO 
 * \return `const db_object_field_t*` TODO
 */
const db_object_field_t* db_object_field_list_begin(const db_object_field_list_t* object_field_list);

/**
 * TODO
 */
struct db_object {
    const db_connection_t* connection;
    const char* table;
    const char* primary_key_name;
    db_object_field_list_t* object_field_list;
    db_backend_meta_data_list_t* backend_meta_data_list;
};

/**
 * TODO
 * \param[in] void TODO 
 * \return `db_object_t*` TODO
 */
db_object_t* db_object_new(void);

/**
 * TODO
 * \param[in] object TODO 
 * \return `void` TODO
 */
void db_object_free(db_object_t* object);

/**
 * TODO
 * \param[in] object TODO 
 * \return `const db_connection_t*` TODO
 */
const db_connection_t* db_object_connection(const db_object_t* object);

/**
 * TODO
 * \param[in] object TODO 
 * \return `const char*` TODO
 */
const char* db_object_table(const db_object_t* object);

/**
 * TODO
 * \param[in] object TODO 
 * \return `const char*` TODO
 */
const char* db_object_primary_key_name(const db_object_t* object);

/**
 * TODO
 * \param[in] object TODO 
 * \return `const db_object_field_list_t*` TODO
 */
const db_object_field_list_t* db_object_object_field_list(const db_object_t* object);

/**
 * TODO
 * \param[in] object TODO 
 * \return `const db_backend_meta_data_list_t*` TODO
 */
const db_backend_meta_data_list_t* db_object_backend_meta_data_list(const db_object_t* object);

/**
 * TODO
 * \param[in] object TODO 
 * \param[in] connection TODO 
 * \return `int` TODO
 */
int db_object_set_connection(db_object_t* object, const db_connection_t* connection);

/**
 * TODO
 * \param[in] object TODO 
 * \param[in] table TODO 
 * \return `int` TODO
 */
int db_object_set_table(db_object_t* object, const char* table);

/**
 * TODO
 * \param[in] object TODO 
 * \param[in] primary_key_name TODO 
 * \return `int` TODO
 */
int db_object_set_primary_key_name(db_object_t* object, const char* primary_key_name);

/**
 * TODO
 * \param[in] object TODO 
 * \param[in] object_field_list TODO 
 * \return `int` TODO
 */
int db_object_set_object_field_list(db_object_t* object, db_object_field_list_t* object_field_list);

/**
 * TODO
 * \param[in] object TODO 
 * \param[in] backend_meta_data_list TODO 
 * \return `int` TODO
 */
int db_object_set_backend_meta_data_list(db_object_t* object, db_backend_meta_data_list_t* backend_meta_data_list);

/**
 * TODO
 * \param[in] object TODO 
 * \param[in] object_field_list TODO 
 * \param[in] value_set TODO 
 * \return `int` TODO
 */
int db_object_create(const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set);

/**
 * TODO
 * \param[in] object TODO 
 * \param[in] join_list TODO 
 * \param[in] clause_list TODO 
 * \return `db_result_list_t*` TODO
 */
db_result_list_t* db_object_read(const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list);

/**
 * TODO
 * \param[in] object TODO 
 * \param[in] object_field_list TODO 
 * \param[in] value_set TODO 
 * \param[in] clause_list TODO 
 * \return `int` TODO
 */
int db_object_update(const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list);

/**
 * TODO
 * \param[in] object TODO 
 * \param[in] clause_list TODO 
 * \return `int` TODO
 */
int db_object_delete(const db_object_t* object, const db_clause_list_t* clause_list);

#ifdef __cplusplus
}
#endif

#endif
