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

struct db_object;
struct db_object_field;
struct db_object_field_list;
typedef struct db_object db_object_t;
typedef struct db_object_field db_object_field_t;
typedef struct db_object_field_list db_object_field_list_t;

#include "db_connection.h"
#include "db_result.h"
#include "db_join.h"
#include "db_clause.h"
#include "db_type.h"
#include "db_value.h"
#include "db_enum.h"
#include "db_backend.h"

/**
 * A representation of an field/value for a database object.
 */
struct db_object_field {
    db_object_field_t* next;
    const char* name;
    db_type_t type;
    const db_enum_t* enum_set;
};

/**
 * Create a database object field.
 * \return a db_object_field_t pointer or NULL on error.
 */
db_object_field_t* db_object_field_new(void);

/**
 * Create a database object field that is a copy of another.
 * \param[in] from_object_field a db_object_field_t pointer.
 * \return a db_object_field_t pointer or NULL on error.
 */
db_object_field_t* db_object_field_new_copy(const db_object_field_t* from_object_field);

/**
 * Delete a database object field.
 * \param[in] object_field a db_object_field_t pointer.
 */
void db_object_field_free(db_object_field_t* object_field);

/**
 * Copy the content of a database object field.
 * \param[in] object_field a db_object_field_t pointer.
 * \param[in] from_object_field a db_object_field_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_field_copy(db_object_field_t* object_field, const db_object_field_t* from_object_field);

/**
 * Get the name of a database object field.
 * \param[in] object_field a db_object_field_t pointer.
 * \return a character pointer or NULL on error or if no field name has been set.
 */
const char* db_object_field_name(const db_object_field_t* object_field);

/**
 * Get the type of a database object field.
 * \param[in] object_field a db_object_field_t pointer.
 * \return a db_type_t.
 */
db_type_t db_object_field_type(const db_object_field_t* object_field);

/**
 * Set the name of a database object field.
 * \param[in] object_field a db_object_field_t pointer.
 * \param[in] name a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_field_set_name(db_object_field_t* object_field, const char* name);

/**
 * Set the type of a database object field.
 * \param[in] object_field a db_object_field_t pointer.
 * \param[in] type a db_type_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_field_set_type(db_object_field_t* object_field, db_type_t type);

/**
 * Set the enumerate set of a database object field.
 * \param[in] object_field a db_object_field_t pointer.
 * \param[in] enum_set a NULL terminated db_enum_t list.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_field_set_enum_set(db_object_field_t* object_field, const db_enum_t* enum_set);

/**
 * Check if the object field is not empty.
 * \param[in] object_field a db_object_field_t pointer.
 * \return DB_ERROR_* if empty, otherwise DB_OK.
 */
int db_object_field_not_empty(const db_object_field_t* object_field);

/**
 * Get the next object field connected in a database object field list.
 * \param[in] object_field a db_object_field_t pointer.
 * \return a db_object_field_t pointer or NULL on error or if there are no more
 * object fields in the list.
 */
const db_object_field_t* db_object_field_next(const db_object_field_t* object_field);

/**
 * A list of object fields.
 */
struct db_object_field_list {
    db_object_field_t* begin;
    db_object_field_t* end;
    size_t size;
};

/**
 * Create a new object field list.
 * \return a db_object_field_list_t pointer or NULL on error.
 */
db_object_field_list_t* db_object_field_list_new(void);

/**
 * Create a new object field list that is a copy of another.
 * \param[in] from_object_field_list a db_object_field_list_t pointer.
 * \return a db_object_field_list_t pointer or NULL on error.
 */
db_object_field_list_t* db_object_field_list_new_copy(const db_object_field_list_t* from_object_field_list);

/**
 * Delete a object field list and all object fields within the list.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 */
void db_object_field_list_free(db_object_field_list_t* object_field_list);

/**
 * Copy the content of a database object field list.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \param[in] from_object_field_list a db_object_field_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_field_list_copy(db_object_field_list_t* object_field_list, const db_object_field_list_t* from_object_field_list);

/**
 * Add a database object field to a database object field list, this will takes
 * over the ownership of the object field.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \param[in] object_field a db_object_field_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_field_list_add(db_object_field_list_t* object_field_list, db_object_field_t* object_field);

/**
 * Return the first database object field in a database object field list.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \return a db_object_field_t pointer or NULL on error or if the list is empty.
 */
const db_object_field_t* db_object_field_list_begin(const db_object_field_list_t* object_field_list);

/**
 * Return the size of a object field list.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \return a size_t, may be zero on error.
 */
size_t db_object_field_list_size(const db_object_field_list_t* object_field_list);

/**
 * A database object.
 */
struct db_object {
    const db_connection_t* connection;
    const char* table;
    const char* primary_key_name;
    db_object_field_list_t* object_field_list;
};

/**
 * Create a new database object.
 * \return a db_object_t pointer or NULL on error.
 */
db_object_t* db_object_new(void);

/**
 * Delete a database object and the object field list and backend meta data list
 * if set.
 * \param[in] object a db_object_t pointer.
 */
void db_object_free(db_object_t* object);

/**
 * Get the database connection of a database object.
 * \param[in] object a db_object_t pointer.
 * \return a db_connection_t pointer or NULL on error or if no connection has
 * been set.
 */
const db_connection_t* db_object_connection(const db_object_t* object);

/**
 * Get the table name of a database object.
 * \param[in] object a db_object_t pointer.
 * \return a character pointer or NULL on error or if no table name has been
 * set.
 */
const char* db_object_table(const db_object_t* object);

/**
 * Get the object field list of a database object.
 * \param[in] object a db_object_t pointer.
 * \return a db_object_field_list_t pointer or NULL on error or if no object
 * field list has been set.
 */
const db_object_field_list_t* db_object_object_field_list(const db_object_t* object);

/**
 * Set the database connection of a database object.
 * \param[in] object a db_object_t pointer.
 * \param[in] connection a db_connection_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_set_connection(db_object_t* object, const db_connection_t* connection);

/**
 * Set the table name of a database object.
 * \param[in] object a db_object_t pointer.
 * \param[in] table a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_set_table(db_object_t* object, const char* table);

/**
 * Set the primary key name of a database object.
 * \param[in] object a db_object_t pointer.
 * \param[in] primary_key_name a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_set_primary_key_name(db_object_t* object, const char* primary_key_name);

/**
 * Set the object field list of a database object, this takes over the ownership
 * of the object field list.
 * \param[in] object a db_object_t pointer.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_set_object_field_list(db_object_t* object, db_object_field_list_t* object_field_list);

/**
 * Create an object in the database. The `object_field_list` describes the
 * fields that should be set in the object and the `value_set` has the values
 * for each field.
 * \param[in] object a db_object_t pointer.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \param[in] value_set a db_value_set_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_create(db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set);

/**
 * Read an object or objects from the database.
 * \param[in] object a db_object_t pointer.
 * \param[in] join_list a db_join_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a db_result_list_t pointer or NULL on error or if no objects where
 * read.
 */
db_result_list_t* db_object_read(const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list);

/**
 * Update an object or objects in the database.
 * \param[in] object a db_object_t pointer.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \param[in] value_set a db_value_set_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_update(const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list);

/**
 * Delete an object or objects from the database.
 * \param[in] object a db_object_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_delete(const db_object_t* object, const db_clause_list_t* clause_list);

/**
 * Count objects from the database. Return the count in `count`.
 * \param[in] object a db_object_t pointer.
 * \param[in] join_list a db_join_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \param[out] count a size_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_object_count(const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list, size_t* count);

#endif
