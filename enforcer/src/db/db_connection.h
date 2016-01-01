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

#ifndef __db_connection_h
#define __db_connection_h

struct db_connection;
typedef struct db_connection db_connection_t;

#include "db_configuration.h"
#include "db_backend.h"
#include "db_result.h"
#include "db_object.h"
#include "db_join.h"
#include "db_clause.h"

/**
 * A database connection.
 */
struct db_connection {
    const db_configuration_list_t* configuration_list;
    db_backend_t* backend;
};

/**
 * Create a new database connection.
 * \return a db_connection_t pointer or NULL on error.
 */
db_connection_t* db_connection_new(void);

/**
 * Delete a database connection and the database backend within.
 * \param[in] connection a db_connection_t pointer.
 */
void db_connection_free(db_connection_t* connection);

/**
 * Set the database configuration list for a database connection.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] configuration_list a db_configuration_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_connection_set_configuration_list(db_connection_t* connection, const db_configuration_list_t* configuration_list);

/**
 * Setup the database connection, this verifies the information in the database
 * configuration list and allocated a database backend.
 * \param[in] connection a db_connection_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_connection_setup(db_connection_t* connection);

/**
 * Connect to the database.
 * \param[in] connection a db_connection_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_connection_connect(const db_connection_t* connection);

/**
 * Create an object in the database. The `object` refer to the database object
 * begin created, the `object_field_list` describes the fields that should be
 * set in the object and the `value_set` has the values for each field.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \param[in] value_set a db_value_set_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_connection_create(const db_connection_t* connection, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set);

/**
 * Read an object or objects from the database.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] join_list a db_join_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a db_result_list_t pointer or NULL on error or if no objects where
 * read.
 */
db_result_list_t* db_connection_read(const db_connection_t* connection, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list);

/**
 * Update an object or objects in the database.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \param[in] value_set a db_value_set_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_connection_update(const db_connection_t* connection, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list);

/**
 * Delete an object or objects from the database.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_connection_delete(const db_connection_t* connection, const db_object_t* object, const db_clause_list_t* clause_list);

/**
 * Count objects from the database. Return the count in `count`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] join_list a db_join_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \param[out] count a size_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_connection_count(const db_connection_t* connection, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list, size_t* count);

#endif
