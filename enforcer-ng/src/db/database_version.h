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

#ifndef __database_version_h
#define __database_version_h

#ifdef __cplusplus
extern "C" {
#endif

struct database_version;
struct database_version_list;
typedef struct database_version database_version_t;
typedef struct database_version_list database_version_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "database_version_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A database version object.
 */
struct database_version {
    db_object_t* dbo;
    db_value_t id;
    db_value_t rev;
    unsigned int version;
};

/**
 * Create a new database version object.
 * \param[in] connection a db_connection_t pointer.
 * \return a database_version_t pointer or NULL on error.
 */
database_version_t* database_version_new(const db_connection_t* connection);

/**
 * Delete a database version object, this does not delete it from the database.
 * \param[in] database_version a database_version_t pointer.
 */
void database_version_free(database_version_t* database_version);

/**
 * Reset the content of a database version object making it as if its new. This does not change anything in the database.
 * \param[in] database_version a database_version_t pointer.
 */
void database_version_reset(database_version_t* database_version);

/**
 * Copy the content of a database version object.
 * \param[in] database_version a database_version_t pointer.
 * \param[in] database_version_copy a database_version_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_copy(database_version_t* database_version, const database_version_t* database_version_copy);

/**
 * Compare two database version objects and return less than, equal to,
 * or greater than zero if A is found, respectively, to be less than, to match,
 * or be greater than B.
 * \param[in] database_version_a a database_version_t pointer.
 * \param[in] database_version_b a database_version_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_cmp(const database_version_t* database_version_a, const database_version_t* database_version_b);

/**
 * Set the content of a database version object based on a database result.
 * \param[in] database_version a database_version_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_from_result(database_version_t* database_version, const db_result_t* result);

/**
 * Get the id of a database version object.
 * \param[in] database_version a database_version_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* database_version_id(const database_version_t* database_version);

/**
 * Get the version of a database version object. Undefined behavior if `database_version` is NULL.
 * \param[in] database_version a database_version_t pointer.
 * \return an unsigned integer.
 */
unsigned int database_version_version(const database_version_t* database_version);

/**
 * Set the version of a database version object.
 * \param[in] database_version a database_version_t pointer.
 * \param[in] version an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_set_version(database_version_t* database_version, unsigned int version);

/**
 * Create a database version object in the database.
 * \param[in] database_version a database_version_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_create(database_version_t* database_version);

/**
 * Get a database version object from the database by a id specified in `id`.
 * \param[in] database_version a database_version_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_get_by_id(database_version_t* database_version, const db_value_t* id);

/**
 * Update a database version object in the database.
 * \param[in] database_version a database_version_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_update(database_version_t* database_version);

/**
 * Delete a database version object from the database.
 * \param[in] database_version a database_version_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_delete(database_version_t* database_version);

/**
 * A list of database version objects.
 */
struct database_version_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    database_version_t* database_version;
};

/**
 * Create a new database version object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a database_version_list_t pointer or NULL on error.
 */
database_version_list_t* database_version_list_new(const db_connection_t* connection);

/**
 * Delete a database version object list
 * \param[in] database_version_list a database_version_list_t pointer.
 */
void database_version_list_free(database_version_list_t* database_version_list);

/**
 * Get all database version objects.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_list_get(database_version_list_t* database_version_list);

/**
 * Get the first database version object in a database version object list. This will reset the position of the list.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return a database_version_t pointer or NULL on error or if there are no
 * database version objects in the database version object list.
 */
const database_version_t* database_version_list_begin(database_version_list_t* database_version_list);

/**
 * Get the next database version object in a database version object list.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return a database_version_t pointer or NULL on error or if there are no more
 * database version objects in the database version object list.
 */
const database_version_t* database_version_list_next(database_version_list_t* database_version_list);

#ifdef __cplusplus
}
#endif

#endif
