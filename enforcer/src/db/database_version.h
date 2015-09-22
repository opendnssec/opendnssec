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

#include "db_object.h"

struct database_version;
struct database_version_list;
typedef struct database_version database_version_t;
typedef struct database_version_list database_version_list_t;

#include "database_version_ext.h"

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
 * Create a new database version object that is a copy of another database version object.
 * \param[in] database_version a database_version_t pointer.
 * \return a database_version_t pointer or NULL on error.
 */
database_version_t* database_version_new_copy(const database_version_t* database_version);

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
 * \return less than, equal to, or greater than zero if A is found, respectively,
 * to be less than, to match, or be greater than B.
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
 * Create a clause for version of a database version object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] version an unsigned integer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* database_version_version_clause(db_clause_list_t* clause_list, unsigned int version);

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
 * Get a new database version object from the database by a id specified in `id`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return a database_version_t pointer or NULL on error or if it does not exist.
 */
database_version_t* database_version_new_get_by_id(const db_connection_t* connection, const db_value_t* id);

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
 * Count the number of database version objects in the database, if a selection of
 * objects should be counted then it can be limited by a database clause list
 * otherwise all objects are counted.
 * \param[in] database_version a database_version_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer or NULL if all objects.
 * \param[out] count a size_t pointer to where the count should be stored.
 * should be counted.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_count(database_version_t* database_version, db_clause_list_t* clause_list, size_t* count);

/**
 * A list of database version objects.
 */
struct database_version_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    database_version_t* database_version;
    int object_store;
    database_version_t** object_list;
    size_t object_list_size;
    size_t object_list_position;
    int object_list_first;
    int associated_fetch;
};

/**
 * Create a new database version object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a database_version_list_t pointer or NULL on error.
 */
database_version_list_t* database_version_list_new(const db_connection_t* connection);

/**
 * Create a new database version object list that is a copy of another.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return a database_version_list_t pointer or NULL on error.
 */
database_version_list_t* database_version_list_new_copy(const database_version_list_t* database_version_copy);

/**
 * Specify that objects should be stored within the list as they are fetch,
 * this is optimal if the list is to be iterated over more then once.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_list_object_store(database_version_list_t* database_version_list);

/**
 * Specify that the list should also fetch associated objects in a more optimal
 * way then fetching them for each individual object later on. This also forces
 * the list to store all objects (see database_version_list_object_store()).
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_list_associated_fetch(database_version_list_t* database_version_list);

/**
 * Delete a database version object list.
 * \param[in] database_version_list a database_version_list_t pointer.
 */
void database_version_list_free(database_version_list_t* database_version_list);

/**
 * free global allocator. 
 * database_version_list_free MUST be called for all its contents.
 */
/**
 * Copy the content of another database version object list.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \param[in] from_database_version_list a database_version_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_list_copy(database_version_list_t* database_version_list, const database_version_list_t* from_database_version_list);

/**
 * Get all database version objects.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_list_get(database_version_list_t* database_version_list);

/**
 * Get a new list with all database version objects.
 * \param[in] connection a db_connection_t pointer.
 * \return a database_version_list_t pointer or NULL on error.
 */
database_version_list_t* database_version_list_new_get(const db_connection_t* connection);

/**
 * Get database version objects from the database by a clause list.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int database_version_list_get_by_clauses(database_version_list_t* database_version_list, const db_clause_list_t* clause_list);

/**
 * Get a new list of database version objects from the database by a clause list.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a database_version_list_t pointer or NULL on error.
 */
database_version_list_t* database_version_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list);

/**
 * Get the first database version object in a database version object list and reset the
 * position of the list.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return a database_version_t pointer or NULL on error or if there are no
 * database version objects in the database version object list.
 */
const database_version_t* database_version_list_begin(database_version_list_t* database_version_list);

/**
 * Get the first database version object in a database version object list and reset the
 * position of the list. The caller will be given ownership of this object and
 * is responsible for freeing it.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return a database_version_t pointer or NULL on error or if there are no
 * database version objects in the database version object list.
 */
database_version_t* database_version_list_get_begin(database_version_list_t* database_version_list);

/**
 * Get the next database version object in a database version object list.
 * Ownership of this object is retained within the list and the object is only
 * valid until the next call to this function.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return a database_version_t pointer or NULL on error or if there are no more
 * database version objects in the database version object list.
 */
const database_version_t* database_version_list_next(database_version_list_t* database_version_list);

/**
 * Get the next database version object in a database version object list.
 * The caller will be given ownership of this object and is responsible for
 * freeing it.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return a database_version_t pointer or NULL on error or if there are no more
 * database version objects in the database version object list.
 */
database_version_t* database_version_list_get_next(database_version_list_t* database_version_list);

/**
 * Get the size of a database version object list.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return a size_t with the size of the list or zero on error, if the list is
 * empty or if the backend does not support returning the size.
 */
size_t database_version_list_size(database_version_list_t* database_version_list);

#endif
