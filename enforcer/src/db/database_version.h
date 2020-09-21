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
extern database_version_t* database_version_new(const db_connection_t* connection);

/**
 * Delete a database version object, this does not delete it from the database.
 * \param[in] database_version a database_version_t pointer.
 */
extern void database_version_free(database_version_t* database_version);

/**
 * Set the content of a database version object based on a database result.
 * \param[in] database_version a database_version_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int database_version_from_result(database_version_t* database_version, const db_result_t* result);

/**
 * Get the version of a database version object. Undefined behavior if `database_version` is NULL.
 * \param[in] database_version a database_version_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int database_version_version(const database_version_t* database_version);

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
extern database_version_list_t* database_version_list_new(const db_connection_t* connection);

/**
 * Delete a database version object list.
 * \param[in] database_version_list a database_version_list_t pointer.
 */
extern void database_version_list_free(database_version_list_t* database_version_list);

/**
 * Get all database version objects.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int database_version_list_get(database_version_list_t* database_version_list);

/**
 * Get a new list with all database version objects.
 * \param[in] connection a db_connection_t pointer.
 * \return a database_version_list_t pointer or NULL on error.
 */
extern database_version_list_t* database_version_list_new_get(const db_connection_t* connection);

/**
 * Get the next database version object in a database version object list.
 * Ownership of this object is retained within the list and the object is only
 * valid until the next call to this function.
 * \param[in] database_version_list a database_version_list_t pointer.
 * \return a database_version_t pointer or NULL on error or if there are no more
 * database version objects in the database version object list.
 */
extern const database_version_t* database_version_list_next(database_version_list_t* database_version_list);

#endif
