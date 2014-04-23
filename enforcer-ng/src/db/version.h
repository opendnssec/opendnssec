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

#ifndef __version_h
#define __version_h

#ifdef __cplusplus
extern "C" {
#endif

struct version;
struct version_list;
typedef struct version version_t;
typedef struct version_list version_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "version_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A version object.
 */
struct version {
    db_object_t* dbo;
    unsigned int version;
#include "version_struct_ext.h"
};

/**
 * Create a new version object.
 * \param[in] connection a db_connection_t pointer.
 * \return a version_t pointer or NULL on error.
 */
version_t* version_new(const db_connection_t* connection);

/**
 * Delete a version object, this does not delete it from the database.
 * \param[in] version a version_t pointer.
 */
void version_free(version_t* version);

/**
 * Reset the content of a version object making it as if its new. This does not change anything in the database.
 * \param[in] version a version_t pointer.
 */
void version_reset(version_t* version);

/**
 * Copy the content of a version object.
 * \param[in] version a version_t pointer.
 * \param[in] version_copy a version_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int version_copy(version_t* version, const version_t* version_copy);

/**
 * Set the content of a version object based on a database result.
 * \param[in] version a version_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int version_from_result(version_t* version, const db_result_t* result);

/**
 * Get the version of a version object. Undefined behavior if `version` is NULL.
 * \param[in] version a version_t pointer.
 * \return an unsigned integer.
 */
unsigned int version_version(const version_t* version);

/**
 * Set the version of a version object.
 * \param[in] version a version_t pointer.
 * \param[in] version an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int version_set_version(version_t* version, unsigned int version);

/**
 * Create a version object in the database.
 * \param[in] version a version_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int version_create(version_t* version);

/**
 * Update a version object in the database.
 * \param[in] version a version_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int version_update(version_t* version);

/**
 * Delete a version object from the database.
 * \param[in] version a version_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int version_delete(version_t* version);

/**
 * A list of version objects.
 */
struct version_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    version_t* version;
};

/**
 * Create a new version object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a version_list_t pointer or NULL on error.
 */
version_list_t* version_list_new(const db_connection_t* connection);

/**
 * Delete a version object list
 * \param[in] version_list a version_list_t pointer.
 */
void version_list_free(version_list_t* version_list);

/**
 * Get all version objects.
 * \param[in] version_list a version_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int version_list_get(version_list_t* version_list);

/**
 * Get the first version object in a version object list. This will reset the position of the list.
 * \param[in] version_list a version_list_t pointer.
 * \return a version_t pointer or NULL on error or if there are no
 * version objects in the version object list.
 */
const version_t* version_list_begin(version_list_t* version_list);

/**
 * Get the next version object in a version object list.
 * \param[in] version_list a version_list_t pointer.
 * \return a version_t pointer or NULL on error or if there are no more
 * version objects in the version object list.
 */
const version_t* version_list_next(version_list_t* version_list);

#ifdef __cplusplus
}
#endif

#endif
