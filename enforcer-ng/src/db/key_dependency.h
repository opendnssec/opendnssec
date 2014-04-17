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

#ifndef __key_dependency_h
#define __key_dependency_h

#ifdef __cplusplus
extern "C" {
#endif

struct key_dependency;
struct key_dependency_list;
typedef struct key_dependency key_dependency_t;
typedef struct key_dependency_list key_dependency_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "key_dependency_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A key dependency object.
 */
struct key_dependency {
    db_object_t* dbo;
    int id;
    char* from_key;
    char* to_key;
    unsigned int rrtype;
#include "key_dependency_struct_ext.h"
};

/**
 * Create a new key dependency object.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_dependency_t pointer or NULL on error.
 */
key_dependency_t* key_dependency_new(const db_connection_t* connection);

/**
 * Delete a key dependency object, this does not delete it from the database.
 * \param[in] key_dependency a key_dependency_t pointer.
 */
void key_dependency_free(key_dependency_t* key_dependency);

/**
 * Reset the content of a key dependency object making it as if its new. This does not change anything in the database.
 * \param[in] key_dependency a key_dependency_t pointer.
 */
void key_dependency_reset(key_dependency_t* key_dependency);

/**
 * Copy the content of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] key_dependency_copy a key_dependency_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_copy(key_dependency_t* key_dependency, const key_dependency_t* key_dependency_copy);

/**
 * Set the content of a key dependency object based on a database result.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_from_result(key_dependency_t* key_dependency, const db_result_t* result);

/**
 * Get the ID of a key dependency object. Undefined behavior if `key_dependency` is NULL.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return an integer.
 */
int key_dependency_id(const key_dependency_t* key_dependency);

/**
 * Get the from_key of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a character pointer or NULL on error or if no from_key has been set.
 */
const char* key_dependency_from_key(const key_dependency_t* key_dependency);

/**
 * Get the to_key of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a character pointer or NULL on error or if no to_key has been set.
 */
const char* key_dependency_to_key(const key_dependency_t* key_dependency);

/**
 * Get the rrtype of a key dependency object. Undefined behavior if `key_dependency` is NULL.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_dependency_rrtype(const key_dependency_t* key_dependency);

/**
 * Set the from_key of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] from_key_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_set_from_key(key_dependency_t* key_dependency, const char* from_key_text);

/**
 * Set the to_key of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] to_key_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_set_to_key(key_dependency_t* key_dependency, const char* to_key_text);

/**
 * Set the rrtype of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] rrtype an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_set_rrtype(key_dependency_t* key_dependency, unsigned int rrtype);

/**
 * Create a key dependency object in the database.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_create(key_dependency_t* key_dependency);

/**
 * Get a key dependency object from the database by an id specified in `id`.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_get_by_id(key_dependency_t* key_dependency, int id);

/**
 * Update a key dependency object in the database.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_update(key_dependency_t* key_dependency);

/**
 * Delete a key dependency object from the database.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_delete(key_dependency_t* key_dependency);

/**
 * A list of key dependency objects.
 */
struct key_dependency_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    key_dependency_t* key_dependency;
};

/**
 * Create a new key dependency object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_dependency_list_t pointer or NULL on error.
 */
key_dependency_list_t* key_dependency_list_new(const db_connection_t* connection);

/**
 * Delete a key dependency object list
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 */
void key_dependency_list_free(key_dependency_list_t* key_dependency_list);

/**
 * Get all key dependency objects.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_list_get(key_dependency_list_t* key_dependency_list);

/**
 * Get the first key dependency object in a key dependency object list. This will reset the position of the list.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a key_dependency_t pointer or NULL on error or if there are no
 * key dependency objects in the key dependency object list.
 */
const key_dependency_t* key_dependency_list_begin(key_dependency_list_t* key_dependency_list);

/**
 * Get the next key dependency object in a key dependency object list.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a key_dependency_t pointer or NULL on error or if there are no more
 * key dependency objects in the key dependency object list.
 */
const key_dependency_t* key_dependency_list_next(key_dependency_list_t* key_dependency_list);

#ifdef __cplusplus
}
#endif

#endif
