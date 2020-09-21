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

#include "db_object.h"

struct key_dependency;
struct key_dependency_list;
typedef struct key_dependency key_dependency_t;
typedef struct key_dependency_list key_dependency_list_t;

typedef enum key_dependency_type {
    KEY_DEPENDENCY_TYPE_INVALID = -1,
    KEY_DEPENDENCY_TYPE_DS = 0,
    KEY_DEPENDENCY_TYPE_RRSIG = 1,
    KEY_DEPENDENCY_TYPE_DNSKEY = 2,
    KEY_DEPENDENCY_TYPE_RRSIGDNSKEY = 3
} key_dependency_type_t;
extern const db_enum_t key_dependency_enum_set_type[];

#include "key_dependency_ext.h"
#include "zone_db.h"
#include "key_data.h"

/**
 * A key dependency object.
 */
struct key_dependency {
    db_object_t* dbo;
    db_value_t id;
    db_value_t rev;
    db_value_t zone_id;
    const zone_db_t* associated_zone_id;
    zone_db_t* private_zone_id;
    db_value_t from_key_data_id;
    const key_data_t* associated_from_key_data_id;
    key_data_t* private_from_key_data_id;
    db_value_t to_key_data_id;
    const key_data_t* associated_to_key_data_id;
    key_data_t* private_to_key_data_id;
    key_dependency_type_t type;
};

/**
 * Create a new key dependency object.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_dependency_t pointer or NULL on error.
 */
extern key_dependency_t* key_dependency_new(const db_connection_t* connection);

/**
 * Create a new key dependency object that is a copy of another key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a key_dependency_t pointer or NULL on error.
 */
extern key_dependency_t* key_dependency_new_copy(const key_dependency_t* key_dependency);

/**
 * Delete a key dependency object, this does not delete it from the database.
 * \param[in] key_dependency a key_dependency_t pointer.
 */
extern void key_dependency_free(key_dependency_t* key_dependency);

/**
 * Copy the content of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] key_dependency_copy a key_dependency_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_copy(key_dependency_t* key_dependency, const key_dependency_t* key_dependency_copy);

/**
 * Set the content of a key dependency object based on a database result.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_from_result(key_dependency_t* key_dependency, const db_result_t* result);

/**
 * Get the zone_id of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
extern const db_value_t* key_dependency_zone_id(const key_dependency_t* key_dependency);

/**
 * Get the from_key_data_id of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
extern const db_value_t* key_dependency_from_key_data_id(const key_dependency_t* key_dependency);

/**
 * Get the from_key_data_id object related to a key dependency object.
 * The caller will be given ownership of this object and is responsible for freeing it.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a key_data_t pointer or NULL on error or if no object could be found.
 */
extern key_data_t* key_dependency_get_from_key_data(const key_dependency_t* key_dependency);

/**
 * Get the to_key_data_id of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
extern const db_value_t* key_dependency_to_key_data_id(const key_dependency_t* key_dependency);

/**
 * Get the type of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a key_dependency_type_t which may be KEY_DEPENDENCY_TYPE_INVALID on error or if no type has been set.
 */
extern key_dependency_type_t key_dependency_type(const key_dependency_t* key_dependency);

/**
 * Set the zone_id of a key dependency object. If this fails the original value may have been lost.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] zone_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_set_zone_id(key_dependency_t* key_dependency, const db_value_t* zone_id);

/**
 * Set the from_key_data_id of a key dependency object. If this fails the original value may have been lost.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] from_key_data_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_set_from_key_data_id(key_dependency_t* key_dependency, const db_value_t* from_key_data_id);

/**
 * Set the to_key_data_id of a key dependency object. If this fails the original value may have been lost.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] to_key_data_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_set_to_key_data_id(key_dependency_t* key_dependency, const db_value_t* to_key_data_id);

/**
 * Set the type of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] type a key_dependency_type_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_set_type(key_dependency_t* key_dependency, key_dependency_type_t type);

/**
 * Create a key dependency object in the database.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_create(key_dependency_t* key_dependency);

/**
 * Get a key dependency object from the database by a id specified in `id`.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_get_by_id(key_dependency_t* key_dependency, const db_value_t* id);

/**
 * Delete a key dependency object from the database.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_delete(key_dependency_t* key_dependency);

/**
 * A list of key dependency objects.
 */
struct key_dependency_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    key_dependency_t* key_dependency;
    int object_store;
    key_dependency_t** object_list;
    size_t object_list_size;
    size_t object_list_position;
    int object_list_first;
    int associated_fetch;
    zone_list_db_t* zone_id_list;
    key_data_list_t* from_key_data_id_list;
    key_data_list_t* to_key_data_id_list;
};

/**
 * Create a new key dependency object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_dependency_list_t pointer or NULL on error.
 */
extern key_dependency_list_t* key_dependency_list_new(const db_connection_t* connection);

/**
 * Create a new key dependency object list that is a copy of another.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a key_dependency_list_t pointer or NULL on error.
 */
extern key_dependency_list_t* key_dependency_list_new_copy(const key_dependency_list_t* key_dependency_copy);

/**
 * Specify that objects should be stored within the list as they are fetch,
 * this is optimal if the list is to be iterated over more then once.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_list_object_store(key_dependency_list_t* key_dependency_list);

/**
 * Delete a key dependency object list.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 */
extern void key_dependency_list_free(key_dependency_list_t* key_dependency_list);

/**
 * Copy the content of another key dependency object list.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \param[in] from_key_dependency_list a key_dependency_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_list_copy(key_dependency_list_t* key_dependency_list, const key_dependency_list_t* from_key_dependency_list);

/**
 * Get key dependency objects from the database by a clause list.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_list_get_by_clauses(key_dependency_list_t* key_dependency_list, const db_clause_list_t* clause_list);

/**
 * Get key dependency objects from the database by a zone_id specified in `zone_id`.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \param[in] zone_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_dependency_list_get_by_zone_id(key_dependency_list_t* key_dependency_list, const db_value_t* zone_id);

/**
 * Get a new list of key dependency objects from the database by a zone_id specified in `zone_id`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] zone_id a db_value_t pointer.
 * \return a key_dependency_list_t pointer or NULL on error.
 */
extern key_dependency_list_t* key_dependency_list_new_get_by_zone_id(const db_connection_t* connection, const db_value_t* zone_id);

/**
 * Get the first key dependency object in a key dependency object list and reset the
 * position of the list.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a key_dependency_t pointer or NULL on error or if there are no
 * key dependency objects in the key dependency object list.
 */
extern const key_dependency_t* key_dependency_list_begin(key_dependency_list_t* key_dependency_list);

/**
 * Get the first key dependency object in a key dependency object list and reset the
 * position of the list. The caller will be given ownership of this object and
 * is responsible for freeing it.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a key_dependency_t pointer or NULL on error or if there are no
 * key dependency objects in the key dependency object list.
 */
extern key_dependency_t* key_dependency_list_get_begin(key_dependency_list_t* key_dependency_list);

/**
 * Get the next key dependency object in a key dependency object list.
 * Ownership of this object is retained within the list and the object is only
 * valid until the next call to this function.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a key_dependency_t pointer or NULL on error or if there are no more
 * key dependency objects in the key dependency object list.
 */
extern const key_dependency_t* key_dependency_list_next(key_dependency_list_t* key_dependency_list);

/**
 * Get the next key dependency object in a key dependency object list.
 * The caller will be given ownership of this object and is responsible for
 * freeing it.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a key_dependency_t pointer or NULL on error or if there are no more
 * key dependency objects in the key dependency object list.
 */
extern key_dependency_t* key_dependency_list_get_next(key_dependency_list_t* key_dependency_list);

/**
 * Get the size of a key dependency object list.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a size_t with the size of the list or zero on error, if the list is
 * empty or if the backend does not support returning the size.
 */
extern size_t key_dependency_list_size(key_dependency_list_t* key_dependency_list);

#endif
