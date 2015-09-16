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
#include "zone.h"
#include "key_data.h"

/**
 * A key dependency object.
 */
struct key_dependency {
    db_object_t* dbo;
    db_value_t id;
    db_value_t rev;
    db_value_t zone_id;
    const zone_t* associated_zone_id;
    zone_t* private_zone_id;
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
key_dependency_t* key_dependency_new(const db_connection_t* connection);

/**
 * Create a new key dependency object that is a copy of another key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a key_dependency_t pointer or NULL on error.
 */
key_dependency_t* key_dependency_new_copy(const key_dependency_t* key_dependency);

/**
 * Delete a key dependency object, this does not delete it from the database.
 * \param[in] key_dependency a key_dependency_t pointer.
 */
void key_dependency_free(key_dependency_t* key_dependency);

void key_dependency_alloc_nuke();

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
 * Compare two key dependency objects and return less than, equal to,
 * or greater than zero if A is found, respectively, to be less than, to match,
 * or be greater than B.
 * \param[in] key_dependency_a a key_dependency_t pointer.
 * \param[in] key_dependency_b a key_dependency_t pointer.
 * \return less than, equal to, or greater than zero if A is found, respectively,
 * to be less than, to match, or be greater than B.
 */
int key_dependency_cmp(const key_dependency_t* key_dependency_a, const key_dependency_t* key_dependency_b);

/**
 * Set the content of a key dependency object based on a database result.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_from_result(key_dependency_t* key_dependency, const db_result_t* result);

/**
 * Get the id of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* key_dependency_id(const key_dependency_t* key_dependency);

/**
 * Get the zone_id of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* key_dependency_zone_id(const key_dependency_t* key_dependency);

/**
 * Cache the zone_id object related to a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_cache_zone(key_dependency_t* key_dependency);

/**
 * Get the zone_id object related to a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a zone_t pointer or NULL on error or if no object could be found.
 */
const zone_t* key_dependency_zone(const key_dependency_t* key_dependency);

/**
 * Get the zone_id object related to a key dependency object.
 * The caller will be given ownership of this object and is responsible for freeing it.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a zone_t pointer or NULL on error or if no object could be found.
 */
zone_t* key_dependency_get_zone(const key_dependency_t* key_dependency);

/**
 * Get the from_key_data_id of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* key_dependency_from_key_data_id(const key_dependency_t* key_dependency);

/**
 * Cache the from_key_data_id object related to a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_cache_from_key_data(key_dependency_t* key_dependency);

/**
 * Get the from_key_data_id object related to a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a key_data_t pointer or NULL on error or if no object could be found.
 */
const key_data_t* key_dependency_from_key_data(const key_dependency_t* key_dependency);

/**
 * Get the from_key_data_id object related to a key dependency object.
 * The caller will be given ownership of this object and is responsible for freeing it.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a key_data_t pointer or NULL on error or if no object could be found.
 */
key_data_t* key_dependency_get_from_key_data(const key_dependency_t* key_dependency);

/**
 * Get the to_key_data_id of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* key_dependency_to_key_data_id(const key_dependency_t* key_dependency);

/**
 * Cache the to_key_data_id object related to a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_cache_to_key_data(key_dependency_t* key_dependency);

/**
 * Get the to_key_data_id object related to a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a key_data_t pointer or NULL on error or if no object could be found.
 */
const key_data_t* key_dependency_to_key_data(const key_dependency_t* key_dependency);

/**
 * Get the to_key_data_id object related to a key dependency object.
 * The caller will be given ownership of this object and is responsible for freeing it.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a key_data_t pointer or NULL on error or if no object could be found.
 */
key_data_t* key_dependency_get_to_key_data(const key_dependency_t* key_dependency);

/**
 * Get the type of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a key_dependency_type_t which may be KEY_DEPENDENCY_TYPE_INVALID on error or if no type has been set.
 */
key_dependency_type_t key_dependency_type(const key_dependency_t* key_dependency);

/**
 * Get the type as text of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return a character pointer or NULL on error or if no type has been set.
 */
const char* key_dependency_type_text(const key_dependency_t* key_dependency);

/**
 * Set the zone_id of a key dependency object. If this fails the original value may have been lost.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] zone_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_set_zone_id(key_dependency_t* key_dependency, const db_value_t* zone_id);

/**
 * Set the from_key_data_id of a key dependency object. If this fails the original value may have been lost.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] from_key_data_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_set_from_key_data_id(key_dependency_t* key_dependency, const db_value_t* from_key_data_id);

/**
 * Set the to_key_data_id of a key dependency object. If this fails the original value may have been lost.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] to_key_data_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_set_to_key_data_id(key_dependency_t* key_dependency, const db_value_t* to_key_data_id);

/**
 * Set the type of a key dependency object.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] type a key_dependency_type_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_set_type(key_dependency_t* key_dependency, key_dependency_type_t type);

/**
 * Set the type of a key dependency object from text.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] type a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_set_type_text(key_dependency_t* key_dependency, const char* type);

/**
 * Create a clause for zone_id of a key dependency object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] zone_id a db_value_t pointer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* key_dependency_zone_id_clause(db_clause_list_t* clause_list, const db_value_t* zone_id);

/**
 * Create a clause for from_key_data_id of a key dependency object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] from_key_data_id a db_value_t pointer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* key_dependency_from_key_data_id_clause(db_clause_list_t* clause_list, const db_value_t* from_key_data_id);

/**
 * Create a clause for to_key_data_id of a key dependency object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] to_key_data_id a db_value_t pointer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* key_dependency_to_key_data_id_clause(db_clause_list_t* clause_list, const db_value_t* to_key_data_id);

/**
 * Create a clause for type of a key dependency object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] type a key_dependency_type_t.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* key_dependency_type_clause(db_clause_list_t* clause_list, key_dependency_type_t type);

/**
 * Create a key dependency object in the database.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_create(key_dependency_t* key_dependency);

/**
 * Get a key dependency object from the database by a id specified in `id`.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_get_by_id(key_dependency_t* key_dependency, const db_value_t* id);

/**
 * Get a new key dependency object from the database by a id specified in `id`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return a key_dependency_t pointer or NULL on error or if it does not exist.
 */
key_dependency_t* key_dependency_new_get_by_id(const db_connection_t* connection, const db_value_t* id);

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
 * Count the number of key dependency objects in the database, if a selection of
 * objects should be counted then it can be limited by a database clause list
 * otherwise all objects are counted.
 * \param[in] key_dependency a key_dependency_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer or NULL if all objects.
 * \param[out] count a size_t pointer to where the count should be stored.
 * should be counted.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_count(key_dependency_t* key_dependency, db_clause_list_t* clause_list, size_t* count);

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
    zone_list_t* zone_id_list;
    key_data_list_t* from_key_data_id_list;
    key_data_list_t* to_key_data_id_list;
};

/**
 * Create a new key dependency object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_dependency_list_t pointer or NULL on error.
 */
key_dependency_list_t* key_dependency_list_new(const db_connection_t* connection);

/**
 * Create a new key dependency object list that is a copy of another.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a key_dependency_list_t pointer or NULL on error.
 */
key_dependency_list_t* key_dependency_list_new_copy(const key_dependency_list_t* key_dependency_copy);

/**
 * Specify that objects should be stored within the list as they are fetch,
 * this is optimal if the list is to be iterated over more then once.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_list_object_store(key_dependency_list_t* key_dependency_list);

/**
 * Specify that the list should also fetch associated objects in a more optimal
 * way then fetching them for each individual object later on. This also forces
 * the list to store all objects (see key_dependency_list_object_store()).
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_list_associated_fetch(key_dependency_list_t* key_dependency_list);

/**
 * Delete a key dependency object list.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 */
void key_dependency_list_free(key_dependency_list_t* key_dependency_list);

void key_dependency_list_alloc_nuke();

/**
 * Copy the content of another key dependency object list.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \param[in] from_key_dependency_list a key_dependency_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_list_copy(key_dependency_list_t* key_dependency_list, const key_dependency_list_t* from_key_dependency_list);

/**
 * Get all key dependency objects.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_list_get(key_dependency_list_t* key_dependency_list);

/**
 * Get a new list with all key dependency objects.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_dependency_list_t pointer or NULL on error.
 */
key_dependency_list_t* key_dependency_list_new_get(const db_connection_t* connection);

/**
 * Get key dependency objects from the database by a clause list.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_list_get_by_clauses(key_dependency_list_t* key_dependency_list, const db_clause_list_t* clause_list);

/**
 * Get a new list of key dependency objects from the database by a clause list.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a key_dependency_list_t pointer or NULL on error.
 */
key_dependency_list_t* key_dependency_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list);

/**
 * Get key dependency objects from the database by a zone_id specified in `zone_id`.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \param[in] zone_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_list_get_by_zone_id(key_dependency_list_t* key_dependency_list, const db_value_t* zone_id);

/**
 * Get a new list of key dependency objects from the database by a zone_id specified in `zone_id`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] zone_id a db_value_t pointer.
 * \return a key_dependency_list_t pointer or NULL on error.
 */
key_dependency_list_t* key_dependency_list_new_get_by_zone_id(const db_connection_t* connection, const db_value_t* zone_id);

/**
 * Get key dependency objects from the database by a from_key_data_id specified in `from_key_data_id`.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \param[in] from_key_data_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_list_get_by_from_key_data_id(key_dependency_list_t* key_dependency_list, const db_value_t* from_key_data_id);

/**
 * Get a new list of key dependency objects from the database by a from_key_data_id specified in `from_key_data_id`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] from_key_data_id a db_value_t pointer.
 * \return a key_dependency_list_t pointer or NULL on error.
 */
key_dependency_list_t* key_dependency_list_new_get_by_from_key_data_id(const db_connection_t* connection, const db_value_t* from_key_data_id);

/**
 * Get key dependency objects from the database by a to_key_data_id specified in `to_key_data_id`.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \param[in] to_key_data_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_dependency_list_get_by_to_key_data_id(key_dependency_list_t* key_dependency_list, const db_value_t* to_key_data_id);

/**
 * Get a new list of key dependency objects from the database by a to_key_data_id specified in `to_key_data_id`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] to_key_data_id a db_value_t pointer.
 * \return a key_dependency_list_t pointer or NULL on error.
 */
key_dependency_list_t* key_dependency_list_new_get_by_to_key_data_id(const db_connection_t* connection, const db_value_t* to_key_data_id);

/**
 * Get the first key dependency object in a key dependency object list and reset the
 * position of the list.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a key_dependency_t pointer or NULL on error or if there are no
 * key dependency objects in the key dependency object list.
 */
const key_dependency_t* key_dependency_list_begin(key_dependency_list_t* key_dependency_list);

/**
 * Get the first key dependency object in a key dependency object list and reset the
 * position of the list. The caller will be given ownership of this object and
 * is responsible for freeing it.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a key_dependency_t pointer or NULL on error or if there are no
 * key dependency objects in the key dependency object list.
 */
key_dependency_t* key_dependency_list_get_begin(key_dependency_list_t* key_dependency_list);

/**
 * Get the next key dependency object in a key dependency object list.
 * Ownership of this object is retained within the list and the object is only
 * valid until the next call to this function.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a key_dependency_t pointer or NULL on error or if there are no more
 * key dependency objects in the key dependency object list.
 */
const key_dependency_t* key_dependency_list_next(key_dependency_list_t* key_dependency_list);

/**
 * Get the next key dependency object in a key dependency object list.
 * The caller will be given ownership of this object and is responsible for
 * freeing it.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a key_dependency_t pointer or NULL on error or if there are no more
 * key dependency objects in the key dependency object list.
 */
key_dependency_t* key_dependency_list_get_next(key_dependency_list_t* key_dependency_list);

/**
 * Get the size of a key dependency object list.
 * \param[in] key_dependency_list a key_dependency_list_t pointer.
 * \return a size_t with the size of the list or zero on error, if the list is
 * empty or if the backend does not support returning the size.
 */
size_t key_dependency_list_size(key_dependency_list_t* key_dependency_list);

#endif
