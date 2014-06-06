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

#ifndef __key_state_h
#define __key_state_h

#include "db_object.h"

#ifdef __cplusplus
extern "C" {
#endif

struct key_state;
struct key_state_list;
typedef struct key_state key_state_t;
typedef struct key_state_list key_state_list_t;

typedef enum key_state_type {
    KEY_STATE_TYPE_INVALID = -1,
    KEY_STATE_TYPE_DS = 0,
    KEY_STATE_TYPE_RRSIG = 1,
    KEY_STATE_TYPE_DNSKEY = 2,
    KEY_STATE_TYPE_RRSIGDNSKEY = 3
} key_state_type_t;
extern const db_enum_t key_state_enum_set_type[];

typedef enum key_state_state {
    KEY_STATE_STATE_INVALID = -1,
    KEY_STATE_STATE_HIDDEN = 0,
    KEY_STATE_STATE_RUMOURED = 1,
    KEY_STATE_STATE_OMNIPRESENT = 2,
    KEY_STATE_STATE_UNRETENTIVE = 3,
    KEY_STATE_STATE_NA = 4
} key_state_state_t;
extern const db_enum_t key_state_enum_set_state[];

#ifdef __cplusplus
}
#endif

#include "key_state_ext.h"
#include "key_data.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A key state object.
 */
struct key_state {
    db_object_t* dbo;
    db_value_t id;
    db_value_t rev;
    db_value_t key_data_id;
    key_state_type_t type;
    key_state_state_t state;
    unsigned int last_change;
    unsigned int minimize;
    unsigned int ttl;
};

/**
 * Create a new key state object.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_state_t pointer or NULL on error.
 */
key_state_t* key_state_new(const db_connection_t* connection);

/**
 * Create a new key state object that is a copy of another key state object.
 * \param[in] key_state a key_state_t pointer.
 * \return a key_state_t pointer or NULL on error.
 */
key_state_t* key_state_new_copy(const key_state_t* key_state);

/**
 * Delete a key state object, this does not delete it from the database.
 * \param[in] key_state a key_state_t pointer.
 */
void key_state_free(key_state_t* key_state);

/**
 * Reset the content of a key state object making it as if its new. This does not change anything in the database.
 * \param[in] key_state a key_state_t pointer.
 */
void key_state_reset(key_state_t* key_state);

/**
 * Copy the content of a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \param[in] key_state_copy a key_state_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_copy(key_state_t* key_state, const key_state_t* key_state_copy);

/**
 * Compare two key state objects and return less than, equal to,
 * or greater than zero if A is found, respectively, to be less than, to match,
 * or be greater than B.
 * \param[in] key_state_a a key_state_t pointer.
 * \param[in] key_state_b a key_state_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_cmp(const key_state_t* key_state_a, const key_state_t* key_state_b);

/**
 * Set the content of a key state object based on a database result.
 * \param[in] key_state a key_state_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_from_result(key_state_t* key_state, const db_result_t* result);

/**
 * Get the id of a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* key_state_id(const key_state_t* key_state);

/**
 * Get the key_data_id of a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* key_state_key_data_id(const key_state_t* key_state);

/**
 * Get the key_data_id object related to a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \return a key_data_t pointer or NULL on error or if no object could be found.
 */
key_data_t* key_state_get_key_data(const key_state_t* key_state);

/**
 * Get the type of a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \return a key_state_type_t which may be KEY_STATE_TYPE_INVALID on error or if no type has been set.
 */
key_state_type_t key_state_type(const key_state_t* key_state);

/**
 * Get the type as text of a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \return a character pointer or NULL on error or if no type has been set.
 */
const char* key_state_type_text(const key_state_t* key_state);

/**
 * Get the state of a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \return a key_state_state_t which may be KEY_STATE_STATE_INVALID on error or if no state has been set.
 */
key_state_state_t key_state_state(const key_state_t* key_state);

/**
 * Get the state as text of a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \return a character pointer or NULL on error or if no state has been set.
 */
const char* key_state_state_text(const key_state_t* key_state);

/**
 * Get the last_change of a key state object. Undefined behavior if `key_state` is NULL.
 * \param[in] key_state a key_state_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_state_last_change(const key_state_t* key_state);

/**
 * Get the minimize of a key state object. Undefined behavior if `key_state` is NULL.
 * \param[in] key_state a key_state_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_state_minimize(const key_state_t* key_state);

/**
 * Get the ttl of a key state object. Undefined behavior if `key_state` is NULL.
 * \param[in] key_state a key_state_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_state_ttl(const key_state_t* key_state);

/**
 * Set the key_data_id of a key state object. If this fails the original value may have been lost.
 * \param[in] key_state a key_state_t pointer.
 * \param[in] key_data_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_set_key_data_id(key_state_t* key_state, const db_value_t* key_data_id);

/**
 * Set the type of a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \param[in] type a key_state_type_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_set_type(key_state_t* key_state, key_state_type_t type);

/**
 * Set the type of a key state object from text.
 * \param[in] key_state a key_state_t pointer.
 * \param[in] type a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_set_type_text(key_state_t* key_state, const char* type);

/**
 * Set the state of a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \param[in] state a key_state_state_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_set_state(key_state_t* key_state, key_state_state_t state);

/**
 * Set the state of a key state object from text.
 * \param[in] key_state a key_state_t pointer.
 * \param[in] state a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_set_state_text(key_state_t* key_state, const char* state);

/**
 * Set the last_change of a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \param[in] last_change an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_set_last_change(key_state_t* key_state, unsigned int last_change);

/**
 * Set the minimize of a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \param[in] minimize an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_set_minimize(key_state_t* key_state, unsigned int minimize);

/**
 * Set the ttl of a key state object.
 * \param[in] key_state a key_state_t pointer.
 * \param[in] ttl an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_set_ttl(key_state_t* key_state, unsigned int ttl);

/**
 * Create a clause for key_data_id of a key state object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] key_data_id a db_value_t pointer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* key_state_key_data_id_clause(db_clause_list_t* clause_list, const db_value_t* key_data_id);

/**
 * Create a clause for type of a key state object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] type a key_state_type_t.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* key_state_type_clause(db_clause_list_t* clause_list, key_state_type_t type);

/**
 * Create a clause for state of a key state object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] state a key_state_state_t.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* key_state_state_clause(db_clause_list_t* clause_list, key_state_state_t state);

/**
 * Create a clause for last_change of a key state object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] last_change an unsigned integer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* key_state_last_change_clause(db_clause_list_t* clause_list, unsigned int last_change);

/**
 * Create a clause for minimize of a key state object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] minimize an unsigned integer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* key_state_minimize_clause(db_clause_list_t* clause_list, unsigned int minimize);

/**
 * Create a clause for ttl of a key state object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] ttl an unsigned integer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* key_state_ttl_clause(db_clause_list_t* clause_list, unsigned int ttl);

/**
 * Create a key state object in the database.
 * \param[in] key_state a key_state_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_create(key_state_t* key_state);

/**
 * Get a key state object from the database by a id specified in `id`.
 * \param[in] key_state a key_state_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_get_by_id(key_state_t* key_state, const db_value_t* id);

/**
 * Get a new key state object from the database by a id specified in `id`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return a key_state_t pointer or NULL on error or if it does not exist.
 */
key_state_t* key_state_new_get_by_id(const db_connection_t* connection, const db_value_t* id);

/**
 * Update a key state object in the database.
 * \param[in] key_state a key_state_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_update(key_state_t* key_state);

/**
 * Delete a key state object from the database.
 * \param[in] key_state a key_state_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_delete(key_state_t* key_state);

/**
 * Count the number of key state objects in the database, if a selection of
 * objects should be counted then it can be limited by a database clause list
 * otherwise all objects are counted.
 * \param[in] key_state a key_state_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer or NULL if all objects.
 * \param[out] count a size_t pointer to where the count should be stored.
 * should be counted.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_count(key_state_t* key_state, db_clause_list_t* clause_list, size_t* count);

/**
 * A list of key state objects.
 */
struct key_state_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    key_state_t* key_state;
};

/**
 * Create a new key state object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_state_list_t pointer or NULL on error.
 */
key_state_list_t* key_state_list_new(const db_connection_t* connection);

/**
 * Delete a key state object list
 * \param[in] key_state_list a key_state_list_t pointer.
 */
void key_state_list_free(key_state_list_t* key_state_list);

/**
 * Get all key state objects.
 * \param[in] key_state_list a key_state_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_list_get(key_state_list_t* key_state_list);

/**
 * Get a new list with all key state objects.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_state_list_t pointer or NULL on error.
 */
key_state_list_t* key_state_list_new_get(const db_connection_t* connection);

/**
 * Get key state objects from the database by a clause list.
 * \param[in] key_state_list a key_state_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_list_get_by_clauses(key_state_list_t* key_state_list, const db_clause_list_t* clause_list);

/**
 * Get a new list of key state objects from the database by a clause list.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a key_state_list_t pointer or NULL on error.
 */
key_state_list_t* key_state_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list);

/**
 * Get key state objects from the database by a key_data_id specified in `key_data_id`.
 * \param[in] key_state_list a key_state_list_t pointer.
 * \param[in] key_data_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_list_get_by_key_data_id(key_state_list_t* key_state_list, const db_value_t* key_data_id);

/**
 * Get a new list of key state objects from the database by a key_data_id specified in `key_data_id`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] key_data_id a db_value_t pointer.
 * \return a key_state_list_t pointer or NULL on error.
 */
key_state_list_t* key_state_list_new_get_by_key_data_id(const db_connection_t* connection, const db_value_t* key_data_id);

/**
 * Get the first key state object in a key state object list and reset the
 * position of the list. This will not work unless key_state_list_fetch_all()
 * has been called.
 * \param[in] key_state_list a key_state_list_t pointer.
 * \return a key_state_t pointer or NULL on error or if there are no
 * key state objects in the key state object list.
 */
const key_state_t* key_state_list_begin(key_state_list_t* key_state_list);

/**
 * Get the first key state object in a key state object list and reset the
 * position of the list. This will not work unless key_state_list_fetch_all()
 * has been called. The caller will be given ownership of this object and is
 * responsible for freeing it.
 * \param[in] key_state_list a key_state_list_t pointer.
 * \return a key_state_t pointer or NULL on error or if there are no
 * key state objects in the key state object list.
 */
key_state_t* key_state_list_get_begin(key_state_list_t* key_state_list);

/**
 * Get the next key state object in a key state object list.
 * Ownership of this object is retained within the list and the object is only
 * valid until the next call to this function.
 * \param[in] key_state_list a key_state_list_t pointer.
 * \return a key_state_t pointer or NULL on error or if there are no more
 * key state objects in the key state object list.
 */
const key_state_t* key_state_list_next(key_state_list_t* key_state_list);

/**
 * Get the next key state object in a key state object list.
 * The caller will be given ownership of this object and is responsible for
 * freeing it.
 * \param[in] key_state_list a key_state_list_t pointer.
 * \return a key_state_t pointer or NULL on error or if there are no more
 * key state objects in the key state object list.
 */
key_state_t* key_state_list_get_next(key_state_list_t* key_state_list);

/**
 * Make sure that all objects in this key state object list is loaded into memory
 * so that key_state_list_begin()/key_state_list_get_begin() can be used to
 * iterate over the list multiple times.
 * \param[in] key_state_list a key_state_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_state_list_fetch_all(key_state_list_t* key_state_list);

/**
 * Get the size of a key state object list.
 * \param[in] key_state_list a key_state_list_t pointer.
 * \return a size_t with the size of the list or zero on error, if the list is
 * empty or if the backend does not support returning the size. The size can be
 * guaranteed to be returned by first calling key_state_list_fetch_all().
 */
size_t key_state_list_size(key_state_list_t* key_state_list);

#ifdef __cplusplus
}
#endif

#endif