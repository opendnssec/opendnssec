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

#ifndef __key_data_h
#define __key_data_h

#include "db_object.h"

struct key_data;
struct key_data_list;
typedef struct key_data key_data_t;
typedef struct key_data_list key_data_list_t;

typedef enum key_data_role {
    KEY_DATA_ROLE_INVALID = -1,
    KEY_DATA_ROLE_KSK = 1,
    KEY_DATA_ROLE_ZSK = 2,
    KEY_DATA_ROLE_CSK = 3
} key_data_role_t;
extern const db_enum_t key_data_enum_set_role[];

#define KEY_DATA_ROLE_SEP(role) ((role) == KEY_DATA_ROLE_KSK || (role) == KEY_DATA_ROLE_CSK)

typedef enum key_data_ds_at_parent {
    KEY_DATA_DS_AT_PARENT_INVALID = -1,
    KEY_DATA_DS_AT_PARENT_UNSUBMITTED = 0,
    KEY_DATA_DS_AT_PARENT_SUBMIT = 1,
    KEY_DATA_DS_AT_PARENT_SUBMITTED = 2,
    KEY_DATA_DS_AT_PARENT_SEEN = 3,
    KEY_DATA_DS_AT_PARENT_RETRACT = 4,
    KEY_DATA_DS_AT_PARENT_RETRACTED = 5
} key_data_ds_at_parent_t;
extern const db_enum_t key_data_enum_set_ds_at_parent[];

#include "key_data_ext.h"
#include "zone_db.h"
#include "hsm_key.h"

/**
 * A key data object.
 */
struct key_data {
    db_object_t* dbo;
    db_value_t id;
    db_value_t rev;
    db_value_t zone_id;
    const zone_db_t* associated_zone_id;
    zone_db_t* private_zone_id;
    db_value_t hsm_key_id;
    const hsm_key_t* associated_hsm_key_id;
    hsm_key_t* private_hsm_key_id;
    unsigned int algorithm;
    unsigned int inception;
    key_data_role_t role;
    unsigned int introducing;
    unsigned int should_revoke;
    unsigned int standby;
    unsigned int active_zsk;
    unsigned int publish;
    unsigned int active_ksk;
    key_data_ds_at_parent_t ds_at_parent;
    unsigned int keytag;
    unsigned int minimize;
    key_state_list_t* key_state_list;
};

/**
 * Create a new key data object.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_data_t pointer or NULL on error.
 */
extern key_data_t* key_data_new(const db_connection_t* connection);

/**
 * Create a new key data object that is a copy of another key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_data_t pointer or NULL on error.
 */
extern key_data_t* key_data_new_copy(const key_data_t* key_data);

/**
 * Delete a key data object, this does not delete it from the database.
 * \param[in] key_data a key_data_t pointer.
 */
extern void key_data_free(key_data_t* key_data);

/**
 * Copy the content of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] key_data_copy a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_copy(key_data_t* key_data, const key_data_t* key_data_copy);

/**
 * Compare two key data objects and return less than, equal to,
 * or greater than zero if A is found, respectively, to be less than, to match,
 * or be greater than B.
 * \param[in] key_data_a a key_data_t pointer.
 * \param[in] key_data_b a key_data_t pointer.
 * \return less than, equal to, or greater than zero if A is found, respectively,
 * to be less than, to match, or be greater than B.
 */
extern int key_data_cmp(const key_data_t* key_data_a, const key_data_t* key_data_b);

/**
 * Set the content of a key data object based on a database result.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_from_result(key_data_t* key_data, const db_result_t* result);

/**
 * Get the id of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
extern const db_value_t* key_data_id(const key_data_t* key_data);

/**
 * Get the zone_id of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
extern const db_value_t* key_data_zone_id(const key_data_t* key_data);

/**
 * Get the zone_id object related to a key data object.
 * The caller will be given ownership of this object and is responsible for freeing it.
 * \param[in] key_data a key_data_t pointer.
 * \return a zone_db_t pointer or NULL on error or if no object could be found.
 */
extern zone_db_t* key_data_get_zone(const key_data_t* key_data);

/**
 * Get the hsm_key_id of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
extern const db_value_t* key_data_hsm_key_id(const key_data_t* key_data);

/**
 * Cache the hsm_key_id object related to a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_cache_hsm_key(key_data_t* key_data);

/**
 * Get the hsm_key_id object related to a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a hsm_key_t pointer or NULL on error or if no object could be found.
 */
extern const hsm_key_t* key_data_hsm_key(const key_data_t* key_data);

/**
 * Get the hsm_key_id object related to a key data object.
 * The caller will be given ownership of this object and is responsible for freeing it.
 * \param[in] key_data a key_data_t pointer.
 * \return a hsm_key_t pointer or NULL on error or if no object could be found.
 */
extern hsm_key_t* key_data_get_hsm_key(const key_data_t* key_data);

/**
 * Get the algorithm of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int key_data_algorithm(const key_data_t* key_data);

/**
 * Get the inception of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int key_data_inception(const key_data_t* key_data);

/**
 * Get the role of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_data_role_t which may be KEY_DATA_ROLE_INVALID on error or if no role has been set.
 */
extern key_data_role_t key_data_role(const key_data_t* key_data);

/**
 * Get the role as text of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a character pointer or NULL on error or if no role has been set.
 */
extern const char* key_data_role_text(const key_data_t* key_data);

/**
 * Get the introducing of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int key_data_introducing(const key_data_t* key_data);

/**
 * Get the active_zsk of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int key_data_active_zsk(const key_data_t* key_data);

/**
 * Get the publish of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int key_data_publish(const key_data_t* key_data);

/**
 * Get the active_ksk of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int key_data_active_ksk(const key_data_t* key_data);

/**
 * Get the ds_at_parent of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_data_ds_at_parent_t which may be KEY_DATA_DS_AT_PARENT_INVALID on error or if no ds_at_parent has been set.
 */
extern key_data_ds_at_parent_t key_data_ds_at_parent(const key_data_t* key_data);

/**
 * Get the keytag of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int key_data_keytag(const key_data_t* key_data);

/**
 * Get the minimize of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int key_data_minimize(const key_data_t* key_data);

/**
 * Get the key_state objects related to a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_list_t pointer or NULL on error.
 */
extern key_state_list_t* key_data_key_state_list(key_data_t* key_data);

/**
 * Retrieve key_state objects related to a key data object.
 * Use key_data_key_state_list() to get the list afterwards.
 * This will refetch objects if already retrieved.
 * \param[in] key_data a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_retrieve_key_state_list(key_data_t* key_data);

/**
 * Set the zone_id of a key data object. If this fails the original value may have been lost.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] zone_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_set_zone_id(key_data_t* key_data, const db_value_t* zone_id);

/**
 * Set the hsm_key_id of a key data object. If this fails the original value may have been lost.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] hsm_key_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_set_hsm_key_id(key_data_t* key_data, const db_value_t* hsm_key_id);

/**
 * Set the algorithm of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] algorithm an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_set_algorithm(key_data_t* key_data, unsigned int algorithm);

/**
 * Set the inception of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] inception an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_set_inception(key_data_t* key_data, unsigned int inception);

/**
 * Set the role of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] role a key_data_role_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_set_role(key_data_t* key_data, key_data_role_t role);

/**
 * Set the introducing of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] introducing an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_set_introducing(key_data_t* key_data, unsigned int introducing);

/**
 * Set the active_zsk of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] active_zsk an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_set_active_zsk(key_data_t* key_data, unsigned int active_zsk);

/**
 * Set the publish of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] publish an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_set_publish(key_data_t* key_data, unsigned int publish);

/**
 * Set the active_ksk of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] active_ksk an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_set_active_ksk(key_data_t* key_data, unsigned int active_ksk);

/**
 * Set the ds_at_parent of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] ds_at_parent a key_data_ds_at_parent_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_set_ds_at_parent(key_data_t* key_data, key_data_ds_at_parent_t ds_at_parent);

/**
 * Set the keytag of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] keytag an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_set_keytag(key_data_t* key_data, unsigned int keytag);

/**
 * Set the minimize of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] minimize an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_set_minimize(key_data_t* key_data, unsigned int minimize);

/**
 * Create a clause for zone_id of a key data object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] zone_id a db_value_t pointer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
extern db_clause_t* key_data_zone_id_clause(db_clause_list_t* clause_list, const db_value_t* zone_id);

/**
 * Create a clause for hsm_key_id of a key data object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] hsm_key_id a db_value_t pointer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
extern db_clause_t* key_data_hsm_key_id_clause(db_clause_list_t* clause_list, const db_value_t* hsm_key_id);

/**
 * Create a clause for role of a key data object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] role a key_data_role_t.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
extern db_clause_t* key_data_role_clause(db_clause_list_t* clause_list, key_data_role_t role);

/**
 * Create a clause for ds_at_parent of a key data object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] ds_at_parent a key_data_ds_at_parent_t.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
extern db_clause_t* key_data_ds_at_parent_clause(db_clause_list_t* clause_list, key_data_ds_at_parent_t ds_at_parent);

/**
 * Create a clause for keytag of a key data object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] keytag an unsigned integer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
extern db_clause_t* key_data_keytag_clause(db_clause_list_t* clause_list, unsigned int keytag);

/**
 * Create a key data object in the database.
 * \param[in] key_data a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_create(key_data_t* key_data);

/**
 * Get a key data object from the database by a id specified in `id`.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_get_by_id(key_data_t* key_data, const db_value_t* id);

/**
 * Update a key data object in the database.
 * \param[in] key_data a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_update(key_data_t* key_data);

/**
 * Delete a key data object from the database.
 * \param[in] key_data a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_delete(key_data_t* key_data);

/**
 * Count the number of key data objects in the database, if a selection of
 * objects should be counted then it can be limited by a database clause list
 * otherwise all objects are counted.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer or NULL if all objects.
 * \param[out] count a size_t pointer to where the count should be stored.
 * should be counted.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_count(key_data_t* key_data, db_clause_list_t* clause_list, size_t* count);

/**
 * A list of key data objects.
 */
struct key_data_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    key_data_t* key_data;
    int object_store;
    key_data_t** object_list;
    size_t object_list_size;
    size_t object_list_position;
    int object_list_first;
    int associated_fetch;
    zone_list_db_t* zone_id_list;
    hsm_key_list_t* hsm_key_id_list;
};

/**
 * Create a new key data object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_data_list_t pointer or NULL on error.
 */
extern key_data_list_t* key_data_list_new(const db_connection_t* connection);

/**
 * Create a new key data object list that is a copy of another.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \return a key_data_list_t pointer or NULL on error.
 */
extern key_data_list_t* key_data_list_new_copy(const key_data_list_t* key_data_copy);

/**
 * Specify that objects should be stored within the list as they are fetch,
 * this is optimal if the list is to be iterated over more then once.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_list_object_store(key_data_list_t* key_data_list);

/**
 * Delete a key data object list.
 * \param[in] key_data_list a key_data_list_t pointer.
 */
extern void key_data_list_free(key_data_list_t* key_data_list);

/**
 * Copy the content of another key data object list.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \param[in] from_key_data_list a key_data_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_list_copy(key_data_list_t* key_data_list, const key_data_list_t* from_key_data_list);

/**
 * Get all key data objects.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_list_get(key_data_list_t* key_data_list);

/**
 * Get a new list with all key data objects.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_data_list_t pointer or NULL on error.
 */
extern key_data_list_t* key_data_list_new_get(const db_connection_t* connection);

/**
 * Get key data objects from the database by a clause list.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_list_get_by_clauses(key_data_list_t* key_data_list, const db_clause_list_t* clause_list);

/**
 * Get a new list of key data objects from the database by a clause list.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a key_data_list_t pointer or NULL on error.
 */
extern key_data_list_t* key_data_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list);

/**
 * Get key data objects from the database by a zone_id specified in `zone_id`.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \param[in] zone_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_list_get_by_zone_id(key_data_list_t* key_data_list, const db_value_t* zone_id);

/**
 * Get a new list of key data objects from the database by a zone_id specified in `zone_id`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] zone_id a db_value_t pointer.
 * \return a key_data_list_t pointer or NULL on error.
 */
extern key_data_list_t* key_data_list_new_get_by_zone_id(const db_connection_t* connection, const db_value_t* zone_id);

/**
 * Get the first key data object in a key data object list and reset the
 * position of the list.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \return a key_data_t pointer or NULL on error or if there are no
 * key data objects in the key data object list.
 */
extern const key_data_t* key_data_list_begin(key_data_list_t* key_data_list);

/**
 * Get the first key data object in a key data object list and reset the
 * position of the list. The caller will be given ownership of this object and
 * is responsible for freeing it.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \return a key_data_t pointer or NULL on error or if there are no
 * key data objects in the key data object list.
 */
extern key_data_t* key_data_list_get_begin(key_data_list_t* key_data_list);

/**
 * Get the next key data object in a key data object list.
 * Ownership of this object is retained within the list and the object is only
 * valid until the next call to this function.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \return a key_data_t pointer or NULL on error or if there are no more
 * key data objects in the key data object list.
 */
extern const key_data_t* key_data_list_next(key_data_list_t* key_data_list);

/**
 * Get the next key data object in a key data object list.
 * The caller will be given ownership of this object and is responsible for
 * freeing it.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \return a key_data_t pointer or NULL on error or if there are no more
 * key data objects in the key data object list.
 */
extern key_data_t* key_data_list_get_next(key_data_list_t* key_data_list);

/**
 * Get the size of a key data object list.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \return a size_t with the size of the list or zero on error, if the list is
 * empty or if the backend does not support returning the size.
 */
extern size_t key_data_list_size(key_data_list_t* key_data_list);

extern key_data_t* key_data_new_get_by_hsm_key_id (const db_connection_t* connection, const db_value_t* hsm_key_id);

extern int key_data_get_by_hsm_key_id (key_data_t* key_data, const db_value_t* hsm_key_id);
#endif
