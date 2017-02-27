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

#ifndef __hsm_key_h
#define __hsm_key_h

#include "db_object.h"

struct hsm_key;
struct hsm_key_list;
typedef struct hsm_key hsm_key_t;
typedef struct hsm_key_list hsm_key_list_t;

typedef enum hsm_key_state {
    HSM_KEY_STATE_INVALID = -1,
    HSM_KEY_STATE_UNUSED = 1,
    HSM_KEY_STATE_PRIVATE = 2,
    HSM_KEY_STATE_SHARED = 3,
    HSM_KEY_STATE_DELETE = 4
} hsm_key_state_t;
extern const db_enum_t hsm_key_enum_set_state[];

typedef enum hsm_key_role {
    HSM_KEY_ROLE_INVALID = -1,
    HSM_KEY_ROLE_KSK = 1,
    HSM_KEY_ROLE_ZSK = 2,
    HSM_KEY_ROLE_CSK = 3
} hsm_key_role_t;
extern const db_enum_t hsm_key_enum_set_role[];

typedef enum hsm_key_key_type {
    HSM_KEY_KEY_TYPE_INVALID = -1,
    HSM_KEY_KEY_TYPE_RSA = 1
} hsm_key_key_type_t;

typedef enum hsm_key_backup {
    HSM_KEY_BACKUP_INVALID = -1,
    HSM_KEY_BACKUP_NO_BACKUP = 0,
    HSM_KEY_BACKUP_BACKUP_REQUIRED = 1,
    HSM_KEY_BACKUP_BACKUP_REQUESTED = 2,
    HSM_KEY_BACKUP_BACKUP_DONE = 3
} hsm_key_backup_t;
extern const db_enum_t hsm_key_enum_set_backup[];

#include "hsm_key_ext.h"
#include "policy.h"

/**
 * A hsm key object.
 */
struct hsm_key {
    db_object_t* dbo;
    db_value_t id;
    db_value_t rev;
    db_value_t policy_id;
    const policy_t* associated_policy_id;
    policy_t* private_policy_id;
    char* locator;
    hsm_key_state_t state;
    unsigned int bits;
    unsigned int algorithm;
    hsm_key_role_t role;
    unsigned int inception;
    unsigned int is_revoked;
    hsm_key_key_type_t key_type;
    char* repository;
    hsm_key_backup_t backup;
};

/**
 * Create a new hsm key object.
 * \param[in] connection a db_connection_t pointer.
 * \return a hsm_key_t pointer or NULL on error.
 */
hsm_key_t* hsm_key_new(const db_connection_t* connection);

/**
 * Create a new hsm key object that is a copy of another hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return a hsm_key_t pointer or NULL on error.
 */
hsm_key_t* hsm_key_new_copy(const hsm_key_t* hsm_key);

/**
 * Delete a hsm key object, this does not delete it from the database.
 * \param[in] hsm_key a hsm_key_t pointer.
 */
void hsm_key_free(hsm_key_t* hsm_key);

/**
 * Copy the content of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] hsm_key_copy a hsm_key_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_copy(hsm_key_t* hsm_key, const hsm_key_t* hsm_key_copy);

/**
 * Set the content of a hsm key object based on a database result.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_from_result(hsm_key_t* hsm_key, const db_result_t* result);

/**
 * Get the id of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* hsm_key_id(const hsm_key_t* hsm_key);

/**
 * Get the policy_id of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* hsm_key_policy_id(const hsm_key_t* hsm_key);

/**
 * Get the locator of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return a character pointer or NULL on error or if no locator has been set.
 */
const char* hsm_key_locator(const hsm_key_t* hsm_key);

/**
 * Get the state of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return a hsm_key_state_t which may be HSM_KEY_STATE_INVALID on error or if no state has been set.
 */
hsm_key_state_t hsm_key_state(const hsm_key_t* hsm_key);

/**
 * Get the bits of a hsm key object. Undefined behavior if `hsm_key` is NULL.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return an unsigned integer.
 */
unsigned int hsm_key_bits(const hsm_key_t* hsm_key);

/**
 * Get the algorithm of a hsm key object. Undefined behavior if `hsm_key` is NULL.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return an unsigned integer.
 */
unsigned int hsm_key_algorithm(const hsm_key_t* hsm_key);

/**
 * Get the role of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return a hsm_key_role_t which may be HSM_KEY_ROLE_INVALID on error or if no role has been set.
 */
hsm_key_role_t hsm_key_role(const hsm_key_t* hsm_key);

/**
 * Get the inception of a hsm key object. Undefined behavior if `hsm_key` is NULL.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return an unsigned integer.
 */
unsigned int hsm_key_inception(const hsm_key_t* hsm_key);

/**
 * Get the repository of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return a character pointer or NULL on error or if no repository has been set.
 */
const char* hsm_key_repository(const hsm_key_t* hsm_key);

/**
 * Get the backup of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return a hsm_key_backup_t which may be HSM_KEY_BACKUP_INVALID on error or if no backup has been set.
 */
hsm_key_backup_t hsm_key_backup(const hsm_key_t* hsm_key);

/**
 * Set the policy_id of a hsm key object. If this fails the original value may have been lost.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] policy_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_set_policy_id(hsm_key_t* hsm_key, const db_value_t* policy_id);

/**
 * Set the locator of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] locator_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_set_locator(hsm_key_t* hsm_key, const char* locator_text);

/**
 * Set the state of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] state a hsm_key_state_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_set_state(hsm_key_t* hsm_key, hsm_key_state_t state);

/**
 * Set the bits of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] bits an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_set_bits(hsm_key_t* hsm_key, unsigned int bits);

/**
 * Set the algorithm of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] algorithm an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_set_algorithm(hsm_key_t* hsm_key, unsigned int algorithm);

/**
 * Set the role of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] role a hsm_key_role_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_set_role(hsm_key_t* hsm_key, hsm_key_role_t role);

/**
 * Set the inception of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] inception an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_set_inception(hsm_key_t* hsm_key, unsigned int inception);

/**
 * Set the key_type of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] key_type a hsm_key_key_type_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_set_key_type(hsm_key_t* hsm_key, hsm_key_key_type_t key_type);

/**
 * Set the repository of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] repository_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_set_repository(hsm_key_t* hsm_key, const char* repository_text);

/**
 * Set the backup of a hsm key object.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] backup a hsm_key_backup_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_set_backup(hsm_key_t* hsm_key, hsm_key_backup_t backup);

/**
 * Create a clause for policy_id of a hsm key object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] policy_id a db_value_t pointer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* hsm_key_policy_id_clause(db_clause_list_t* clause_list, const db_value_t* policy_id);

/**
 * Create a clause for state of a hsm key object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] state a hsm_key_state_t.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* hsm_key_state_clause(db_clause_list_t* clause_list, hsm_key_state_t state);

/**
 * Create a clause for bits of a hsm key object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] bits an unsigned integer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* hsm_key_bits_clause(db_clause_list_t* clause_list, unsigned int bits);

/**
 * Create a clause for algorithm of a hsm key object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] algorithm an unsigned integer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* hsm_key_algorithm_clause(db_clause_list_t* clause_list, unsigned int algorithm);

/**
 * Create a clause for role of a hsm key object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] role a hsm_key_role_t.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* hsm_key_role_clause(db_clause_list_t* clause_list, hsm_key_role_t role);

/**
 * Create a clause for is_revoked of a hsm key object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] is_revoked an unsigned integer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* hsm_key_is_revoked_clause(db_clause_list_t* clause_list, unsigned int is_revoked);

/**
 * Create a clause for key_type of a hsm key object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] key_type a hsm_key_key_type_t.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* hsm_key_key_type_clause(db_clause_list_t* clause_list, hsm_key_key_type_t key_type);

/**
 * Create a clause for repository of a hsm key object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] repository_text a character pointer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* hsm_key_repository_clause(db_clause_list_t* clause_list, const char* repository_text);

/**
 * Create a clause for backup of a hsm key object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] backup a hsm_key_backup_t.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* hsm_key_backup_clause(db_clause_list_t* clause_list, hsm_key_backup_t backup);

/**
 * Create a hsm key object in the database.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_create(hsm_key_t* hsm_key);

/**
 * Get a hsm key object from the database by a id specified in `id`.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_get_by_id(hsm_key_t* hsm_key, const db_value_t* id);

/**
 * Get a hsm key object from the database by a locator specified in `locator`.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] locator a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_get_by_locator(hsm_key_t* hsm_key, const char* locator);

/**
 * Get a new hsm key object from the database by a locator specified in `locator`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] locator a character pointer.
 * \return a hsm_key_t pointer or NULL on error or if it does not exist.
 */
hsm_key_t* hsm_key_new_get_by_locator(const db_connection_t* connection, const char* locator);

/**
 * Update a hsm key object in the database.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_update(hsm_key_t* hsm_key);

/**
 * Count the number of hsm key objects in the database, if a selection of
 * objects should be counted then it can be limited by a database clause list
 * otherwise all objects are counted.
 * \param[in] hsm_key a hsm_key_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer or NULL if all objects.
 * \param[out] count a size_t pointer to where the count should be stored.
 * should be counted.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_count(hsm_key_t* hsm_key, db_clause_list_t* clause_list, size_t* count);

/**
 * A list of hsm key objects.
 */
struct hsm_key_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    hsm_key_t* hsm_key;
    int object_store;
    hsm_key_t** object_list;
    size_t object_list_size;
    size_t object_list_position;
    int object_list_first;
    int associated_fetch;
    policy_list_t* policy_id_list;
};

/**
 * Create a new hsm key object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a hsm_key_list_t pointer or NULL on error.
 */
hsm_key_list_t* hsm_key_list_new(const db_connection_t* connection);

size_t
hsm_key_list_size(hsm_key_list_t* hsm_key_list);

/**
 * Create a new hsm key object list that is a copy of another.
 * \param[in] hsm_key_list a hsm_key_list_t pointer.
 * \return a hsm_key_list_t pointer or NULL on error.
 */
hsm_key_list_t* hsm_key_list_new_copy(const hsm_key_list_t* hsm_key_copy);

/**
 * Specify that objects should be stored within the list as they are fetch,
 * this is optimal if the list is to be iterated over more then once.
 * \param[in] hsm_key_list a hsm_key_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_list_object_store(hsm_key_list_t* hsm_key_list);

/**
 * Delete a hsm key object list.
 * \param[in] hsm_key_list a hsm_key_list_t pointer.
 */
void hsm_key_list_free(hsm_key_list_t* hsm_key_list);

/**
 * free global allocator.
 * hsm_key_list_free MUST be called for all its contents.
 */
/**
 * Copy the content of another hsm key object list.
 * \param[in] hsm_key_list a hsm_key_list_t pointer.
 * \param[in] from_hsm_key_list a hsm_key_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_list_copy(hsm_key_list_t* hsm_key_list, const hsm_key_list_t* from_hsm_key_list);

/**
 * Get hsm key objects from the database by a clause list.
 * \param[in] hsm_key_list a hsm_key_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_list_get_by_clauses(hsm_key_list_t* hsm_key_list, const db_clause_list_t* clause_list);

/**
 * Get a new list of hsm key objects from the database by a clause list.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a hsm_key_list_t pointer or NULL on error.
 */
hsm_key_list_t* hsm_key_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list);

/**
 * Get hsm key objects from the database by a policy_id specified in `policy_id`.
 * \param[in] hsm_key_list a hsm_key_list_t pointer.
 * \param[in] policy_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_list_get_by_policy_id(hsm_key_list_t* hsm_key_list, const db_value_t* policy_id);

/**
 * Get a new list of hsm key objects from the database by a policy_id specified in `policy_id`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] policy_id a db_value_t pointer.
 * \return a hsm_key_list_t pointer or NULL on error.
 */
hsm_key_list_t* hsm_key_list_new_get_by_policy_id(const db_connection_t* connection, const db_value_t* policy_id);

/**
 * Get the first hsm key object in a hsm key object list and reset the
 * position of the list.
 * \param[in] hsm_key_list a hsm_key_list_t pointer.
 * \return a hsm_key_t pointer or NULL on error or if there are no
 * hsm key objects in the hsm key object list.
 */
const hsm_key_t* hsm_key_list_begin(hsm_key_list_t* hsm_key_list);

/**
 * Get the first hsm key object in a hsm key object list and reset the
 * position of the list. The caller will be given ownership of this object and
 * is responsible for freeing it.
 * \param[in] hsm_key_list a hsm_key_list_t pointer.
 * \return a hsm_key_t pointer or NULL on error or if there are no
 * hsm key objects in the hsm key object list.
 */
hsm_key_t* hsm_key_list_get_begin(hsm_key_list_t* hsm_key_list);

/**
 * Get the next hsm key object in a hsm key object list.
 * Ownership of this object is retained within the list and the object is only
 * valid until the next call to this function.
 * \param[in] hsm_key_list a hsm_key_list_t pointer.
 * \return a hsm_key_t pointer or NULL on error or if there are no more
 * hsm key objects in the hsm key object list.
 */
const hsm_key_t* hsm_key_list_next(hsm_key_list_t* hsm_key_list);

/**
 * Get the next hsm key object in a hsm key object list.
 * The caller will be given ownership of this object and is responsible for
 * freeing it.
 * \param[in] hsm_key_list a hsm_key_list_t pointer.
 * \return a hsm_key_t pointer or NULL on error or if there are no more
 * hsm key objects in the hsm key object list.
 */
hsm_key_t* hsm_key_list_get_next(hsm_key_list_t* hsm_key_list);

#endif
