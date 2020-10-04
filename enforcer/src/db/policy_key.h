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

#ifndef __policy_key_h
#define __policy_key_h

#include "db_object.h"

struct policy_key;
struct policy_key_list;
typedef struct policy_key policy_key_t;
typedef struct policy_key_list policy_key_list_t;

typedef enum policy_key_role {
    POLICY_KEY_ROLE_INVALID = -1,
    POLICY_KEY_ROLE_KSK = 1,
    POLICY_KEY_ROLE_ZSK = 2,
    POLICY_KEY_ROLE_CSK = 3
} policy_key_role_t;
extern const db_enum_t policy_key_enum_set_role[];

#include "policy_key_ext.h"
#include "policy.h"

/**
 * A policy key object.
 */
struct policy_key {
    db_object_t* dbo;
    db_value_t id;
    db_value_t rev;
    db_value_t policy_id;
    const policy_t* associated_policy_id;
    policy_t* private_policy_id;
    policy_key_role_t role;
    unsigned int algorithm;
    unsigned int bits;
    unsigned int lifetime;
    char* repository;
    unsigned int standby;
    unsigned int manual_rollover;
    unsigned int rfc5011;
    unsigned int minimize;
};

/**
 * Create a new policy key object.
 * \param[in] connection a db_connection_t pointer.
 * \return a policy_key_t pointer or NULL on error.
 */
extern policy_key_t* policy_key_new(const db_connection_t* connection);

/**
 * Create a new policy key object that is a copy of another policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \return a policy_key_t pointer or NULL on error.
 */
extern policy_key_t* policy_key_new_copy(const policy_key_t* policy_key);

/**
 * Delete a policy key object, this does not delete it from the database.
 * \param[in] policy_key a policy_key_t pointer.
 */
extern void policy_key_free(policy_key_t* policy_key);

/**
 * Reset the content of a policy key object making it as if its new. This does not change anything in the database.
 * \param[in] policy_key a policy_key_t pointer.
 */
extern void policy_key_reset(policy_key_t* policy_key);

/**
 * Copy the content of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] policy_key_copy a policy_key_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_copy(policy_key_t* policy_key, const policy_key_t* policy_key_copy);

/**
 * Compare two policy key objects and return less than, equal to,
 * or greater than zero if A is found, respectively, to be less than, to match,
 * or be greater than B.
 * \param[in] policy_key_a a policy_key_t pointer.
 * \param[in] policy_key_b a policy_key_t pointer.
 * \return less than, equal to, or greater than zero if A is found, respectively,
 * to be less than, to match, or be greater than B.
 */
extern int policy_key_cmp(const policy_key_t* policy_key_a, const policy_key_t* policy_key_b);

/**
 * Set the content of a policy key object based on a database result.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_from_result(policy_key_t* policy_key, const db_result_t* result);

/**
 * Get the policy_id of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
extern const db_value_t* policy_key_policy_id(const policy_key_t* policy_key);

/**
 * Get the policy_id object related to a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \return a policy_t pointer or NULL on error or if no object could be found.
 */
extern const policy_t* policy_key_policy(const policy_key_t* policy_key);

/**
 * Get the policy_id object related to a policy key object.
 * The caller will be given ownership of this object and is responsible for freeing it.
 * \param[in] policy_key a policy_key_t pointer.
 * \return a policy_t pointer or NULL on error or if no object could be found.
 */
extern policy_t* policy_key_get_policy(const policy_key_t* policy_key);

/**
 * Get the role of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \return a policy_key_role_t which may be POLICY_KEY_ROLE_INVALID on error or if no role has been set.
 */
extern policy_key_role_t policy_key_role(const policy_key_t* policy_key);

/**
 * Get the role as text of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \return a character pointer or NULL on error or if no role has been set.
 */
extern const char* policy_key_role_text(const policy_key_t* policy_key);

/**
 * Get the algorithm of a policy key object. Undefined behavior if `policy_key` is NULL.
 * \param[in] policy_key a policy_key_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_key_algorithm(const policy_key_t* policy_key);

/**
 * Get the bits of a policy key object. Undefined behavior if `policy_key` is NULL.
 * \param[in] policy_key a policy_key_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_key_bits(const policy_key_t* policy_key);

/**
 * Get the lifetime of a policy key object. Undefined behavior if `policy_key` is NULL.
 * \param[in] policy_key a policy_key_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_key_lifetime(const policy_key_t* policy_key);

/**
 * Get the repository of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \return a character pointer or NULL on error or if no repository has been set.
 */
extern const char* policy_key_repository(const policy_key_t* policy_key);

/**
 * Get the standby of a policy key object. Undefined behavior if `policy_key` is NULL.
 * \param[in] policy_key a policy_key_t pointer.
 * \return an integer.
 */
extern int policy_key_standby(const policy_key_t* policy_key);

/**
 * Get the manual_rollover of a policy key object. Undefined behavior if `policy_key` is NULL.
 * \param[in] policy_key a policy_key_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_key_manual_rollover(const policy_key_t* policy_key);

/**
 * Get the rfc5011 of a policy key object. Undefined behavior if `policy_key` is NULL.
 * \param[in] policy_key a policy_key_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_key_rfc5011(const policy_key_t* policy_key);

/**
 * Get the minimize of a policy key object. Undefined behavior if `policy_key` is NULL.
 * \param[in] policy_key a policy_key_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_key_minimize(const policy_key_t* policy_key);

/**
 * Set the policy_id of a policy key object. If this fails the original value may have been lost.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] policy_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_set_policy_id(policy_key_t* policy_key, const db_value_t* policy_id);

/**
 * Set the role of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] role a policy_key_role_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_set_role(policy_key_t* policy_key, policy_key_role_t role);

/**
 * Set the algorithm of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] algorithm an unsigned integer with a maximum value of 255.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_set_algorithm(policy_key_t* policy_key, unsigned int algorithm);

/**
 * Set the bits of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] bits an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_set_bits(policy_key_t* policy_key, unsigned int bits);

/**
 * Set the lifetime of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] lifetime an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_set_lifetime(policy_key_t* policy_key, unsigned int lifetime);

/**
 * Set the repository of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] repository_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_set_repository(policy_key_t* policy_key, const char* repository_text);

/**
 * Set the standby of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] standby an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_set_standby(policy_key_t* policy_key, unsigned int standby);

/**
 * Set the manual_rollover of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] manual_rollover an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_set_manual_rollover(policy_key_t* policy_key, unsigned int manual_rollover);

/**
 * Set the rfc5011 of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] rfc5011 an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_set_rfc5011(policy_key_t* policy_key, unsigned int rfc5011);

/**
 * Set the minimize of a policy key object.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] minimize an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_set_minimize(policy_key_t* policy_key, unsigned int minimize);

/**
 * Create a policy key object in the database.
 * \param[in] policy_key a policy_key_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_create(policy_key_t* policy_key);

/**
 * Get a policy key object from the database by a id specified in `id`.
 * \param[in] policy_key a policy_key_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_get_by_id(policy_key_t* policy_key, const db_value_t* id);

/**
 * Delete a policy key object from the database.
 * \param[in] policy_key a policy_key_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_delete(policy_key_t* policy_key);

/**
 * A list of policy key objects.
 */
struct policy_key_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    policy_key_t* policy_key;
    int object_store;
    policy_key_t** object_list;
    size_t object_list_size;
    size_t object_list_position;
    int object_list_first;
    int associated_fetch;
    policy_list_t* policy_id_list;
};

/**
 * Create a new policy key object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a policy_key_list_t pointer or NULL on error.
 */
extern policy_key_list_t* policy_key_list_new(const db_connection_t* connection);

/**
 * Create a new policy key object list that is a copy of another.
 * \param[in] policy_key_list a policy_key_list_t pointer.
 * \return a policy_key_list_t pointer or NULL on error.
 */
extern policy_key_list_t* policy_key_list_new_copy(const policy_key_list_t* policy_key_copy);

/**
 * Specify that objects should be stored within the list as they are fetch,
 * this is optimal if the list is to be iterated over more then once.
 * \param[in] policy_key_list a policy_key_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_list_object_store(policy_key_list_t* policy_key_list);

/**
 * Delete a policy key object list.
 * \param[in] policy_key_list a policy_key_list_t pointer.
 */
extern void policy_key_list_free(policy_key_list_t* policy_key_list);

/**
 * Copy the content of another policy key object list.
 * \param[in] policy_key_list a policy_key_list_t pointer.
 * \param[in] from_policy_key_list a policy_key_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_list_copy(policy_key_list_t* policy_key_list, const policy_key_list_t* from_policy_key_list);

/**
 * Get policy key objects from the database by a clause list.
 * \param[in] policy_key_list a policy_key_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_list_get_by_clauses(policy_key_list_t* policy_key_list, const db_clause_list_t* clause_list);

/**
 * Get policy key objects from the database by a policy_id specified in `policy_id`.
 * \param[in] policy_key_list a policy_key_list_t pointer.
 * \param[in] policy_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_key_list_get_by_policy_id(policy_key_list_t* policy_key_list, const db_value_t* policy_id);

/**
 * Get a new list of policy key objects from the database by a policy_id specified in `policy_id`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] policy_id a db_value_t pointer.
 * \return a policy_key_list_t pointer or NULL on error.
 */
extern policy_key_list_t* policy_key_list_new_get_by_policy_id(const db_connection_t* connection, const db_value_t* policy_id);

/**
 * Get the first policy key object in a policy key object list and reset the
 * position of the list.
 * \param[in] policy_key_list a policy_key_list_t pointer.
 * \return a policy_key_t pointer or NULL on error or if there are no
 * policy key objects in the policy key object list.
 */
extern const policy_key_t* policy_key_list_begin(policy_key_list_t* policy_key_list);

/**
 * Get the next policy key object in a policy key object list.
 * Ownership of this object is retained within the list and the object is only
 * valid until the next call to this function.
 * \param[in] policy_key_list a policy_key_list_t pointer.
 * \return a policy_key_t pointer or NULL on error or if there are no more
 * policy key objects in the policy key object list.
 */
extern const policy_key_t* policy_key_list_next(policy_key_list_t* policy_key_list);

/**
 * Get the next policy key object in a policy key object list.
 * The caller will be given ownership of this object and is responsible for
 * freeing it.
 * \param[in] policy_key_list a policy_key_list_t pointer.
 * \return a policy_key_t pointer or NULL on error or if there are no more
 * policy key objects in the policy key object list.
 */
extern policy_key_t* policy_key_list_get_next(policy_key_list_t* policy_key_list);

/**
 * Get the size of a policy key object list.
 * \param[in] policy_key_list a policy_key_list_t pointer.
 * \return a size_t with the size of the list or zero on error, if the list is
 * empty or if the backend does not support returning the size.
 */
extern size_t policy_key_list_size(policy_key_list_t* policy_key_list);

extern policy_key_t * policy_key_new_get_by_policyid_and_role (const db_connection_t* connection, const db_value_t* policyid, const policy_key_role_t role);

extern int policy_key_get_by_policyid_and_role(policy_key_t* policy_key, const db_value_t* policyid , const policy_key_role_t role);
#endif
