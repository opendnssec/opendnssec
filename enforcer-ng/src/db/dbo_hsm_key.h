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

#ifndef __dbo_hsm_key_h
#define __dbo_hsm_key_h

#ifdef __cplusplus
extern "C" {
#endif

struct dbo_hsm_key;
struct dbo_hsm_key_list;
typedef struct dbo_hsm_key dbo_hsm_key_t;
typedef struct dbo_hsm_key_list dbo_hsm_key_list_t;

typedef enum dbo_hsm_key_role {
    DBO_HSM_KEY_ROLE_INVALID = -1,
    DBO_HSM_KEY_ROLE_KSK = 1,
    DBO_HSM_KEY_ROLE_ZSK = 2,
    DBO_HSM_KEY_ROLE_CSK = 3
} dbo_hsm_key_role_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "dbo_hsm_key_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A dbo hsm key object.
 */
struct dbo_hsm_key {
    db_object_t* dbo;
    int id;
    char* locator;
    unsigned int candidate_for_sharing;
    unsigned int bits;
    char* policy;
    unsigned int algorithm;
    dbo_hsm_key_role_t role;
    unsigned int inception;
    unsigned int isrevoked;
    char* key_type;
    char* repository;
    unsigned int backmeup;
    unsigned int backedup;
    unsigned int requirebackup;
#include "dbo_hsm_key_struct_ext.h"
};

/**
 * Create a new dbo hsm key object.
 * \param[in] connection a db_connection_t pointer.
 * \return a dbo_hsm_key_t pointer or NULL on error.
 */
dbo_hsm_key_t* dbo_hsm_key_new(const db_connection_t* connection);

/**
 * Delete a dbo hsm key object, this does not delete it from the database.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 */
void dbo_hsm_key_free(dbo_hsm_key_t* dbo_hsm_key);

/**
 * Reset the content of a dbo hsm key object making it as if its new. This does not change anything in the database.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 */
void dbo_hsm_key_reset(dbo_hsm_key_t* dbo_hsm_key);

/**
 * Copy the content of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] dbo_hsm_key_copy a dbo_hsm_key_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_copy(dbo_hsm_key_t* dbo_hsm_key, const dbo_hsm_key_t* dbo_hsm_key_copy);

/**
 * Set the content of a dbo hsm key object based on a database result.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_from_result(dbo_hsm_key_t* dbo_hsm_key, const db_result_t* result);

/**
 * Get the ID of a dbo hsm key object. Undefined behavior if `dbo_hsm_key` is NULL.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return an integer.
 */
int dbo_hsm_key_id(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the locator of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return a character pointer or NULL on error or if no locator has been set.
 */
const char* dbo_hsm_key_locator(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the candidate_for_sharing of a dbo hsm key object. Undefined behavior if `dbo_hsm_key` is NULL.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return an unsigned integer.
 */
unsigned int dbo_hsm_key_candidate_for_sharing(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the bits of a dbo hsm key object. Undefined behavior if `dbo_hsm_key` is NULL.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return an unsigned integer.
 */
unsigned int dbo_hsm_key_bits(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the policy of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return a character pointer or NULL on error or if no policy has been set.
 */
const char* dbo_hsm_key_policy(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the algorithm of a dbo hsm key object. Undefined behavior if `dbo_hsm_key` is NULL.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return an unsigned integer.
 */
unsigned int dbo_hsm_key_algorithm(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the role of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return a dbo_hsm_key_role_t which may be DBO_HSM_KEY_ROLE_INVALID on error or if no role has been set.
 */
dbo_hsm_key_role_t dbo_hsm_key_role(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the role as text of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return a character pointer or NULL on error or if no role has been set.
 */
const char* dbo_hsm_key_role_text(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the inception of a dbo hsm key object. Undefined behavior if `dbo_hsm_key` is NULL.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return an unsigned integer.
 */
unsigned int dbo_hsm_key_inception(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the isrevoked of a dbo hsm key object. Undefined behavior if `dbo_hsm_key` is NULL.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return an unsigned integer.
 */
unsigned int dbo_hsm_key_isrevoked(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the key_type of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return a character pointer or NULL on error or if no key_type has been set.
 */
const char* dbo_hsm_key_key_type(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the repository of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return a character pointer or NULL on error or if no repository has been set.
 */
const char* dbo_hsm_key_repository(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the backmeup of a dbo hsm key object. Undefined behavior if `dbo_hsm_key` is NULL.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return an unsigned integer.
 */
unsigned int dbo_hsm_key_backmeup(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the backedup of a dbo hsm key object. Undefined behavior if `dbo_hsm_key` is NULL.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return an unsigned integer.
 */
unsigned int dbo_hsm_key_backedup(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get the requirebackup of a dbo hsm key object. Undefined behavior if `dbo_hsm_key` is NULL.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return an unsigned integer.
 */
unsigned int dbo_hsm_key_requirebackup(const dbo_hsm_key_t* dbo_hsm_key);

/**
 * Set the locator of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] locator_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_locator(dbo_hsm_key_t* dbo_hsm_key, const char* locator_text);

/**
 * Set the candidate_for_sharing of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] candidate_for_sharing an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_candidate_for_sharing(dbo_hsm_key_t* dbo_hsm_key, unsigned int candidate_for_sharing);

/**
 * Set the bits of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] bits an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_bits(dbo_hsm_key_t* dbo_hsm_key, unsigned int bits);

/**
 * Set the policy of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] policy_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_policy(dbo_hsm_key_t* dbo_hsm_key, const char* policy_text);

/**
 * Set the algorithm of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] algorithm an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_algorithm(dbo_hsm_key_t* dbo_hsm_key, unsigned int algorithm);

/**
 * Set the role of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] role a dbo_hsm_key_role_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_role(dbo_hsm_key_t* dbo_hsm_key, dbo_hsm_key_role_t role);

/**
 * Set the role of a dbo hsm key object from text.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] role a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_role_text(dbo_hsm_key_t* dbo_hsm_key, const char* role);

/**
 * Set the inception of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] inception an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_inception(dbo_hsm_key_t* dbo_hsm_key, unsigned int inception);

/**
 * Set the isrevoked of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] isrevoked an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_isrevoked(dbo_hsm_key_t* dbo_hsm_key, unsigned int isrevoked);

/**
 * Set the key_type of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] key_type_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_key_type(dbo_hsm_key_t* dbo_hsm_key, const char* key_type_text);

/**
 * Set the repository of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] repository_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_repository(dbo_hsm_key_t* dbo_hsm_key, const char* repository_text);

/**
 * Set the backmeup of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] backmeup an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_backmeup(dbo_hsm_key_t* dbo_hsm_key, unsigned int backmeup);

/**
 * Set the backedup of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] backedup an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_backedup(dbo_hsm_key_t* dbo_hsm_key, unsigned int backedup);

/**
 * Set the requirebackup of a dbo hsm key object.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] requirebackup an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_set_requirebackup(dbo_hsm_key_t* dbo_hsm_key, unsigned int requirebackup);

/**
 * Create a dbo hsm key object in the database.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_create(dbo_hsm_key_t* dbo_hsm_key);

/**
 * Get a dbo hsm key object from the database by an id specified in `id`.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_get_by_id(dbo_hsm_key_t* dbo_hsm_key, int id);

/**
 * Update a dbo hsm key object in the database.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_update(dbo_hsm_key_t* dbo_hsm_key);

/**
 * Delete a dbo hsm key object from the database.
 * \param[in] dbo_hsm_key a dbo_hsm_key_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_delete(dbo_hsm_key_t* dbo_hsm_key);

/**
 * A list of dbo hsm key objects.
 */
struct dbo_hsm_key_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    dbo_hsm_key_t* dbo_hsm_key;
};

/**
 * Create a new dbo hsm key object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a dbo_hsm_key_list_t pointer or NULL on error.
 */
dbo_hsm_key_list_t* dbo_hsm_key_list_new(const db_connection_t* connection);

/**
 * Delete a dbo hsm key object list
 * \param[in] dbo_hsm_key_list a dbo_hsm_key_list_t pointer.
 */
void dbo_hsm_key_list_free(dbo_hsm_key_list_t* dbo_hsm_key_list);

/**
 * Get all dbo hsm key objects.
 * \param[in] dbo_hsm_key_list a dbo_hsm_key_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_hsm_key_list_get(dbo_hsm_key_list_t* dbo_hsm_key_list);

/**
 * Get the first dbo hsm key object in a dbo hsm key object list. This will reset the position of the list.
 * \param[in] dbo_hsm_key_list a dbo_hsm_key_list_t pointer.
 * \return a dbo_hsm_key_t pointer or NULL on error or if there are no
 * dbo hsm key objects in the dbo hsm key object list.
 */
const dbo_hsm_key_t* dbo_hsm_key_list_begin(dbo_hsm_key_list_t* dbo_hsm_key_list);

/**
 * Get the next dbo hsm key object in a dbo hsm key object list.
 * \param[in] dbo_hsm_key_list a dbo_hsm_key_list_t pointer.
 * \return a dbo_hsm_key_t pointer or NULL on error or if there are no more
 * dbo hsm key objects in the dbo hsm key object list.
 */
const dbo_hsm_key_t* dbo_hsm_key_list_next(dbo_hsm_key_list_t* dbo_hsm_key_list);

#ifdef __cplusplus
}
#endif

#endif
