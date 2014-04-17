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

#ifndef __policy_h
#define __policy_h

#ifdef __cplusplus
extern "C" {
#endif

struct policy;
struct policy_list;
typedef struct policy policy_t;
typedef struct policy_list policy_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "policy_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A policy object.
 */
struct policy {
    db_object_t* dbo;
    db_value_t id;
    char* name;
    char* description;
    int signatures;
    int denial;
    int keylist;
    int zone;
    int parent;
#include "policy_struct_ext.h"
};

/**
 * Create a new policy object.
 * \param[in] connection a db_connection_t pointer.
 * \return a policy_t pointer or NULL on error.
 */
policy_t* policy_new(const db_connection_t* connection);

/**
 * Delete a policy object, this does not delete it from the database.
 * \param[in] policy a policy_t pointer.
 */
void policy_free(policy_t* policy);

/**
 * Reset the content of a policy object making it as if its new. This does not change anything in the database.
 * \param[in] policy a policy_t pointer.
 */
void policy_reset(policy_t* policy);

/**
 * Copy the content of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] policy_copy a policy_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_copy(policy_t* policy, const policy_t* policy_copy);

/**
 * Set the content of a policy object based on a database result.
 * \param[in] policy a policy_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_from_result(policy_t* policy, const db_result_t* result);

/**
 * Get the id of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return a db_value_t pointer.
 */
const db_value_t* policy_id(const policy_t* policy);

/**
 * Get the name of a policy object.
 * \param[in] policy a policy_t pointer.
 * \return a character pointer or NULL on error or if no name has been set.
 */
const char* policy_name(const policy_t* policy);

/**
 * Get the description of a policy object.
 * \param[in] policy a policy_t pointer.
 * \return a character pointer or NULL on error or if no description has been set.
 */
const char* policy_description(const policy_t* policy);

/**
 * Get the signatures of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an integer.
 */
int policy_signatures(const policy_t* policy);

/**
 * Get the denial of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an integer.
 */
int policy_denial(const policy_t* policy);

/**
 * Get the keylist of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an integer.
 */
int policy_keylist(const policy_t* policy);

/**
 * Get the zone of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an integer.
 */
int policy_zone(const policy_t* policy);

/**
 * Get the parent of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an integer.
 */
int policy_parent(const policy_t* policy);

/**
 * Set the name of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] name_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_set_name(policy_t* policy, const char* name_text);

/**
 * Set the description of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] description_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_set_description(policy_t* policy, const char* description_text);

/**
 * Set the signatures of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] signatures an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_set_signatures(policy_t* policy, int signatures);

/**
 * Set the denial of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] denial an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_set_denial(policy_t* policy, int denial);

/**
 * Set the keylist of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] keylist an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_set_keylist(policy_t* policy, int keylist);

/**
 * Set the zone of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] zone an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_set_zone(policy_t* policy, int zone);

/**
 * Set the parent of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] parent an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_set_parent(policy_t* policy, int parent);

/**
 * Create a policy object in the database.
 * \param[in] policy a policy_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_create(policy_t* policy);

/**
 * Get a policy object from the database by an id specified in `id`.
 * \param[in] policy a policy_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_get_by_id(policy_t* policy, const db_value_t* id);

/**
 * Update a policy object in the database.
 * \param[in] policy a policy_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_update(policy_t* policy);

/**
 * Delete a policy object from the database.
 * \param[in] policy a policy_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_delete(policy_t* policy);

/**
 * A list of policy objects.
 */
struct policy_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    policy_t* policy;
};

/**
 * Create a new policy object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a policy_list_t pointer or NULL on error.
 */
policy_list_t* policy_list_new(const db_connection_t* connection);

/**
 * Delete a policy object list
 * \param[in] policy_list a policy_list_t pointer.
 */
void policy_list_free(policy_list_t* policy_list);

/**
 * Get all policy objects.
 * \param[in] policy_list a policy_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int policy_list_get(policy_list_t* policy_list);

/**
 * Get the first policy object in a policy object list. This will reset the position of the list.
 * \param[in] policy_list a policy_list_t pointer.
 * \return a policy_t pointer or NULL on error or if there are no
 * policy objects in the policy object list.
 */
const policy_t* policy_list_begin(policy_list_t* policy_list);

/**
 * Get the next policy object in a policy object list.
 * \param[in] policy_list a policy_list_t pointer.
 * \return a policy_t pointer or NULL on error or if there are no more
 * policy objects in the policy object list.
 */
const policy_t* policy_list_next(policy_list_t* policy_list);

#ifdef __cplusplus
}
#endif

#endif
