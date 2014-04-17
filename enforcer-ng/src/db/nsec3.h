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

#ifndef __nsec3_h
#define __nsec3_h

#ifdef __cplusplus
extern "C" {
#endif

struct nsec3;
struct nsec3_list;
typedef struct nsec3 nsec3_t;
typedef struct nsec3_list nsec3_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "nsec3_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A nsec3 object.
 */
struct nsec3 {
    db_object_t* dbo;
    db_value_t id;
    unsigned int optout;
    unsigned int ttl;
    unsigned int resalt;
    unsigned int algorithm;
    unsigned int iterations;
    unsigned int saltlength;
    char* salt;
    unsigned int salt_last_change;
#include "nsec3_struct_ext.h"
};

/**
 * Create a new nsec3 object.
 * \param[in] connection a db_connection_t pointer.
 * \return a nsec3_t pointer or NULL on error.
 */
nsec3_t* nsec3_new(const db_connection_t* connection);

/**
 * Delete a nsec3 object, this does not delete it from the database.
 * \param[in] nsec3 a nsec3_t pointer.
 */
void nsec3_free(nsec3_t* nsec3);

/**
 * Reset the content of a nsec3 object making it as if its new. This does not change anything in the database.
 * \param[in] nsec3 a nsec3_t pointer.
 */
void nsec3_reset(nsec3_t* nsec3);

/**
 * Copy the content of a nsec3 object.
 * \param[in] nsec3 a nsec3_t pointer.
 * \param[in] nsec3_copy a nsec3_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_copy(nsec3_t* nsec3, const nsec3_t* nsec3_copy);

/**
 * Set the content of a nsec3 object based on a database result.
 * \param[in] nsec3 a nsec3_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_from_result(nsec3_t* nsec3, const db_result_t* result);

/**
 * Get the id of a nsec3 object. Undefined behavior if `nsec3` is NULL.
 * \param[in] nsec3 a nsec3_t pointer.
 * \return a db_value_t pointer.
 */
const db_value_t* nsec3_id(const nsec3_t* nsec3);

/**
 * Get the optout of a nsec3 object. Undefined behavior if `nsec3` is NULL.
 * \param[in] nsec3 a nsec3_t pointer.
 * \return an unsigned integer.
 */
unsigned int nsec3_optout(const nsec3_t* nsec3);

/**
 * Get the ttl of a nsec3 object. Undefined behavior if `nsec3` is NULL.
 * \param[in] nsec3 a nsec3_t pointer.
 * \return an unsigned integer.
 */
unsigned int nsec3_ttl(const nsec3_t* nsec3);

/**
 * Get the resalt of a nsec3 object. Undefined behavior if `nsec3` is NULL.
 * \param[in] nsec3 a nsec3_t pointer.
 * \return an unsigned integer.
 */
unsigned int nsec3_resalt(const nsec3_t* nsec3);

/**
 * Get the algorithm of a nsec3 object. Undefined behavior if `nsec3` is NULL.
 * \param[in] nsec3 a nsec3_t pointer.
 * \return an unsigned integer.
 */
unsigned int nsec3_algorithm(const nsec3_t* nsec3);

/**
 * Get the iterations of a nsec3 object. Undefined behavior if `nsec3` is NULL.
 * \param[in] nsec3 a nsec3_t pointer.
 * \return an unsigned integer.
 */
unsigned int nsec3_iterations(const nsec3_t* nsec3);

/**
 * Get the saltlength of a nsec3 object. Undefined behavior if `nsec3` is NULL.
 * \param[in] nsec3 a nsec3_t pointer.
 * \return an unsigned integer.
 */
unsigned int nsec3_saltlength(const nsec3_t* nsec3);

/**
 * Get the salt of a nsec3 object.
 * \param[in] nsec3 a nsec3_t pointer.
 * \return a character pointer or NULL on error or if no salt has been set.
 */
const char* nsec3_salt(const nsec3_t* nsec3);

/**
 * Get the salt_last_change of a nsec3 object. Undefined behavior if `nsec3` is NULL.
 * \param[in] nsec3 a nsec3_t pointer.
 * \return an unsigned integer.
 */
unsigned int nsec3_salt_last_change(const nsec3_t* nsec3);

/**
 * Set the optout of a nsec3 object.
 * \param[in] nsec3 a nsec3_t pointer.
 * \param[in] optout an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_set_optout(nsec3_t* nsec3, unsigned int optout);

/**
 * Set the ttl of a nsec3 object.
 * \param[in] nsec3 a nsec3_t pointer.
 * \param[in] ttl an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_set_ttl(nsec3_t* nsec3, unsigned int ttl);

/**
 * Set the resalt of a nsec3 object.
 * \param[in] nsec3 a nsec3_t pointer.
 * \param[in] resalt an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_set_resalt(nsec3_t* nsec3, unsigned int resalt);

/**
 * Set the algorithm of a nsec3 object.
 * \param[in] nsec3 a nsec3_t pointer.
 * \param[in] algorithm an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_set_algorithm(nsec3_t* nsec3, unsigned int algorithm);

/**
 * Set the iterations of a nsec3 object.
 * \param[in] nsec3 a nsec3_t pointer.
 * \param[in] iterations an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_set_iterations(nsec3_t* nsec3, unsigned int iterations);

/**
 * Set the saltlength of a nsec3 object.
 * \param[in] nsec3 a nsec3_t pointer.
 * \param[in] saltlength an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_set_saltlength(nsec3_t* nsec3, unsigned int saltlength);

/**
 * Set the salt of a nsec3 object.
 * \param[in] nsec3 a nsec3_t pointer.
 * \param[in] salt_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_set_salt(nsec3_t* nsec3, const char* salt_text);

/**
 * Set the salt_last_change of a nsec3 object.
 * \param[in] nsec3 a nsec3_t pointer.
 * \param[in] salt_last_change an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_set_salt_last_change(nsec3_t* nsec3, unsigned int salt_last_change);

/**
 * Create a nsec3 object in the database.
 * \param[in] nsec3 a nsec3_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_create(nsec3_t* nsec3);

/**
 * Get a nsec3 object from the database by an id specified in `id`.
 * \param[in] nsec3 a nsec3_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_get_by_id(nsec3_t* nsec3, const db_value_t* id);

/**
 * Update a nsec3 object in the database.
 * \param[in] nsec3 a nsec3_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_update(nsec3_t* nsec3);

/**
 * Delete a nsec3 object from the database.
 * \param[in] nsec3 a nsec3_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_delete(nsec3_t* nsec3);

/**
 * A list of nsec3 objects.
 */
struct nsec3_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    nsec3_t* nsec3;
};

/**
 * Create a new nsec3 object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a nsec3_list_t pointer or NULL on error.
 */
nsec3_list_t* nsec3_list_new(const db_connection_t* connection);

/**
 * Delete a nsec3 object list
 * \param[in] nsec3_list a nsec3_list_t pointer.
 */
void nsec3_list_free(nsec3_list_t* nsec3_list);

/**
 * Get all nsec3 objects.
 * \param[in] nsec3_list a nsec3_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec3_list_get(nsec3_list_t* nsec3_list);

/**
 * Get the first nsec3 object in a nsec3 object list. This will reset the position of the list.
 * \param[in] nsec3_list a nsec3_list_t pointer.
 * \return a nsec3_t pointer or NULL on error or if there are no
 * nsec3 objects in the nsec3 object list.
 */
const nsec3_t* nsec3_list_begin(nsec3_list_t* nsec3_list);

/**
 * Get the next nsec3 object in a nsec3 object list.
 * \param[in] nsec3_list a nsec3_list_t pointer.
 * \return a nsec3_t pointer or NULL on error or if there are no more
 * nsec3 objects in the nsec3 object list.
 */
const nsec3_t* nsec3_list_next(nsec3_list_t* nsec3_list);

#ifdef __cplusplus
}
#endif

#endif
