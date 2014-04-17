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

#ifndef __csk_h
#define __csk_h

#ifdef __cplusplus
extern "C" {
#endif

struct csk;
struct csk_list;
typedef struct csk csk_t;
typedef struct csk_list csk_list_t;

typedef enum csk_rollover_type {
    CSK_ROLLOVER_TYPE_INVALID = -1,
    CSK_ROLLOVER_TYPE_DOUBLE_RRSET = 0,
    CSK_ROLLOVER_TYPE_SINGLE_SIGNATURE = 1,
    CSK_ROLLOVER_TYPE_DOUBLE_DS = 2,
    CSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE = 4,
    CSK_ROLLOVER_TYPE_PREPUBLICATION = 5
} csk_rollover_type_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "csk_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A csk object.
 */
struct csk {
    db_object_t* dbo;
    int id;
    unsigned int algorithm;
    unsigned int bits;
    int lifetime;
    char* repository;
    unsigned int standby;
    unsigned int manual_rollover;
    unsigned int rfc5011;
    csk_rollover_type_t rollover_type;
#include "csk_struct_ext.h"
};

/**
 * Create a new csk object.
 * \param[in] connection a db_connection_t pointer.
 * \return a csk_t pointer or NULL on error.
 */
csk_t* csk_new(const db_connection_t* connection);

/**
 * Delete a csk object, this does not delete it from the database.
 * \param[in] csk a csk_t pointer.
 */
void csk_free(csk_t* csk);

/**
 * Reset the content of a csk object making it as if its new. This does not change anything in the database.
 * \param[in] csk a csk_t pointer.
 */
void csk_reset(csk_t* csk);

/**
 * Copy the content of a csk object.
 * \param[in] csk a csk_t pointer.
 * \param[in] csk_copy a csk_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_copy(csk_t* csk, const csk_t* csk_copy);

/**
 * Set the content of a csk object based on a database result.
 * \param[in] csk a csk_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_from_result(csk_t* csk, const db_result_t* result);

/**
 * Get the ID of a csk object. Undefined behavior if `csk` is NULL.
 * \param[in] csk a csk_t pointer.
 * \return an integer.
 */
int csk_id(const csk_t* csk);

/**
 * Get the algorithm of a csk object. Undefined behavior if `csk` is NULL.
 * \param[in] csk a csk_t pointer.
 * \return an unsigned integer.
 */
unsigned int csk_algorithm(const csk_t* csk);

/**
 * Get the bits of a csk object. Undefined behavior if `csk` is NULL.
 * \param[in] csk a csk_t pointer.
 * \return an unsigned integer.
 */
unsigned int csk_bits(const csk_t* csk);

/**
 * Get the lifetime of a csk object. Undefined behavior if `csk` is NULL.
 * \param[in] csk a csk_t pointer.
 * \return an integer.
 */
int csk_lifetime(const csk_t* csk);

/**
 * Get the repository of a csk object.
 * \param[in] csk a csk_t pointer.
 * \return a character pointer or NULL on error or if no repository has been set.
 */
const char* csk_repository(const csk_t* csk);

/**
 * Get the standby of a csk object. Undefined behavior if `csk` is NULL.
 * \param[in] csk a csk_t pointer.
 * \return an unsigned integer.
 */
unsigned int csk_standby(const csk_t* csk);

/**
 * Get the manual_rollover of a csk object. Undefined behavior if `csk` is NULL.
 * \param[in] csk a csk_t pointer.
 * \return an unsigned integer.
 */
unsigned int csk_manual_rollover(const csk_t* csk);

/**
 * Get the rfc5011 of a csk object. Undefined behavior if `csk` is NULL.
 * \param[in] csk a csk_t pointer.
 * \return an unsigned integer.
 */
unsigned int csk_rfc5011(const csk_t* csk);

/**
 * Get the rollover_type of a csk object.
 * \param[in] csk a csk_t pointer.
 * \return a csk_rollover_type_t which may be CSK_ROLLOVER_TYPE_INVALID on error or if no rollover_type has been set.
 */
csk_rollover_type_t csk_rollover_type(const csk_t* csk);

/**
 * Get the rollover_type as text of a csk object.
 * \param[in] csk a csk_t pointer.
 * \return a character pointer or NULL on error or if no rollover_type has been set.
 */
const char* csk_rollover_type_text(const csk_t* csk);

/**
 * Set the algorithm of a csk object.
 * \param[in] csk a csk_t pointer.
 * \param[in] algorithm an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_set_algorithm(csk_t* csk, unsigned int algorithm);

/**
 * Set the bits of a csk object.
 * \param[in] csk a csk_t pointer.
 * \param[in] bits an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_set_bits(csk_t* csk, unsigned int bits);

/**
 * Set the lifetime of a csk object.
 * \param[in] csk a csk_t pointer.
 * \param[in] lifetime an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_set_lifetime(csk_t* csk, int lifetime);

/**
 * Set the repository of a csk object.
 * \param[in] csk a csk_t pointer.
 * \param[in] repository_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_set_repository(csk_t* csk, const char* repository_text);

/**
 * Set the standby of a csk object.
 * \param[in] csk a csk_t pointer.
 * \param[in] standby an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_set_standby(csk_t* csk, unsigned int standby);

/**
 * Set the manual_rollover of a csk object.
 * \param[in] csk a csk_t pointer.
 * \param[in] manual_rollover an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_set_manual_rollover(csk_t* csk, unsigned int manual_rollover);

/**
 * Set the rfc5011 of a csk object.
 * \param[in] csk a csk_t pointer.
 * \param[in] rfc5011 an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_set_rfc5011(csk_t* csk, unsigned int rfc5011);

/**
 * Set the rollover_type of a csk object.
 * \param[in] csk a csk_t pointer.
 * \param[in] rollover_type a csk_rollover_type_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_set_rollover_type(csk_t* csk, csk_rollover_type_t rollover_type);

/**
 * Set the rollover_type of a csk object from text.
 * \param[in] csk a csk_t pointer.
 * \param[in] rollover_type a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_set_rollover_type_text(csk_t* csk, const char* rollover_type);

/**
 * Create a csk object in the database.
 * \param[in] csk a csk_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_create(csk_t* csk);

/**
 * Get a csk object from the database by an id specified in `id`.
 * \param[in] csk a csk_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_get_by_id(csk_t* csk, int id);

/**
 * Update a csk object in the database.
 * \param[in] csk a csk_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_update(csk_t* csk);

/**
 * Delete a csk object from the database.
 * \param[in] csk a csk_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_delete(csk_t* csk);

/**
 * A list of csk objects.
 */
struct csk_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    csk_t* csk;
};

/**
 * Create a new csk object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a csk_list_t pointer or NULL on error.
 */
csk_list_t* csk_list_new(const db_connection_t* connection);

/**
 * Delete a csk object list
 * \param[in] csk_list a csk_list_t pointer.
 */
void csk_list_free(csk_list_t* csk_list);

/**
 * Get all csk objects.
 * \param[in] csk_list a csk_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int csk_list_get(csk_list_t* csk_list);

/**
 * Get the first csk object in a csk object list. This will reset the position of the list.
 * \param[in] csk_list a csk_list_t pointer.
 * \return a csk_t pointer or NULL on error or if there are no
 * csk objects in the csk object list.
 */
const csk_t* csk_list_begin(csk_list_t* csk_list);

/**
 * Get the next csk object in a csk object list.
 * \param[in] csk_list a csk_list_t pointer.
 * \return a csk_t pointer or NULL on error or if there are no more
 * csk objects in the csk object list.
 */
const csk_t* csk_list_next(csk_list_t* csk_list);

#ifdef __cplusplus
}
#endif

#endif
