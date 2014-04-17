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

#ifndef __signatures_h
#define __signatures_h

#ifdef __cplusplus
extern "C" {
#endif

struct signatures;
struct signatures_list;
typedef struct signatures signatures_t;
typedef struct signatures_list signatures_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "signatures_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A signatures object.
 */
struct signatures {
    db_object_t* dbo;
    int id;
    int resign;
    int refresh;
    int jitter;
    int inceptionOffset;
    int valdefault;
    int valdenial;
    int max_zone_ttl;
#include "signatures_struct_ext.h"
};

/**
 * Create a new signatures object.
 * \param[in] connection a db_connection_t pointer.
 * \return a signatures_t pointer or NULL on error.
 */
signatures_t* signatures_new(const db_connection_t* connection);

/**
 * Delete a signatures object, this does not delete it from the database.
 * \param[in] signatures a signatures_t pointer.
 */
void signatures_free(signatures_t* signatures);

/**
 * Reset the content of a signatures object making it as if its new. This does not change anything in the database.
 * \param[in] signatures a signatures_t pointer.
 */
void signatures_reset(signatures_t* signatures);

/**
 * Copy the content of a signatures object.
 * \param[in] signatures a signatures_t pointer.
 * \param[in] signatures_copy a signatures_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_copy(signatures_t* signatures, const signatures_t* signatures_copy);

/**
 * Set the content of a signatures object based on a database result.
 * \param[in] signatures a signatures_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_from_result(signatures_t* signatures, const db_result_t* result);

/**
 * Get the ID of a signatures object. Undefined behavior if `signatures` is NULL.
 * \param[in] signatures a signatures_t pointer.
 * \return an integer.
 */
int signatures_id(const signatures_t* signatures);

/**
 * Get the resign of a signatures object. Undefined behavior if `signatures` is NULL.
 * \param[in] signatures a signatures_t pointer.
 * \return an integer.
 */
int signatures_resign(const signatures_t* signatures);

/**
 * Get the refresh of a signatures object. Undefined behavior if `signatures` is NULL.
 * \param[in] signatures a signatures_t pointer.
 * \return an integer.
 */
int signatures_refresh(const signatures_t* signatures);

/**
 * Get the jitter of a signatures object. Undefined behavior if `signatures` is NULL.
 * \param[in] signatures a signatures_t pointer.
 * \return an integer.
 */
int signatures_jitter(const signatures_t* signatures);

/**
 * Get the inceptionOffset of a signatures object. Undefined behavior if `signatures` is NULL.
 * \param[in] signatures a signatures_t pointer.
 * \return an integer.
 */
int signatures_inceptionOffset(const signatures_t* signatures);

/**
 * Get the valdefault of a signatures object. Undefined behavior if `signatures` is NULL.
 * \param[in] signatures a signatures_t pointer.
 * \return an integer.
 */
int signatures_valdefault(const signatures_t* signatures);

/**
 * Get the valdenial of a signatures object. Undefined behavior if `signatures` is NULL.
 * \param[in] signatures a signatures_t pointer.
 * \return an integer.
 */
int signatures_valdenial(const signatures_t* signatures);

/**
 * Get the max_zone_ttl of a signatures object. Undefined behavior if `signatures` is NULL.
 * \param[in] signatures a signatures_t pointer.
 * \return an integer.
 */
int signatures_max_zone_ttl(const signatures_t* signatures);

/**
 * Set the resign of a signatures object.
 * \param[in] signatures a signatures_t pointer.
 * \param[in] resign an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_set_resign(signatures_t* signatures, int resign);

/**
 * Set the refresh of a signatures object.
 * \param[in] signatures a signatures_t pointer.
 * \param[in] refresh an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_set_refresh(signatures_t* signatures, int refresh);

/**
 * Set the jitter of a signatures object.
 * \param[in] signatures a signatures_t pointer.
 * \param[in] jitter an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_set_jitter(signatures_t* signatures, int jitter);

/**
 * Set the inceptionOffset of a signatures object.
 * \param[in] signatures a signatures_t pointer.
 * \param[in] inceptionOffset an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_set_inceptionOffset(signatures_t* signatures, int inceptionOffset);

/**
 * Set the valdefault of a signatures object.
 * \param[in] signatures a signatures_t pointer.
 * \param[in] valdefault an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_set_valdefault(signatures_t* signatures, int valdefault);

/**
 * Set the valdenial of a signatures object.
 * \param[in] signatures a signatures_t pointer.
 * \param[in] valdenial an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_set_valdenial(signatures_t* signatures, int valdenial);

/**
 * Set the max_zone_ttl of a signatures object.
 * \param[in] signatures a signatures_t pointer.
 * \param[in] max_zone_ttl an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_set_max_zone_ttl(signatures_t* signatures, int max_zone_ttl);

/**
 * Create a signatures object in the database.
 * \param[in] signatures a signatures_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_create(signatures_t* signatures);

/**
 * Get a signatures object from the database by an id specified in `id`.
 * \param[in] signatures a signatures_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_get_by_id(signatures_t* signatures, int id);

/**
 * Update a signatures object in the database.
 * \param[in] signatures a signatures_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_update(signatures_t* signatures);

/**
 * Delete a signatures object from the database.
 * \param[in] signatures a signatures_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_delete(signatures_t* signatures);

/**
 * A list of signatures objects.
 */
struct signatures_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    signatures_t* signatures;
};

/**
 * Create a new signatures object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a signatures_list_t pointer or NULL on error.
 */
signatures_list_t* signatures_list_new(const db_connection_t* connection);

/**
 * Delete a signatures object list
 * \param[in] signatures_list a signatures_list_t pointer.
 */
void signatures_list_free(signatures_list_t* signatures_list);

/**
 * Get all signatures objects.
 * \param[in] signatures_list a signatures_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int signatures_list_get(signatures_list_t* signatures_list);

/**
 * Get the first signatures object in a signatures object list. This will reset the position of the list.
 * \param[in] signatures_list a signatures_list_t pointer.
 * \return a signatures_t pointer or NULL on error or if there are no
 * signatures objects in the signatures object list.
 */
const signatures_t* signatures_list_begin(signatures_list_t* signatures_list);

/**
 * Get the next signatures object in a signatures object list.
 * \param[in] signatures_list a signatures_list_t pointer.
 * \return a signatures_t pointer or NULL on error or if there are no more
 * signatures objects in the signatures object list.
 */
const signatures_t* signatures_list_next(signatures_list_t* signatures_list);

#ifdef __cplusplus
}
#endif

#endif
