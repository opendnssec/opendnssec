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

#ifndef __denial_h
#define __denial_h

#ifdef __cplusplus
extern "C" {
#endif

struct denial;
struct denial_list;
typedef struct denial denial_t;
typedef struct denial_list denial_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "denial_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A denial object.
 */
struct denial {
    db_object_t* dbo;
    int id;
    int nsec;
    int nsec3;
#include "denial_struct_ext.h"
};

/**
 * Create a new denial object.
 * \param[in] connection a db_connection_t pointer.
 * \return a denial_t pointer or NULL on error.
 */
denial_t* denial_new(const db_connection_t* connection);

/**
 * Delete a denial object, this does not delete it from the database.
 * \param[in] denial a denial_t pointer.
 */
void denial_free(denial_t* denial);

/**
 * Reset the content of a denial object making it as if its new. This does not change anything in the database.
 * \param[in] denial a denial_t pointer.
 */
void denial_reset(denial_t* denial);

/**
 * Copy the content of a denial object.
 * \param[in] denial a denial_t pointer.
 * \param[in] denial_copy a denial_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int denial_copy(denial_t* denial, const denial_t* denial_copy);

/**
 * Set the content of a denial object based on a database result.
 * \param[in] denial a denial_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int denial_from_result(denial_t* denial, const db_result_t* result);

/**
 * Get the ID of a denial object. Undefined behavior if `denial` is NULL.
 * \param[in] denial a denial_t pointer.
 * \return an integer.
 */
int denial_id(const denial_t* denial);

/**
 * Get the nsec of a denial object. Undefined behavior if `denial` is NULL.
 * \param[in] denial a denial_t pointer.
 * \return an integer.
 */
int denial_nsec(const denial_t* denial);

/**
 * Get the nsec3 of a denial object. Undefined behavior if `denial` is NULL.
 * \param[in] denial a denial_t pointer.
 * \return an integer.
 */
int denial_nsec3(const denial_t* denial);

/**
 * Set the nsec of a denial object.
 * \param[in] denial a denial_t pointer.
 * \param[in] nsec an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int denial_set_nsec(denial_t* denial, int nsec);

/**
 * Set the nsec3 of a denial object.
 * \param[in] denial a denial_t pointer.
 * \param[in] nsec3 an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int denial_set_nsec3(denial_t* denial, int nsec3);

/**
 * Create a denial object in the database.
 * \param[in] denial a denial_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int denial_create(denial_t* denial);

/**
 * Get a denial object from the database by an id specified in `id`.
 * \param[in] denial a denial_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int denial_get_by_id(denial_t* denial, int id);

/**
 * Update a denial object in the database.
 * \param[in] denial a denial_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int denial_update(denial_t* denial);

/**
 * Delete a denial object from the database.
 * \param[in] denial a denial_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int denial_delete(denial_t* denial);

/**
 * A list of denial objects.
 */
struct denial_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    denial_t* denial;
};

/**
 * Create a new denial object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a denial_list_t pointer or NULL on error.
 */
denial_list_t* denial_list_new(const db_connection_t* connection);

/**
 * Delete a denial object list
 * \param[in] denial_list a denial_list_t pointer.
 */
void denial_list_free(denial_list_t* denial_list);

/**
 * Get all denial objects.
 * \param[in] denial_list a denial_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int denial_list_get(denial_list_t* denial_list);

/**
 * Get the first denial object in a denial object list. This will reset the position of the list.
 * \param[in] denial_list a denial_list_t pointer.
 * \return a denial_t pointer or NULL on error or if there are no
 * denial objects in the denial object list.
 */
const denial_t* denial_list_begin(denial_list_t* denial_list);

/**
 * Get the next denial object in a denial object list.
 * \param[in] denial_list a denial_list_t pointer.
 * \return a denial_t pointer or NULL on error or if there are no more
 * denial objects in the denial object list.
 */
const denial_t* denial_list_next(denial_list_t* denial_list);

#ifdef __cplusplus
}
#endif

#endif
