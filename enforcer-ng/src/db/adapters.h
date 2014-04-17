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

#ifndef __adapters_h
#define __adapters_h

#ifdef __cplusplus
extern "C" {
#endif

struct adapters;
struct adapters_list;
typedef struct adapters adapters_t;
typedef struct adapters_list adapters_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "adapters_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A adapters object.
 */
struct adapters {
    db_object_t* dbo;
    int id;
    int input;
    int output;
#include "adapters_struct_ext.h"
};

/**
 * Create a new adapters object.
 * \param[in] connection a db_connection_t pointer.
 * \return a adapters_t pointer or NULL on error.
 */
adapters_t* adapters_new(const db_connection_t* connection);

/**
 * Delete a adapters object, this does not delete it from the database.
 * \param[in] adapters a adapters_t pointer.
 */
void adapters_free(adapters_t* adapters);

/**
 * Reset the content of a adapters object making it as if its new. This does not change anything in the database.
 * \param[in] adapters a adapters_t pointer.
 */
void adapters_reset(adapters_t* adapters);

/**
 * Copy the content of a adapters object.
 * \param[in] adapters a adapters_t pointer.
 * \param[in] adapters_copy a adapters_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapters_copy(adapters_t* adapters, const adapters_t* adapters_copy);

/**
 * Set the content of a adapters object based on a database result.
 * \param[in] adapters a adapters_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapters_from_result(adapters_t* adapters, const db_result_t* result);

/**
 * Get the ID of a adapters object. Undefined behavior if `adapters` is NULL.
 * \param[in] adapters a adapters_t pointer.
 * \return an integer.
 */
int adapters_id(const adapters_t* adapters);

/**
 * Get the input of a adapters object. Undefined behavior if `adapters` is NULL.
 * \param[in] adapters a adapters_t pointer.
 * \return an integer.
 */
int adapters_input(const adapters_t* adapters);

/**
 * Get the output of a adapters object. Undefined behavior if `adapters` is NULL.
 * \param[in] adapters a adapters_t pointer.
 * \return an integer.
 */
int adapters_output(const adapters_t* adapters);

/**
 * Set the input of a adapters object.
 * \param[in] adapters a adapters_t pointer.
 * \param[in] input an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapters_set_input(adapters_t* adapters, int input);

/**
 * Set the output of a adapters object.
 * \param[in] adapters a adapters_t pointer.
 * \param[in] output an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapters_set_output(adapters_t* adapters, int output);

/**
 * Create a adapters object in the database.
 * \param[in] adapters a adapters_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapters_create(adapters_t* adapters);

/**
 * Get a adapters object from the database by an id specified in `id`.
 * \param[in] adapters a adapters_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapters_get_by_id(adapters_t* adapters, int id);

/**
 * Update a adapters object in the database.
 * \param[in] adapters a adapters_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapters_update(adapters_t* adapters);

/**
 * Delete a adapters object from the database.
 * \param[in] adapters a adapters_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapters_delete(adapters_t* adapters);

/**
 * A list of adapters objects.
 */
struct adapters_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    adapters_t* adapters;
};

/**
 * Create a new adapters object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a adapters_list_t pointer or NULL on error.
 */
adapters_list_t* adapters_list_new(const db_connection_t* connection);

/**
 * Delete a adapters object list
 * \param[in] adapters_list a adapters_list_t pointer.
 */
void adapters_list_free(adapters_list_t* adapters_list);

/**
 * Get all adapters objects.
 * \param[in] adapters_list a adapters_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapters_list_get(adapters_list_t* adapters_list);

/**
 * Get the first adapters object in a adapters object list. This will reset the position of the list.
 * \param[in] adapters_list a adapters_list_t pointer.
 * \return a adapters_t pointer or NULL on error or if there are no
 * adapters objects in the adapters object list.
 */
const adapters_t* adapters_list_begin(adapters_list_t* adapters_list);

/**
 * Get the next adapters object in a adapters object list.
 * \param[in] adapters_list a adapters_list_t pointer.
 * \return a adapters_t pointer or NULL on error or if there are no more
 * adapters objects in the adapters object list.
 */
const adapters_t* adapters_list_next(adapters_list_t* adapters_list);

#ifdef __cplusplus
}
#endif

#endif
