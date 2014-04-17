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

#ifndef __parent_h
#define __parent_h

#ifdef __cplusplus
extern "C" {
#endif

struct parent;
struct parent_list;
typedef struct parent parent_t;
typedef struct parent_list parent_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "parent_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A parent object.
 */
struct parent {
    db_object_t* dbo;
    db_value_t id;
    int ttlds;
    int registrationdelay;
    int propagationdelay;
    int ttl;
    int min;
#include "parent_struct_ext.h"
};

/**
 * Create a new parent object.
 * \param[in] connection a db_connection_t pointer.
 * \return a parent_t pointer or NULL on error.
 */
parent_t* parent_new(const db_connection_t* connection);

/**
 * Delete a parent object, this does not delete it from the database.
 * \param[in] parent a parent_t pointer.
 */
void parent_free(parent_t* parent);

/**
 * Reset the content of a parent object making it as if its new. This does not change anything in the database.
 * \param[in] parent a parent_t pointer.
 */
void parent_reset(parent_t* parent);

/**
 * Copy the content of a parent object.
 * \param[in] parent a parent_t pointer.
 * \param[in] parent_copy a parent_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int parent_copy(parent_t* parent, const parent_t* parent_copy);

/**
 * Set the content of a parent object based on a database result.
 * \param[in] parent a parent_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int parent_from_result(parent_t* parent, const db_result_t* result);

/**
 * Get the id of a parent object. Undefined behavior if `parent` is NULL.
 * \param[in] parent a parent_t pointer.
 * \return a db_value_t pointer.
 */
const db_value_t* parent_id(const parent_t* parent);

/**
 * Get the ttlds of a parent object. Undefined behavior if `parent` is NULL.
 * \param[in] parent a parent_t pointer.
 * \return an integer.
 */
int parent_ttlds(const parent_t* parent);

/**
 * Get the registrationdelay of a parent object. Undefined behavior if `parent` is NULL.
 * \param[in] parent a parent_t pointer.
 * \return an integer.
 */
int parent_registrationdelay(const parent_t* parent);

/**
 * Get the propagationdelay of a parent object. Undefined behavior if `parent` is NULL.
 * \param[in] parent a parent_t pointer.
 * \return an integer.
 */
int parent_propagationdelay(const parent_t* parent);

/**
 * Get the ttl of a parent object. Undefined behavior if `parent` is NULL.
 * \param[in] parent a parent_t pointer.
 * \return an integer.
 */
int parent_ttl(const parent_t* parent);

/**
 * Get the min of a parent object. Undefined behavior if `parent` is NULL.
 * \param[in] parent a parent_t pointer.
 * \return an integer.
 */
int parent_min(const parent_t* parent);

/**
 * Set the ttlds of a parent object.
 * \param[in] parent a parent_t pointer.
 * \param[in] ttlds an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int parent_set_ttlds(parent_t* parent, int ttlds);

/**
 * Set the registrationdelay of a parent object.
 * \param[in] parent a parent_t pointer.
 * \param[in] registrationdelay an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int parent_set_registrationdelay(parent_t* parent, int registrationdelay);

/**
 * Set the propagationdelay of a parent object.
 * \param[in] parent a parent_t pointer.
 * \param[in] propagationdelay an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int parent_set_propagationdelay(parent_t* parent, int propagationdelay);

/**
 * Set the ttl of a parent object.
 * \param[in] parent a parent_t pointer.
 * \param[in] ttl an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int parent_set_ttl(parent_t* parent, int ttl);

/**
 * Set the min of a parent object.
 * \param[in] parent a parent_t pointer.
 * \param[in] min an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int parent_set_min(parent_t* parent, int min);

/**
 * Create a parent object in the database.
 * \param[in] parent a parent_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int parent_create(parent_t* parent);

/**
 * Get a parent object from the database by an id specified in `id`.
 * \param[in] parent a parent_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int parent_get_by_id(parent_t* parent, const db_value_t* id);

/**
 * Update a parent object in the database.
 * \param[in] parent a parent_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int parent_update(parent_t* parent);

/**
 * Delete a parent object from the database.
 * \param[in] parent a parent_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int parent_delete(parent_t* parent);

/**
 * A list of parent objects.
 */
struct parent_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    parent_t* parent;
};

/**
 * Create a new parent object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a parent_list_t pointer or NULL on error.
 */
parent_list_t* parent_list_new(const db_connection_t* connection);

/**
 * Delete a parent object list
 * \param[in] parent_list a parent_list_t pointer.
 */
void parent_list_free(parent_list_t* parent_list);

/**
 * Get all parent objects.
 * \param[in] parent_list a parent_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int parent_list_get(parent_list_t* parent_list);

/**
 * Get the first parent object in a parent object list. This will reset the position of the list.
 * \param[in] parent_list a parent_list_t pointer.
 * \return a parent_t pointer or NULL on error or if there are no
 * parent objects in the parent object list.
 */
const parent_t* parent_list_begin(parent_list_t* parent_list);

/**
 * Get the next parent object in a parent object list.
 * \param[in] parent_list a parent_list_t pointer.
 * \return a parent_t pointer or NULL on error or if there are no more
 * parent objects in the parent object list.
 */
const parent_t* parent_list_next(parent_list_t* parent_list);

#ifdef __cplusplus
}
#endif

#endif
