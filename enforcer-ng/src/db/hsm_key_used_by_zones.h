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

#ifndef __hsm_key_used_by_zones_h
#define __hsm_key_used_by_zones_h

#ifdef __cplusplus
extern "C" {
#endif

struct hsm_key_used_by_zones;
struct hsm_key_used_by_zones_list;
typedef struct hsm_key_used_by_zones hsm_key_used_by_zones_t;
typedef struct hsm_key_used_by_zones_list hsm_key_used_by_zones_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "hsm_key_used_by_zones_ext.h"
#include "dbo_hsm_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A hsm key used by zones object.
 */
struct hsm_key_used_by_zones {
    db_object_t* dbo;
    db_value_t id;
    char* value;
    db_value_t parent_id;
#include "hsm_key_used_by_zones_struct_ext.h"
};

/**
 * Create a new hsm key used by zones object.
 * \param[in] connection a db_connection_t pointer.
 * \return a hsm_key_used_by_zones_t pointer or NULL on error.
 */
hsm_key_used_by_zones_t* hsm_key_used_by_zones_new(const db_connection_t* connection);

/**
 * Delete a hsm key used by zones object, this does not delete it from the database.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 */
void hsm_key_used_by_zones_free(hsm_key_used_by_zones_t* hsm_key_used_by_zones);

/**
 * Reset the content of a hsm key used by zones object making it as if its new. This does not change anything in the database.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 */
void hsm_key_used_by_zones_reset(hsm_key_used_by_zones_t* hsm_key_used_by_zones);

/**
 * Copy the content of a hsm key used by zones object.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 * \param[in] hsm_key_used_by_zones_copy a hsm_key_used_by_zones_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_used_by_zones_copy(hsm_key_used_by_zones_t* hsm_key_used_by_zones, const hsm_key_used_by_zones_t* hsm_key_used_by_zones_copy);

/**
 * Set the content of a hsm key used by zones object based on a database result.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_used_by_zones_from_result(hsm_key_used_by_zones_t* hsm_key_used_by_zones, const db_result_t* result);

/**
 * Get the id of a hsm key used by zones object.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* hsm_key_used_by_zones_id(const hsm_key_used_by_zones_t* hsm_key_used_by_zones);

/**
 * Get the value of a hsm key used by zones object.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 * \return a character pointer or NULL on error or if no value has been set.
 */
const char* hsm_key_used_by_zones_value(const hsm_key_used_by_zones_t* hsm_key_used_by_zones);

/**
 * Get the parent_id of a hsm key used by zones object.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* hsm_key_used_by_zones_parent_id(const hsm_key_used_by_zones_t* hsm_key_used_by_zones);

/**
 * Get the parent_id object related to a hsm key used by zones object.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 * \return a dbo_hsm_key_t pointer or NULL on error or if no object could be found.
 */
dbo_hsm_key_t* hsm_key_used_by_zones_get_parent_id(const hsm_key_used_by_zones_t* hsm_key_used_by_zones);

/**
 * Set the value of a hsm key used by zones object.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 * \param[in] value_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_used_by_zones_set_value(hsm_key_used_by_zones_t* hsm_key_used_by_zones, const char* value_text);

/**
 * Set the parent_id of a hsm key used by zones object. If this fails the original value may have been lost.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 * \param[in] parent_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_used_by_zones_set_parent_id(hsm_key_used_by_zones_t* hsm_key_used_by_zones, const db_value_t* parent_id);

/**
 * Create a hsm key used by zones object in the database.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_used_by_zones_create(hsm_key_used_by_zones_t* hsm_key_used_by_zones);

/**
 * Get a hsm key used by zones object from the database by an id specified in `id`.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_used_by_zones_get_by_id(hsm_key_used_by_zones_t* hsm_key_used_by_zones, const db_value_t* id);

/**
 * Update a hsm key used by zones object in the database.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_used_by_zones_update(hsm_key_used_by_zones_t* hsm_key_used_by_zones);

/**
 * Delete a hsm key used by zones object from the database.
 * \param[in] hsm_key_used_by_zones a hsm_key_used_by_zones_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_used_by_zones_delete(hsm_key_used_by_zones_t* hsm_key_used_by_zones);

/**
 * A list of hsm key used by zones objects.
 */
struct hsm_key_used_by_zones_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    hsm_key_used_by_zones_t* hsm_key_used_by_zones;
};

/**
 * Create a new hsm key used by zones object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a hsm_key_used_by_zones_list_t pointer or NULL on error.
 */
hsm_key_used_by_zones_list_t* hsm_key_used_by_zones_list_new(const db_connection_t* connection);

/**
 * Delete a hsm key used by zones object list
 * \param[in] hsm_key_used_by_zones_list a hsm_key_used_by_zones_list_t pointer.
 */
void hsm_key_used_by_zones_list_free(hsm_key_used_by_zones_list_t* hsm_key_used_by_zones_list);

/**
 * Get all hsm key used by zones objects.
 * \param[in] hsm_key_used_by_zones_list a hsm_key_used_by_zones_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int hsm_key_used_by_zones_list_get(hsm_key_used_by_zones_list_t* hsm_key_used_by_zones_list);

/**
 * Get the first hsm key used by zones object in a hsm key used by zones object list. This will reset the position of the list.
 * \param[in] hsm_key_used_by_zones_list a hsm_key_used_by_zones_list_t pointer.
 * \return a hsm_key_used_by_zones_t pointer or NULL on error or if there are no
 * hsm key used by zones objects in the hsm key used by zones object list.
 */
const hsm_key_used_by_zones_t* hsm_key_used_by_zones_list_begin(hsm_key_used_by_zones_list_t* hsm_key_used_by_zones_list);

/**
 * Get the next hsm key used by zones object in a hsm key used by zones object list.
 * \param[in] hsm_key_used_by_zones_list a hsm_key_used_by_zones_list_t pointer.
 * \return a hsm_key_used_by_zones_t pointer or NULL on error or if there are no more
 * hsm key used by zones objects in the hsm key used by zones object list.
 */
const hsm_key_used_by_zones_t* hsm_key_used_by_zones_list_next(hsm_key_used_by_zones_list_t* hsm_key_used_by_zones_list);

#ifdef __cplusplus
}
#endif

#endif
