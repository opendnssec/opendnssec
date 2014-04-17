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

#ifndef __adapter_h
#define __adapter_h

#ifdef __cplusplus
extern "C" {
#endif

struct adapter;
struct adapter_list;
typedef struct adapter adapter_t;
typedef struct adapter_list adapter_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "adapter_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A adapter object.
 */
struct adapter {
    db_object_t* dbo;
    int id;
    char* adapter;
    char* type;
    char* file;
#include "adapter_struct_ext.h"
};

/**
 * Create a new adapter object.
 * \param[in] connection a db_connection_t pointer.
 * \return a adapter_t pointer or NULL on error.
 */
adapter_t* adapter_new(const db_connection_t* connection);

/**
 * Delete a adapter object, this does not delete it from the database.
 * \param[in] adapter a adapter_t pointer.
 */
void adapter_free(adapter_t* adapter);

/**
 * Reset the content of a adapter object making it as if its new. This does not change anything in the database.
 * \param[in] adapter a adapter_t pointer.
 */
void adapter_reset(adapter_t* adapter);

/**
 * Copy the content of a adapter object.
 * \param[in] adapter a adapter_t pointer.
 * \param[in] adapter_copy a adapter_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_copy(adapter_t* adapter, const adapter_t* adapter_copy);

/**
 * Set the content of a adapter object based on a database result.
 * \param[in] adapter a adapter_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_from_result(adapter_t* adapter, const db_result_t* result);

/**
 * Get the ID of a adapter object. Undefined behavior if `adapter` is NULL.
 * \param[in] adapter a adapter_t pointer.
 * \return an integer.
 */
int adapter_id(const adapter_t* adapter);

/**
 * Get the adapter of a adapter object.
 * \param[in] adapter a adapter_t pointer.
 * \return a character pointer or NULL on error or if no adapter has been set.
 */
const char* adapter_adapter(const adapter_t* adapter);

/**
 * Get the type of a adapter object.
 * \param[in] adapter a adapter_t pointer.
 * \return a character pointer or NULL on error or if no type has been set.
 */
const char* adapter_type(const adapter_t* adapter);

/**
 * Get the file of a adapter object.
 * \param[in] adapter a adapter_t pointer.
 * \return a character pointer or NULL on error or if no file has been set.
 */
const char* adapter_file(const adapter_t* adapter);

/**
 * Set the adapter of a adapter object.
 * \param[in] adapter a adapter_t pointer.
 * \param[in] adapter_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_set_adapter(adapter_t* adapter, const char* adapter_text);

/**
 * Set the type of a adapter object.
 * \param[in] adapter a adapter_t pointer.
 * \param[in] type_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_set_type(adapter_t* adapter, const char* type_text);

/**
 * Set the file of a adapter object.
 * \param[in] adapter a adapter_t pointer.
 * \param[in] file_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_set_file(adapter_t* adapter, const char* file_text);

/**
 * Create a adapter object in the database.
 * \param[in] adapter a adapter_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_create(adapter_t* adapter);

/**
 * Get a adapter object from the database by an id specified in `id`.
 * \param[in] adapter a adapter_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_get_by_id(adapter_t* adapter, int id);

/**
 * Update a adapter object in the database.
 * \param[in] adapter a adapter_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_update(adapter_t* adapter);

/**
 * Delete a adapter object from the database.
 * \param[in] adapter a adapter_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_delete(adapter_t* adapter);

/**
 * A list of adapter objects.
 */
struct adapter_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    adapter_t* adapter;
};

/**
 * Create a new adapter object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a adapter_list_t pointer or NULL on error.
 */
adapter_list_t* adapter_list_new(const db_connection_t* connection);

/**
 * Delete a adapter object list
 * \param[in] adapter_list a adapter_list_t pointer.
 */
void adapter_list_free(adapter_list_t* adapter_list);

/**
 * Get all adapter objects.
 * \param[in] adapter_list a adapter_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_list_get(adapter_list_t* adapter_list);

/**
 * Get the first adapter object in a adapter object list. This will reset the position of the list.
 * \param[in] adapter_list a adapter_list_t pointer.
 * \return a adapter_t pointer or NULL on error or if there are no
 * adapter objects in the adapter object list.
 */
const adapter_t* adapter_list_begin(adapter_list_t* adapter_list);

/**
 * Get the next adapter object in a adapter object list.
 * \param[in] adapter_list a adapter_list_t pointer.
 * \return a adapter_t pointer or NULL on error or if there are no more
 * adapter objects in the adapter object list.
 */
const adapter_t* adapter_list_next(adapter_list_t* adapter_list);

#ifdef __cplusplus
}
#endif

#endif
