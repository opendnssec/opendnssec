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
typedef struct adapter adapter_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A adapter object.
 */
struct adapter {
    db_object_t* dbo;
    int id;
    char* file;
    char* type;
    char* adapter;
};

/**
 * Create a new adapter object.
 * \param[in] connection a db_connection_t pointer.
 * \return an adapter_t pointer or NULL on error.
 */
adapter_t* adapter_new(const db_connection_t* connection);

/**
 * Delete an adapter object, this does not delete it from the database.
 * \param[in] adapter an adapter_t pointer.
 */
void adapter_free(adapter_t* adapter);

/**
 * Reset the content of an adapter object making it as if its new. This does not
 * change anything in the database.
 * \param[in] adapter an adapter_t pointer.
 */
void adapter_reset(adapter_t* adapter);

/**
 * Set the content of an adapter object based on a database result.
 * \param[in] adapter an adapter_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_from_result(adapter_t* adapter, const db_result_t* result);

/**
 * Get the ID of an adapter object. Undefined behavior if `adapter` is NULL.
 * \param[in] adapter an adapter_t pointer.
 * \return an integer.
 */
int adapter_id(const adapter_t* adapter);

/**
 * Get the file of an adapter object.
 * \param[in] adapter an adapter_t pointer.
 * \return a character pointer.
 */
const char* adapter_file(const adapter_t* adapter);

/**
 * Get the type of an adapter object.
 * \param[in] adapter an adapter_t pointer.
 * \return a character pointer.
 */
const char* adapter_type(const adapter_t* adapter);

/**
 * Get the adapter of an adapter object.
 * \param[in] adapter an adapter_t pointer.
 * \return a character pointer.
 */
const char* adapter_adapter(const adapter_t* adapter);

/**
 * Set the file of an adapter object.
 * \param[in] adapter an adapter_t pointer.
 * \param[in] file a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_set_file(adapter_t* adapter, const char* file);

/**
 * Set the type of an adapter object.
 * \param[in] adapter an adapter_t pointer.
 * \param[in] type a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_set_type(adapter_t* adapter, const char* type);

/**
 * Set the adapter of an adapter object.
 * \param[in] adapter an adapter_t pointer.
 * \param[in] adapter a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_set_adapter(adapter_t* adapter, const char* adapter_text);

/**
 * Create an adapter object in the database.
 * \param[in] adapter an adapter_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_create(adapter_t* adapter);

/**
 * Get an adapter object from the database by an id specified in `id`.
 * \param[in] adapter an adapter_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_get_by_id(adapter_t* adapter, int id);

/**
 * Update an adapter object in the database.
 * \param[in] adapter an adapter_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_update(adapter_t* adapter);

/**
 * Delete an adapter object from the database.
 * \param[in] adapter an adapter_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int adapter_delete(adapter_t* adapter);

#ifdef __cplusplus
}
#endif

#endif
