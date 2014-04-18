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

#ifndef __zsk_h
#define __zsk_h

#ifdef __cplusplus
extern "C" {
#endif

struct zsk;
struct zsk_list;
typedef struct zsk zsk_t;
typedef struct zsk_list zsk_list_t;

typedef enum zsk_rollover_type {
    ZSK_ROLLOVER_TYPE_INVALID = -1,
    ZSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE = 0,
    ZSK_ROLLOVER_TYPE_PREPUBLICATION = 1,
    ZSK_ROLLOVER_TYPE_DOUBLE_RRSIG = 2
} zsk_rollover_type_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "zsk_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A zsk object.
 */
struct zsk {
    db_object_t* dbo;
    db_value_t id;
    unsigned int algorithm;
    unsigned int bits;
    int lifetime;
    char* repository;
    unsigned int standby;
    unsigned int manual_rollover;
    zsk_rollover_type_t rollover_type;
#include "zsk_struct_ext.h"
};

/**
 * Create a new zsk object.
 * \param[in] connection a db_connection_t pointer.
 * \return a zsk_t pointer or NULL on error.
 */
zsk_t* zsk_new(const db_connection_t* connection);

/**
 * Delete a zsk object, this does not delete it from the database.
 * \param[in] zsk a zsk_t pointer.
 */
void zsk_free(zsk_t* zsk);

/**
 * Reset the content of a zsk object making it as if its new. This does not change anything in the database.
 * \param[in] zsk a zsk_t pointer.
 */
void zsk_reset(zsk_t* zsk);

/**
 * Copy the content of a zsk object.
 * \param[in] zsk a zsk_t pointer.
 * \param[in] zsk_copy a zsk_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_copy(zsk_t* zsk, const zsk_t* zsk_copy);

/**
 * Set the content of a zsk object based on a database result.
 * \param[in] zsk a zsk_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_from_result(zsk_t* zsk, const db_result_t* result);

/**
 * Get the id of a zsk object.
 * \param[in] zsk a zsk_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* zsk_id(const zsk_t* zsk);

/**
 * Get the algorithm of a zsk object. Undefined behavior if `zsk` is NULL.
 * \param[in] zsk a zsk_t pointer.
 * \return an unsigned integer.
 */
unsigned int zsk_algorithm(const zsk_t* zsk);

/**
 * Get the bits of a zsk object. Undefined behavior if `zsk` is NULL.
 * \param[in] zsk a zsk_t pointer.
 * \return an unsigned integer.
 */
unsigned int zsk_bits(const zsk_t* zsk);

/**
 * Get the lifetime of a zsk object. Undefined behavior if `zsk` is NULL.
 * \param[in] zsk a zsk_t pointer.
 * \return an integer.
 */
int zsk_lifetime(const zsk_t* zsk);

/**
 * Get the repository of a zsk object.
 * \param[in] zsk a zsk_t pointer.
 * \return a character pointer or NULL on error or if no repository has been set.
 */
const char* zsk_repository(const zsk_t* zsk);

/**
 * Get the standby of a zsk object. Undefined behavior if `zsk` is NULL.
 * \param[in] zsk a zsk_t pointer.
 * \return an unsigned integer.
 */
unsigned int zsk_standby(const zsk_t* zsk);

/**
 * Get the manual_rollover of a zsk object. Undefined behavior if `zsk` is NULL.
 * \param[in] zsk a zsk_t pointer.
 * \return an unsigned integer.
 */
unsigned int zsk_manual_rollover(const zsk_t* zsk);

/**
 * Get the rollover_type of a zsk object.
 * \param[in] zsk a zsk_t pointer.
 * \return a zsk_rollover_type_t which may be ZSK_ROLLOVER_TYPE_INVALID on error or if no rollover_type has been set.
 */
zsk_rollover_type_t zsk_rollover_type(const zsk_t* zsk);

/**
 * Get the rollover_type as text of a zsk object.
 * \param[in] zsk a zsk_t pointer.
 * \return a character pointer or NULL on error or if no rollover_type has been set.
 */
const char* zsk_rollover_type_text(const zsk_t* zsk);

/**
 * Set the algorithm of a zsk object.
 * \param[in] zsk a zsk_t pointer.
 * \param[in] algorithm an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_set_algorithm(zsk_t* zsk, unsigned int algorithm);

/**
 * Set the bits of a zsk object.
 * \param[in] zsk a zsk_t pointer.
 * \param[in] bits an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_set_bits(zsk_t* zsk, unsigned int bits);

/**
 * Set the lifetime of a zsk object.
 * \param[in] zsk a zsk_t pointer.
 * \param[in] lifetime an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_set_lifetime(zsk_t* zsk, int lifetime);

/**
 * Set the repository of a zsk object.
 * \param[in] zsk a zsk_t pointer.
 * \param[in] repository_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_set_repository(zsk_t* zsk, const char* repository_text);

/**
 * Set the standby of a zsk object.
 * \param[in] zsk a zsk_t pointer.
 * \param[in] standby an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_set_standby(zsk_t* zsk, unsigned int standby);

/**
 * Set the manual_rollover of a zsk object.
 * \param[in] zsk a zsk_t pointer.
 * \param[in] manual_rollover an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_set_manual_rollover(zsk_t* zsk, unsigned int manual_rollover);

/**
 * Set the rollover_type of a zsk object.
 * \param[in] zsk a zsk_t pointer.
 * \param[in] rollover_type a zsk_rollover_type_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_set_rollover_type(zsk_t* zsk, zsk_rollover_type_t rollover_type);

/**
 * Set the rollover_type of a zsk object from text.
 * \param[in] zsk a zsk_t pointer.
 * \param[in] rollover_type a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_set_rollover_type_text(zsk_t* zsk, const char* rollover_type);

/**
 * Create a zsk object in the database.
 * \param[in] zsk a zsk_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_create(zsk_t* zsk);

/**
 * Get a zsk object from the database by an id specified in `id`.
 * \param[in] zsk a zsk_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_get_by_id(zsk_t* zsk, const db_value_t* id);

/**
 * Update a zsk object in the database.
 * \param[in] zsk a zsk_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_update(zsk_t* zsk);

/**
 * Delete a zsk object from the database.
 * \param[in] zsk a zsk_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_delete(zsk_t* zsk);

/**
 * A list of zsk objects.
 */
struct zsk_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    zsk_t* zsk;
};

/**
 * Create a new zsk object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a zsk_list_t pointer or NULL on error.
 */
zsk_list_t* zsk_list_new(const db_connection_t* connection);

/**
 * Delete a zsk object list
 * \param[in] zsk_list a zsk_list_t pointer.
 */
void zsk_list_free(zsk_list_t* zsk_list);

/**
 * Get all zsk objects.
 * \param[in] zsk_list a zsk_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zsk_list_get(zsk_list_t* zsk_list);

/**
 * Get the first zsk object in a zsk object list. This will reset the position of the list.
 * \param[in] zsk_list a zsk_list_t pointer.
 * \return a zsk_t pointer or NULL on error or if there are no
 * zsk objects in the zsk object list.
 */
const zsk_t* zsk_list_begin(zsk_list_t* zsk_list);

/**
 * Get the next zsk object in a zsk object list.
 * \param[in] zsk_list a zsk_list_t pointer.
 * \return a zsk_t pointer or NULL on error or if there are no more
 * zsk objects in the zsk object list.
 */
const zsk_t* zsk_list_next(zsk_list_t* zsk_list);

#ifdef __cplusplus
}
#endif

#endif
