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

#ifndef __ksk_h
#define __ksk_h

#ifdef __cplusplus
extern "C" {
#endif

struct ksk;
struct ksk_list;
typedef struct ksk ksk_t;
typedef struct ksk_list ksk_list_t;

typedef enum ksk_rollover_type {
    KSK_ROLLOVER_TYPE_INVALID = -1,
    KSK_ROLLOVER_TYPE_DOUBLE_RRSET = 0,
    KSK_ROLLOVER_TYPE_DOUBLE_DS = 2,
    KSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE = 4
} ksk_rollover_type_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "ksk_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A ksk object.
 */
struct ksk {
    db_object_t* dbo;
    int id;
    unsigned int algorithm;
    unsigned int bits;
    int lifetime;
    char* repository;
    unsigned int standby;
    unsigned int manual_rollover;
    unsigned int rfc5011;
    ksk_rollover_type_t rollover_type;
#include "ksk_struct_ext.h"
};

/**
 * Create a new ksk object.
 * \param[in] connection a db_connection_t pointer.
 * \return a ksk_t pointer or NULL on error.
 */
ksk_t* ksk_new(const db_connection_t* connection);

/**
 * Delete a ksk object, this does not delete it from the database.
 * \param[in] ksk a ksk_t pointer.
 */
void ksk_free(ksk_t* ksk);

/**
 * Reset the content of a ksk object making it as if its new. This does not change anything in the database.
 * \param[in] ksk a ksk_t pointer.
 */
void ksk_reset(ksk_t* ksk);

/**
 * Copy the content of a ksk object.
 * \param[in] ksk a ksk_t pointer.
 * \param[in] ksk_copy a ksk_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_copy(ksk_t* ksk, const ksk_t* ksk_copy);

/**
 * Set the content of a ksk object based on a database result.
 * \param[in] ksk a ksk_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_from_result(ksk_t* ksk, const db_result_t* result);

/**
 * Get the ID of a ksk object. Undefined behavior if `ksk` is NULL.
 * \param[in] ksk a ksk_t pointer.
 * \return an integer.
 */
int ksk_id(const ksk_t* ksk);

/**
 * Get the algorithm of a ksk object. Undefined behavior if `ksk` is NULL.
 * \param[in] ksk a ksk_t pointer.
 * \return an unsigned integer.
 */
unsigned int ksk_algorithm(const ksk_t* ksk);

/**
 * Get the bits of a ksk object. Undefined behavior if `ksk` is NULL.
 * \param[in] ksk a ksk_t pointer.
 * \return an unsigned integer.
 */
unsigned int ksk_bits(const ksk_t* ksk);

/**
 * Get the lifetime of a ksk object. Undefined behavior if `ksk` is NULL.
 * \param[in] ksk a ksk_t pointer.
 * \return an integer.
 */
int ksk_lifetime(const ksk_t* ksk);

/**
 * Get the repository of a ksk object.
 * \param[in] ksk a ksk_t pointer.
 * \return a character pointer or NULL on error or if no repository has been set.
 */
const char* ksk_repository(const ksk_t* ksk);

/**
 * Get the standby of a ksk object. Undefined behavior if `ksk` is NULL.
 * \param[in] ksk a ksk_t pointer.
 * \return an unsigned integer.
 */
unsigned int ksk_standby(const ksk_t* ksk);

/**
 * Get the manual_rollover of a ksk object. Undefined behavior if `ksk` is NULL.
 * \param[in] ksk a ksk_t pointer.
 * \return an unsigned integer.
 */
unsigned int ksk_manual_rollover(const ksk_t* ksk);

/**
 * Get the rfc5011 of a ksk object. Undefined behavior if `ksk` is NULL.
 * \param[in] ksk a ksk_t pointer.
 * \return an unsigned integer.
 */
unsigned int ksk_rfc5011(const ksk_t* ksk);

/**
 * Get the rollover_type of a ksk object.
 * \param[in] ksk a ksk_t pointer.
 * \return a ksk_rollover_type_t which may be KSK_ROLLOVER_TYPE_INVALID on error or if no rollover_type has been set.
 */
ksk_rollover_type_t ksk_rollover_type(const ksk_t* ksk);

/**
 * Get the rollover_type as text of a ksk object.
 * \param[in] ksk a ksk_t pointer.
 * \return a character pointer or NULL on error or if no rollover_type has been set.
 */
const char* ksk_rollover_type_text(const ksk_t* ksk);

/**
 * Set the algorithm of a ksk object.
 * \param[in] ksk a ksk_t pointer.
 * \param[in] algorithm an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_set_algorithm(ksk_t* ksk, unsigned int algorithm);

/**
 * Set the bits of a ksk object.
 * \param[in] ksk a ksk_t pointer.
 * \param[in] bits an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_set_bits(ksk_t* ksk, unsigned int bits);

/**
 * Set the lifetime of a ksk object.
 * \param[in] ksk a ksk_t pointer.
 * \param[in] lifetime an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_set_lifetime(ksk_t* ksk, int lifetime);

/**
 * Set the repository of a ksk object.
 * \param[in] ksk a ksk_t pointer.
 * \param[in] repository_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_set_repository(ksk_t* ksk, const char* repository_text);

/**
 * Set the standby of a ksk object.
 * \param[in] ksk a ksk_t pointer.
 * \param[in] standby an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_set_standby(ksk_t* ksk, unsigned int standby);

/**
 * Set the manual_rollover of a ksk object.
 * \param[in] ksk a ksk_t pointer.
 * \param[in] manual_rollover an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_set_manual_rollover(ksk_t* ksk, unsigned int manual_rollover);

/**
 * Set the rfc5011 of a ksk object.
 * \param[in] ksk a ksk_t pointer.
 * \param[in] rfc5011 an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_set_rfc5011(ksk_t* ksk, unsigned int rfc5011);

/**
 * Set the rollover_type of a ksk object.
 * \param[in] ksk a ksk_t pointer.
 * \param[in] rollover_type a ksk_rollover_type_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_set_rollover_type(ksk_t* ksk, ksk_rollover_type_t rollover_type);

/**
 * Set the rollover_type of a ksk object from text.
 * \param[in] ksk a ksk_t pointer.
 * \param[in] rollover_type a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_set_rollover_type_text(ksk_t* ksk, const char* rollover_type);

/**
 * Create a ksk object in the database.
 * \param[in] ksk a ksk_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_create(ksk_t* ksk);

/**
 * Get a ksk object from the database by an id specified in `id`.
 * \param[in] ksk a ksk_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_get_by_id(ksk_t* ksk, int id);

/**
 * Update a ksk object in the database.
 * \param[in] ksk a ksk_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_update(ksk_t* ksk);

/**
 * Delete a ksk object from the database.
 * \param[in] ksk a ksk_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_delete(ksk_t* ksk);

/**
 * A list of ksk objects.
 */
struct ksk_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    ksk_t* ksk;
};

/**
 * Create a new ksk object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a ksk_list_t pointer or NULL on error.
 */
ksk_list_t* ksk_list_new(const db_connection_t* connection);

/**
 * Delete a ksk object list
 * \param[in] ksk_list a ksk_list_t pointer.
 */
void ksk_list_free(ksk_list_t* ksk_list);

/**
 * Get all ksk objects.
 * \param[in] ksk_list a ksk_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ksk_list_get(ksk_list_t* ksk_list);

/**
 * Get the first ksk object in a ksk object list. This will reset the position of the list.
 * \param[in] ksk_list a ksk_list_t pointer.
 * \return a ksk_t pointer or NULL on error or if there are no
 * ksk objects in the ksk object list.
 */
const ksk_t* ksk_list_begin(ksk_list_t* ksk_list);

/**
 * Get the next ksk object in a ksk object list.
 * \param[in] ksk_list a ksk_list_t pointer.
 * \return a ksk_t pointer or NULL on error or if there are no more
 * ksk objects in the ksk object list.
 */
const ksk_t* ksk_list_next(ksk_list_t* ksk_list);

#ifdef __cplusplus
}
#endif

#endif
