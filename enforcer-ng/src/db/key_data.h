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

#ifndef __key_data_h
#define __key_data_h

#ifdef __cplusplus
extern "C" {
#endif

struct key_data;
struct key_data_list;
typedef struct key_data key_data_t;
typedef struct key_data_list key_data_list_t;

typedef enum key_data_role {
    KEY_DATA_ROLE_INVALID = -1,
    KEY_DATA_ROLE_KSK = 1,
    KEY_DATA_ROLE_ZSK = 2,
    KEY_DATA_ROLE_CSK = 3
} key_data_role_t;

typedef enum key_data_ds_at_parent {
    KEY_DATA_DS_AT_PARENT_INVALID = -1,
    KEY_DATA_DS_AT_PARENT_UNSUBMITTED = 0,
    KEY_DATA_DS_AT_PARENT_SUBMIT = 1,
    KEY_DATA_DS_AT_PARENT_SUBMITTED = 2,
    KEY_DATA_DS_AT_PARENT_SEEN = 3,
    KEY_DATA_DS_AT_PARENT_RETRACT = 4,
    KEY_DATA_DS_AT_PARENT_RETRACTED = 5
} key_data_ds_at_parent_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "key_data_ext.h"
#include "key_state.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A key data object.
 */
struct key_data {
    db_object_t* dbo;
    db_value_t id;
    char* locator;
    unsigned int algorithm;
    unsigned int inception;
    db_value_t ds;
    db_value_t rrsig;
    db_value_t dnskey;
    key_data_role_t role;
    unsigned int introducing;
    unsigned int shouldrevoke;
    unsigned int standby;
    unsigned int active_zsk;
    unsigned int publish;
    db_value_t rrsigdnskey;
    unsigned int active_ksk;
    key_data_ds_at_parent_t ds_at_parent;
    unsigned int keytag;
#include "key_data_struct_ext.h"
};

/**
 * Create a new key data object.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_data_t pointer or NULL on error.
 */
key_data_t* key_data_new(const db_connection_t* connection);

/**
 * Delete a key data object, this does not delete it from the database.
 * \param[in] key_data a key_data_t pointer.
 */
void key_data_free(key_data_t* key_data);

/**
 * Reset the content of a key data object making it as if its new. This does not change anything in the database.
 * \param[in] key_data a key_data_t pointer.
 */
void key_data_reset(key_data_t* key_data);

/**
 * Copy the content of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] key_data_copy a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_copy(key_data_t* key_data, const key_data_t* key_data_copy);

/**
 * Set the content of a key data object based on a database result.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_from_result(key_data_t* key_data, const db_result_t* result);

/**
 * Get the id of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* key_data_id(const key_data_t* key_data);

/**
 * Get the locator of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a character pointer or NULL on error or if no locator has been set.
 */
const char* key_data_locator(const key_data_t* key_data);

/**
 * Get the algorithm of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_data_algorithm(const key_data_t* key_data);

/**
 * Get the inception of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_data_inception(const key_data_t* key_data);

/**
 * Get the ds of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* key_data_ds(const key_data_t* key_data);

/**
 * Get the ds object related to a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer or NULL on error or if no object could be found.
 */
key_state_t* key_data_get_ds(const key_data_t* key_data);

/**
 * Get the rrsig of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* key_data_rrsig(const key_data_t* key_data);

/**
 * Get the rrsig object related to a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer or NULL on error or if no object could be found.
 */
key_state_t* key_data_get_rrsig(const key_data_t* key_data);

/**
 * Get the dnskey of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* key_data_dnskey(const key_data_t* key_data);

/**
 * Get the dnskey object related to a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer or NULL on error or if no object could be found.
 */
key_state_t* key_data_get_dnskey(const key_data_t* key_data);

/**
 * Get the role of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_data_role_t which may be KEY_DATA_ROLE_INVALID on error or if no role has been set.
 */
key_data_role_t key_data_role(const key_data_t* key_data);

/**
 * Get the role as text of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a character pointer or NULL on error or if no role has been set.
 */
const char* key_data_role_text(const key_data_t* key_data);

/**
 * Get the introducing of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_data_introducing(const key_data_t* key_data);

/**
 * Get the shouldrevoke of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_data_shouldrevoke(const key_data_t* key_data);

/**
 * Get the standby of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_data_standby(const key_data_t* key_data);

/**
 * Get the active_zsk of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_data_active_zsk(const key_data_t* key_data);

/**
 * Get the publish of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_data_publish(const key_data_t* key_data);

/**
 * Get the rrsigdnskey of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* key_data_rrsigdnskey(const key_data_t* key_data);

/**
 * Get the rrsigdnskey object related to a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer or NULL on error or if no object could be found.
 */
key_state_t* key_data_get_rrsigdnskey(const key_data_t* key_data);

/**
 * Get the active_ksk of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_data_active_ksk(const key_data_t* key_data);

/**
 * Get the ds_at_parent of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_data_ds_at_parent_t which may be KEY_DATA_DS_AT_PARENT_INVALID on error or if no ds_at_parent has been set.
 */
key_data_ds_at_parent_t key_data_ds_at_parent(const key_data_t* key_data);

/**
 * Get the ds_at_parent as text of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a character pointer or NULL on error or if no ds_at_parent has been set.
 */
const char* key_data_ds_at_parent_text(const key_data_t* key_data);

/**
 * Get the keytag of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an unsigned integer.
 */
unsigned int key_data_keytag(const key_data_t* key_data);

/**
 * Set the locator of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] locator_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_locator(key_data_t* key_data, const char* locator_text);

/**
 * Set the algorithm of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] algorithm an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_algorithm(key_data_t* key_data, unsigned int algorithm);

/**
 * Set the inception of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] inception an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_inception(key_data_t* key_data, unsigned int inception);

/**
 * Set the ds of a key data object. If this fails the original value may have been lost.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] ds a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_ds(key_data_t* key_data, const db_value_t* ds);

/**
 * Set the rrsig of a key data object. If this fails the original value may have been lost.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] rrsig a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_rrsig(key_data_t* key_data, const db_value_t* rrsig);

/**
 * Set the dnskey of a key data object. If this fails the original value may have been lost.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] dnskey a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_dnskey(key_data_t* key_data, const db_value_t* dnskey);

/**
 * Set the role of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] role a key_data_role_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_role(key_data_t* key_data, key_data_role_t role);

/**
 * Set the role of a key data object from text.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] role a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_role_text(key_data_t* key_data, const char* role);

/**
 * Set the introducing of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] introducing an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_introducing(key_data_t* key_data, unsigned int introducing);

/**
 * Set the shouldrevoke of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] shouldrevoke an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_shouldrevoke(key_data_t* key_data, unsigned int shouldrevoke);

/**
 * Set the standby of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] standby an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_standby(key_data_t* key_data, unsigned int standby);

/**
 * Set the active_zsk of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] active_zsk an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_active_zsk(key_data_t* key_data, unsigned int active_zsk);

/**
 * Set the publish of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] publish an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_publish(key_data_t* key_data, unsigned int publish);

/**
 * Set the rrsigdnskey of a key data object. If this fails the original value may have been lost.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] rrsigdnskey a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_rrsigdnskey(key_data_t* key_data, const db_value_t* rrsigdnskey);

/**
 * Set the active_ksk of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] active_ksk an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_active_ksk(key_data_t* key_data, unsigned int active_ksk);

/**
 * Set the ds_at_parent of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] ds_at_parent a key_data_ds_at_parent_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_ds_at_parent(key_data_t* key_data, key_data_ds_at_parent_t ds_at_parent);

/**
 * Set the ds_at_parent of a key data object from text.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] ds_at_parent a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_ds_at_parent_text(key_data_t* key_data, const char* ds_at_parent);

/**
 * Set the keytag of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] keytag an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_keytag(key_data_t* key_data, unsigned int keytag);

/**
 * Create a key data object in the database.
 * \param[in] key_data a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_create(key_data_t* key_data);

/**
 * Get a key data object from the database by an id specified in `id`.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_get_by_id(key_data_t* key_data, const db_value_t* id);

/**
 * Update a key data object in the database.
 * \param[in] key_data a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_update(key_data_t* key_data);

/**
 * Delete a key data object from the database.
 * \param[in] key_data a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_delete(key_data_t* key_data);

/**
 * A list of key data objects.
 */
struct key_data_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    key_data_t* key_data;
};

/**
 * Create a new key data object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_data_list_t pointer or NULL on error.
 */
key_data_list_t* key_data_list_new(const db_connection_t* connection);

/**
 * Delete a key data object list
 * \param[in] key_data_list a key_data_list_t pointer.
 */
void key_data_list_free(key_data_list_t* key_data_list);

/**
 * Get all key data objects.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_list_get(key_data_list_t* key_data_list);

/**
 * Get the first key data object in a key data object list. This will reset the position of the list.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \return a key_data_t pointer or NULL on error or if there are no
 * key data objects in the key data object list.
 */
const key_data_t* key_data_list_begin(key_data_list_t* key_data_list);

/**
 * Get the next key data object in a key data object list.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \return a key_data_t pointer or NULL on error or if there are no more
 * key data objects in the key data object list.
 */
const key_data_t* key_data_list_next(key_data_list_t* key_data_list);

#ifdef __cplusplus
}
#endif

#endif
