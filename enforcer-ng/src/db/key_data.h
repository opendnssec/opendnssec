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

typedef enum key_data_keyrole {
    KEY_DATA_KEYROLE_INVALID = -1,
    KEY_DATA_KEYROLE_KSK = 1,
    KEY_DATA_KEYROLE_ZSK = 2,
    KEY_DATA_KEYROLE_CSK = 3
} key_data_keyrole_t;

typedef enum key_data_dsatparent {
    KEY_DATA_DSATPARENT_INVALID = -1,
    KEY_DATA_DSATPARENT_UNSUBMITTED = 0,
    KEY_DATA_DSATPARENT_SUBMIT = 1,
    KEY_DATA_DSATPARENT_SUBMITTED = 2,
    KEY_DATA_DSATPARENT_SEEN = 3,
    KEY_DATA_DSATPARENT_RETRACT = 4,
    KEY_DATA_DSATPARENT_RETRACTED = 5
} key_data_dsatparent_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "key_state.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A key data object.
 */
struct key_data {
    db_object_t* dbo;
    int id;
    char* locator;
    int algorithm;
    int inception;
    key_data_keyrole_t role;
    int introducing;
    int shouldrevoke;
    int standby;
    int active_zsk;
    int publish;
    int active_ksk;
    key_data_dsatparent_t ds_at_parent;
    int keytag;

    /* foreign key */
    int ds;
    int rrsig;
    int dnskey;
    int rrsigdnskey;
    key_state_t* key_state_ds;
    key_state_t* key_state_rrsig;
    key_state_t* key_state_dnskey;
    key_state_t* key_state_rrsigdnskey;
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
 * Reset the content of a key data object making it as if its new. This does not
 * change anything in the database.
 * \param[in] key_data a key_data_t pointer.
 */
void key_data_reset(key_data_t* key_data);

/**
 * Set the content of a key data object based on a database result.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_from_result(key_data_t* key_data, const db_result_t* result);

/**
 * Get the ID of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an integer.
 */
int key_data_id(const key_data_t* key_data);

/**
 * Get the locator of a key data object. Undefined behavior if `key_data` is
 * NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return a character pointer.
 */
const char* key_data_locator(const key_data_t* key_data);

/**
 * Get the algorithm of a key data object. Undefined behavior if `key_data` is
 * NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an integer.
 */
int key_data_algorithm(const key_data_t* key_data);

/**
 * Get the inception of a key data object. Undefined behavior if `key_data` is
 * NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an integer.
 */
int key_data_inception(const key_data_t* key_data);

/**
 * Get the role of a key data object. Undefined behavior if `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_data_keyrole_t.
 */
key_data_keyrole_t key_data_role(const key_data_t* key_data);

/**
 * Get the role as text of a key data object. Undefined behavior if `key_data`
 * is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return a character pointer.
 */
const char* key_data_role_text(const key_data_t* key_data);

/**
 * Get the introducing of a key data object. Undefined behavior if `key_data` is
 * NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an integer.
 */
int key_data_introducing(const key_data_t* key_data);

/**
 * Get the shouldrevoke of a key data object. Undefined behavior if `key_data`
 * is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an integer.
 */
int key_data_shouldrevoke(const key_data_t* key_data);

/**
 * Get the standby of a key data object. Undefined behavior if `key_data` is
 * NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an integer.
 */
int key_data_standby(const key_data_t* key_data);

/**
 * Get the active ZSK of a key data object. Undefined behavior if `key_data` is
 * NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an integer.
 */
int key_data_active_zsk(const key_data_t* key_data);

/**
 * Get the publish of a key data object. Undefined behavior if `key_data` is
 * NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an integer.
 */
int key_data_publish(const key_data_t* key_data);

/**
 * Get the active KSK of a key data object. Undefined behavior if `key_data` is
 * NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return an integer.
 */
int key_data_active_ksk(const key_data_t* key_data);

/**
 * Get the DS at parent of a key data object. Undefined behavior if `key_data`
 * is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_data_dsatparent_t.
 */
key_data_dsatparent_t key_data_ds_at_parent(const key_data_t* key_data);

/**
 * Get the DS at parent as text of a key data object. Undefined behavior if
 * `key_data` is NULL.
 * \param[in] key_data a key_data_t pointer.
 * \return a character pointer.
 */
const char* key_data_ds_at_parent_text(const key_data_t* key_data);

/**
 * Set the locator of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] locator a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_locator(key_data_t* key_data, const char* locator);

/**
 * Set the algorithm of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] algorithm an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_algorithm(key_data_t* key_data, int algorithm);

/**
 * Set the inception of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] inception an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_inception(key_data_t* key_data, int inception);

/**
 * Set the role of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] role a key_data_keyrole_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_role(key_data_t* key_data, key_data_keyrole_t role);

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
 * \param[in] introducing an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_introducing(key_data_t* key_data, int introducing);

/**
 * Set the shouldrevoke of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] shouldrevoke an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_shouldrevoke(key_data_t* key_data, int shouldrevoke);

/**
 * Set the standby of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] standby an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_standby(key_data_t* key_data, int standby);

/**
 * Set the active ZSK of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] active_zsk an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_active_zsk(key_data_t* key_data, int active_zsk);

/**
 * Set the publish of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] publish an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_publish(key_data_t* key_data, int publish);

/**
 * Set the active KSK of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] active_ksk an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_active_ksk(key_data_t* key_data, int active_ksk);

/**
 * Set the DS at parent of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] ds_at_parent a key_data_dsatparent_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_ds_at_parent(key_data_t* key_data, key_data_dsatparent_t ds_at_parent);

/**
 * Set the DS at parent of a key data object from text.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] ds_at_parent a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_set_ds_at_parent_text(key_data_t* key_data, const char* ds_at_parent);

/**
 * Get the key states objects for a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_get_key_state_list(key_data_t* key_data);

/**
 * Get the DS key state object of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
const key_state_t* key_data_get_ds(key_data_t* key_data);

/**
 * Get the RRSIG key state object of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
const key_state_t* key_data_get_rrsig(key_data_t* key_data);

/**
 * Get the DNSKEY key state object of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
const key_state_t* key_data_get_dnskey(key_data_t* key_data);

/**
 * Get the RRSIG DNSKEY key state object of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
const key_state_t* key_data_get_rrsigdnskey(key_data_t* key_data);

/**
 * Create a key data object in the database.
 * \param[in] key_data a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_create(key_data_t* key_data);

/**
 * Get a key data object from the database by an id specified in `id`.
 * \param[in] key_data a key_data_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_get_by_id(key_data_t* key_data, int id);

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
    key_data_t* key_data;
};

/**
 * Create a new key data object list.
 * \param[in] connection a db_connection_t pointer.
 * \return an key_data_list_t pointer or NULL on error.
 */
key_data_list_t* key_data_list_new(const db_connection_t* connection);

/**
 * Delete an key data object list
 * \param[in] key_data_list an key_data_list_t pointer.
 */
void key_data_list_free(key_data_list_t* key_data_list);

/**
 * Get all key data objects by an enforcer zone id specified in
 * `enforcer_zone_id`.
 * \param[in] key_data_list an key_data_list_t pointer.
 * \param[in] enforcer_zone_id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_list_get_by_enforcer_zone_id(key_data_list_t* key_data_list, int enforcer_zone_id);

/**
 * Get the first key data object in an key data object list. This will reset the
 * position of the list.
 * \param[in] key_data_list an key_data_list_t pointer.
 * \return a key_data_t pointer or NULL on error or if there are no
 * key data objects in the key data object list.
 */
const key_data_t* key_data_list_begin(key_data_list_t* key_data_list);

/**
 * Get the next key data object in an key data object list.
 * \param[in] key_data_list an key_data_list_t pointer.
 * \return a key_data_t pointer or NULL on error or if there are no more
 * key data objects in the key data object list.
 */
const key_data_t* key_data_list_next(key_data_list_t* key_data_list);

#ifdef __cplusplus
}
#endif

#endif
