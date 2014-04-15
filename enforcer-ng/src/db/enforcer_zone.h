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

#ifndef __enforcer_zone_h
#define __enforcer_zone_h

#ifdef __cplusplus
extern "C" {
#endif

struct enforcer_zone;
struct enforcer_zone_list;
typedef struct enforcer_zone enforcer_zone_t;
typedef struct enforcer_zone_list enforcer_zone_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "key_data.h"
#include "adapter.h"
#include "key_dependency.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * An enforcer zone object.
 */
struct enforcer_zone {
    db_object_t* dbo;
    int id;
    char* name;
    char* policy;
    int signconf_needs_writing;
    char* signconf_path;
    int next_change;
    int ttl_end_ds;
    int ttl_end_dk;
    int ttl_end_rs;
    int roll_ksk_now;
    int roll_zsk_now;
    int roll_csk_now;
    int next_ksk_roll;
    int next_zsk_roll;
    int next_csk_roll;

    /* foreign key */
    int adapters;
};

/**
 * Create a new enforcer zone object.
 * \param[in] connection a db_connection_t pointer.
 * \return an enforcer_zone_t pointer or NULL on error.
 */
enforcer_zone_t* enforcer_zone_new(const db_connection_t* connection);

/**
 * Delete an enforcer zone object, this does not delete it from the database.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 */
void enforcer_zone_free(enforcer_zone_t* enforcer_zone);

/**
 * Reset an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 */
void enforcer_zone_reset(enforcer_zone_t* enforcer_zone);

/**
 * Set the content of an enforcer zone object based on a database result.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_from_result(enforcer_zone_t* enforcer_zone, const db_result_t* result);

/**
 * Get the ID of an enforcer zone object. Undefined behavior if `enforcer_zone`
 * is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_id(const enforcer_zone_t* enforcer_zone);

/**
 * Get the name of an enforcer zone object. Undefined behavior if
 * `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return a character pointer.
 */
const char* enforcer_zone_name(const enforcer_zone_t* enforcer_zone);

/**
 * Get the policy of an enforcer zone object. Undefined behavior if
 * `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return a character pointer.
 */
const char* enforcer_zone_policy(const enforcer_zone_t* enforcer_zone);

/**
 * Check if the signconf needs writing for an enforcer zone object. Undefined
 * behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_signconf_needs_writing(const enforcer_zone_t* enforcer_zone);

/**
 * Get the signconf path of an enforcer zone object. Undefined behavior if
 * `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return a character pointer.
 */
const char* enforcer_zone_signconf_path(const enforcer_zone_t* enforcer_zone);

/**
 * TODO: Describe next change.
 * Get the next change of an enforcer zone object. Undefined behavior if
 * `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_next_change(const enforcer_zone_t* enforcer_zone);

/**
 * TODO: Describe TTL End DS.
 * Get the TTL End DS of an enforcer zone object. Undefined behavior if
 * `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_ttl_end_ds(const enforcer_zone_t* enforcer_zone);

/**
 * TODO: Describe TTL End DK.
 * Get the TTL End DK of an enforcer zone object. Undefined behavior if
 * `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_ttl_end_dk(const enforcer_zone_t* enforcer_zone);

/**
 * TODO: Describe TTL End RS.
 * Get the TTL End RS of an enforcer zone object. Undefined behavior if
 * `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_ttl_end_rs(const enforcer_zone_t* enforcer_zone);

/**
 * Check if we should roll KSK for an enforcer zone object. Undefined behavior
 * if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_roll_ksk_now(const enforcer_zone_t* enforcer_zone);

/**
 * Check if we should roll ZSK for an enforcer zone object. Undefined behavior
 * if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_roll_zsk_now(const enforcer_zone_t* enforcer_zone);

/**
 * Check if we should roll CSK for an enforcer zone object. Undefined behavior
 * if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_roll_csk_now(const enforcer_zone_t* enforcer_zone);

/**
 * TODO: Describe next KSK roll.
 * Get the next KSK roll of an enforcer zone object. Undefined behavior if
 * `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_next_ksk_roll(const enforcer_zone_t* enforcer_zone);

/**
 * TODO: Describe next ZSK roll.
 * Get the next ZSK roll of an enforcer zone object. Undefined behavior if
 * `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_next_zsk_roll(const enforcer_zone_t* enforcer_zone);

/**
 * TODO: Describe next CSK roll.
 * Get the next CSK roll of an enforcer zone object. Undefined behavior if
 * `enforcer_zone` is NULL.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_next_csk_roll(const enforcer_zone_t* enforcer_zone);

/**
 * Set the name of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] name a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_name(enforcer_zone_t* enforcer_zone, const char* name);

/**
 * Set the policy of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] policy a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_policy(enforcer_zone_t* enforcer_zone, const char* policy);

/**
 * Set the signconf needs writing of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] signconf_needs_writing an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_signconf_needs_writing(enforcer_zone_t* enforcer_zone, int signconf_needs_writing);

/**
 * Set the signconf path of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] signconf_path a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_signconf_path(enforcer_zone_t* enforcer_zone, const char* signconf_path);

/**
 * Set the next change of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] next_change an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_next_change(enforcer_zone_t* enforcer_zone, int next_change);

/**
 * Set the TTL End DS of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] ttl_end_ds an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_ttl_end_ds(enforcer_zone_t* enforcer_zone, int ttl_end_ds);

/**
 * Set the TTL End DK of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] ttl_end_dk an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_ttl_end_dk(enforcer_zone_t* enforcer_zone, int ttl_end_dk);

/**
 * Set the TTL End RS of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] ttl_end_rs an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_ttl_end_rs(enforcer_zone_t* enforcer_zone, int ttl_end_rs);

/**
 * Set the roll KSK now of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] roll_ksk_now an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_roll_ksk_now(enforcer_zone_t* enforcer_zone, int roll_ksk_now);

/**
 * Set the roll ZSK now of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] roll_zsk_now an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_roll_zsk_now(enforcer_zone_t* enforcer_zone, int roll_zsk_now);

/**
 * Set the roll CSK now of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] roll_csk_now an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_roll_csk_now(enforcer_zone_t* enforcer_zone, int roll_csk_now);

/**
 * Set the next KSK roll of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] next_ksk_roll an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_next_ksk_roll(enforcer_zone_t* enforcer_zone, int next_ksk_roll);

/**
 * Set the next ZSK roll of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] next_zsk_roll an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_next_zsk_roll(enforcer_zone_t* enforcer_zone, int next_zsk_roll);

/**
 * Set the next CSK roll of an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] next_csk_roll an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_next_csk_roll(enforcer_zone_t* enforcer_zone, int next_csk_roll);

/**
 * Get a list of keys for an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return a key_data_list_t pointer or NULL on error or if there are no keys
 * in the enforcer zone object.
 */
key_data_list_t* enforcer_zone_get_keys(const enforcer_zone_t* enforcer_zone);

/**
 * Get a list of adapters for an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return a adapter_list_t pointer or NULL on error or if there are no adapters
 * in the enforcer zone object.
 */
adapter_list_t* enforcer_zone_get_adapters(const enforcer_zone_t* enforcer_zone);

/* TODO: Set adapters? */

/**
 * Get a list of key dependencies for an enforcer zone object.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return a key_dependency_list_t pointer or NULL on error or if there are no
 * key dependencies in the enforcer zone object.
 */
key_dependency_list_t* enforcer_zone_get_key_dependencies(const enforcer_zone_t* enforcer_zone);

/**
 * Create an enforcer zone object in the database.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_create(enforcer_zone_t* enforcer_zone);

/**
 * Get an enforcer zone object from the database by an id specified in `id`.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_get_by_id(enforcer_zone_t* enforcer_zone, int id);

/**
 * Get an enforcer zone object from the database by a name specified in `name`.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \param[in] name a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_get_by_name(enforcer_zone_t* enforcer_zone, const char* name);

/**
 * Update an enforcer zone object in the database.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_update(enforcer_zone_t* enforcer_zone);

/**
 * Delete an enforcer zone object from the database.
 * \param[in] enforcer_zone an enforcer_zone_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_delete(enforcer_zone_t* enforcer_zone);

/**
 * A list of enforcer zone objects.
 */
struct enforcer_zone_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    enforcer_zone_t* enforcer_zone;
};

/**
 * Create a new enforcer zone object list.
 * \param[in] connection a db_connection_t pointer.
 * \return an enforcer_zone_list_t pointer or NULL on error.
 */
enforcer_zone_list_t* enforcer_zone_list_new(const db_connection_t* connection);

/**
 * Delete an enforcer zone object list
 * \param[in] enforcer_zone_list an enforcer_zone_list_t pointer.
 */
void enforcer_zone_list_free(enforcer_zone_list_t* enforcer_zone_list);

/**
 * Get all enforcer zone objects.
 * \param[in] enforcer_zone_list an enforcer_zone_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_list_get(enforcer_zone_list_t* enforcer_zone_list);

/**
 * Get the first enforcer zone object in an enforcer zone object list. This will
 * reset the position of the list.
 * \param[in] enforcer_zone_list an enforcer_zone_list_t pointer.
 * \return a enforcer_zone_t pointer or NULL on error or if there are no
 * enforcer zone objects in the enforcer zone object list.
 */
const enforcer_zone_t* enforcer_zone_list_begin(enforcer_zone_list_t* enforcer_zone_list);

/**
 * Get the next enforcer zone object in an enforcer zone object list.
 * \param[in] enforcer_zone_list an enforcer_zone_list_t pointer.
 * \return a enforcer_zone_t pointer or NULL on error or if there are no more
 * enforcer zone objects in the enforcer zone object list.
 */
const enforcer_zone_t* enforcer_zone_list_next(enforcer_zone_list_t* enforcer_zone_list);

#ifdef __cplusplus
}
#endif

#endif
