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
#include "enforcer_zone_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A enforcer zone object.
 */
struct enforcer_zone {
    db_object_t* dbo;
    int id;
    char* name;
    char* policy;
    unsigned int signconf_needs_writing;
    char* signconf_path;
    unsigned int next_change;
    unsigned int ttl_end_ds;
    unsigned int ttl_end_dk;
    unsigned int ttl_end_rs;
    unsigned int roll_ksk_now;
    unsigned int roll_zsk_now;
    unsigned int roll_csk_now;
    int adapters;
    unsigned int next_ksk_roll;
    unsigned int next_zsk_roll;
    unsigned int next_csk_roll;
#include "enforcer_zone_struct_ext.h"
};

/**
 * Create a new enforcer zone object.
 * \param[in] connection a db_connection_t pointer.
 * \return a enforcer_zone_t pointer or NULL on error.
 */
enforcer_zone_t* enforcer_zone_new(const db_connection_t* connection);

/**
 * Delete a enforcer zone object, this does not delete it from the database.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 */
void enforcer_zone_free(enforcer_zone_t* enforcer_zone);

/**
 * Reset the content of a enforcer zone object making it as if its new. This does not change anything in the database.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 */
void enforcer_zone_reset(enforcer_zone_t* enforcer_zone);

/**
 * Copy the content of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] enforcer_zone_copy a enforcer_zone_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_copy(enforcer_zone_t* enforcer_zone, const enforcer_zone_t* enforcer_zone_copy);

/**
 * Set the content of a enforcer zone object based on a database result.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_from_result(enforcer_zone_t* enforcer_zone, const db_result_t* result);

/**
 * Get the ID of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_id(const enforcer_zone_t* enforcer_zone);

/**
 * Get the name of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return a character pointer or NULL on error or if no name has been set.
 */
const char* enforcer_zone_name(const enforcer_zone_t* enforcer_zone);

/**
 * Get the policy of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return a character pointer or NULL on error or if no policy has been set.
 */
const char* enforcer_zone_policy(const enforcer_zone_t* enforcer_zone);

/**
 * Get the signconf_needs_writing of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an unsigned integer.
 */
unsigned int enforcer_zone_signconf_needs_writing(const enforcer_zone_t* enforcer_zone);

/**
 * Get the signconf_path of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return a character pointer or NULL on error or if no signconf_path has been set.
 */
const char* enforcer_zone_signconf_path(const enforcer_zone_t* enforcer_zone);

/**
 * Get the next_change of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an unsigned integer.
 */
unsigned int enforcer_zone_next_change(const enforcer_zone_t* enforcer_zone);

/**
 * Get the ttl_end_ds of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an unsigned integer.
 */
unsigned int enforcer_zone_ttl_end_ds(const enforcer_zone_t* enforcer_zone);

/**
 * Get the ttl_end_dk of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an unsigned integer.
 */
unsigned int enforcer_zone_ttl_end_dk(const enforcer_zone_t* enforcer_zone);

/**
 * Get the ttl_end_rs of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an unsigned integer.
 */
unsigned int enforcer_zone_ttl_end_rs(const enforcer_zone_t* enforcer_zone);

/**
 * Get the roll_ksk_now of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an unsigned integer.
 */
unsigned int enforcer_zone_roll_ksk_now(const enforcer_zone_t* enforcer_zone);

/**
 * Get the roll_zsk_now of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an unsigned integer.
 */
unsigned int enforcer_zone_roll_zsk_now(const enforcer_zone_t* enforcer_zone);

/**
 * Get the roll_csk_now of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an unsigned integer.
 */
unsigned int enforcer_zone_roll_csk_now(const enforcer_zone_t* enforcer_zone);

/**
 * Get the adapters of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an integer.
 */
int enforcer_zone_adapters(const enforcer_zone_t* enforcer_zone);

/**
 * Get the next_ksk_roll of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an unsigned integer.
 */
unsigned int enforcer_zone_next_ksk_roll(const enforcer_zone_t* enforcer_zone);

/**
 * Get the next_zsk_roll of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an unsigned integer.
 */
unsigned int enforcer_zone_next_zsk_roll(const enforcer_zone_t* enforcer_zone);

/**
 * Get the next_csk_roll of a enforcer zone object. Undefined behavior if `enforcer_zone` is NULL.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return an unsigned integer.
 */
unsigned int enforcer_zone_next_csk_roll(const enforcer_zone_t* enforcer_zone);

/**
 * Set the name of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] name_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_name(enforcer_zone_t* enforcer_zone, const char* name_text);

/**
 * Set the policy of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] policy_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_policy(enforcer_zone_t* enforcer_zone, const char* policy_text);

/**
 * Set the signconf_needs_writing of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] signconf_needs_writing an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_signconf_needs_writing(enforcer_zone_t* enforcer_zone, unsigned int signconf_needs_writing);

/**
 * Set the signconf_path of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] signconf_path_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_signconf_path(enforcer_zone_t* enforcer_zone, const char* signconf_path_text);

/**
 * Set the next_change of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] next_change an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_next_change(enforcer_zone_t* enforcer_zone, unsigned int next_change);

/**
 * Set the ttl_end_ds of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] ttl_end_ds an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_ttl_end_ds(enforcer_zone_t* enforcer_zone, unsigned int ttl_end_ds);

/**
 * Set the ttl_end_dk of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] ttl_end_dk an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_ttl_end_dk(enforcer_zone_t* enforcer_zone, unsigned int ttl_end_dk);

/**
 * Set the ttl_end_rs of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] ttl_end_rs an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_ttl_end_rs(enforcer_zone_t* enforcer_zone, unsigned int ttl_end_rs);

/**
 * Set the roll_ksk_now of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] roll_ksk_now an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_roll_ksk_now(enforcer_zone_t* enforcer_zone, unsigned int roll_ksk_now);

/**
 * Set the roll_zsk_now of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] roll_zsk_now an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_roll_zsk_now(enforcer_zone_t* enforcer_zone, unsigned int roll_zsk_now);

/**
 * Set the roll_csk_now of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] roll_csk_now an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_roll_csk_now(enforcer_zone_t* enforcer_zone, unsigned int roll_csk_now);

/**
 * Set the adapters of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] adapters an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_adapters(enforcer_zone_t* enforcer_zone, int adapters);

/**
 * Set the next_ksk_roll of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] next_ksk_roll an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_next_ksk_roll(enforcer_zone_t* enforcer_zone, unsigned int next_ksk_roll);

/**
 * Set the next_zsk_roll of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] next_zsk_roll an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_next_zsk_roll(enforcer_zone_t* enforcer_zone, unsigned int next_zsk_roll);

/**
 * Set the next_csk_roll of a enforcer zone object.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] next_csk_roll an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_set_next_csk_roll(enforcer_zone_t* enforcer_zone, unsigned int next_csk_roll);

/**
 * Create a enforcer zone object in the database.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_create(enforcer_zone_t* enforcer_zone);

/**
 * Get a enforcer zone object from the database by an id specified in `id`.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_get_by_id(enforcer_zone_t* enforcer_zone, int id);

/**
 * Update a enforcer zone object in the database.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_update(enforcer_zone_t* enforcer_zone);

/**
 * Delete a enforcer zone object from the database.
 * \param[in] enforcer_zone a enforcer_zone_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_delete(enforcer_zone_t* enforcer_zone);

/**
 * A list of enforcer zone objects.
 */
struct enforcer_zone_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    enforcer_zone_t* enforcer_zone;
};

/**
 * Create a new enforcer zone object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a enforcer_zone_list_t pointer or NULL on error.
 */
enforcer_zone_list_t* enforcer_zone_list_new(const db_connection_t* connection);

/**
 * Delete a enforcer zone object list
 * \param[in] enforcer_zone_list a enforcer_zone_list_t pointer.
 */
void enforcer_zone_list_free(enforcer_zone_list_t* enforcer_zone_list);

/**
 * Get all enforcer zone objects.
 * \param[in] enforcer_zone_list a enforcer_zone_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int enforcer_zone_list_get(enforcer_zone_list_t* enforcer_zone_list);

/**
 * Get the first enforcer zone object in a enforcer zone object list. This will reset the position of the list.
 * \param[in] enforcer_zone_list a enforcer_zone_list_t pointer.
 * \return a enforcer_zone_t pointer or NULL on error or if there are no
 * enforcer zone objects in the enforcer zone object list.
 */
const enforcer_zone_t* enforcer_zone_list_begin(enforcer_zone_list_t* enforcer_zone_list);

/**
 * Get the next enforcer zone object in a enforcer zone object list.
 * \param[in] enforcer_zone_list a enforcer_zone_list_t pointer.
 * \return a enforcer_zone_t pointer or NULL on error or if there are no more
 * enforcer zone objects in the enforcer zone object list.
 */
const enforcer_zone_t* enforcer_zone_list_next(enforcer_zone_list_t* enforcer_zone_list);

#ifdef __cplusplus
}
#endif

#endif
