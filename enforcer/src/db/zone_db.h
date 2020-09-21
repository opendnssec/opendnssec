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

#ifndef __zone_db_h
#define __zone_db_h

#include "db_object.h"

struct zone_db;
struct zone_list_db;
typedef struct zone_db zone_db_t;
typedef struct zone_list_db zone_list_db_t;

#include "zone_db_ext.h"
#include "policy.h"

/**
 * A zone object.
 */
struct zone_db {
    db_object_t* dbo;
    db_value_t id;
    db_value_t rev;
    db_value_t policy_id;
    const policy_t* associated_policy_id;
    policy_t* private_policy_id;
    char* name;
    unsigned int signconf_needs_writing;
    char* signconf_path;
    int next_change;
    unsigned int ttl_end_ds;
    unsigned int ttl_end_dk;
    unsigned int ttl_end_rs;
    unsigned int roll_ksk_now;
    unsigned int roll_zsk_now;
    unsigned int roll_csk_now;
    char* input_adapter_type;
    char* input_adapter_uri;
    char* output_adapter_type;
    char* output_adapter_uri;
    unsigned int next_ksk_roll;
    unsigned int next_zsk_roll;
    unsigned int next_csk_roll;
    key_data_list_t* key_data_list;
    key_dependency_list_t* key_dependency_list;
};

/**
 * Create a new zone object.
 * \param[in] connection a db_connection_t pointer.
 * \return a zone_db_t pointer or NULL on error.
 */
extern zone_db_t* zone_db_new(const db_connection_t* connection);

/**
 * Create a new zone object that is a copy of another zone object.
 * \param[in] zone a zone_db_t pointer.
 * \return a zone_db_t pointer or NULL on error.
 */
extern zone_db_t* zone_db_new_copy(const zone_db_t* zone);

/**
 * Delete a zone object, this does not delete it from the database.
 * \param[in] zone a zone_db_t pointer.
 */
extern void zone_db_free(zone_db_t* zone);

/**
 * Copy the content of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] zone_copy a zone_db_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_copy(zone_db_t* zone, const zone_db_t* zone_copy);

/**
 * Set the content of a zone object based on a database result.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_from_result(zone_db_t* zone, const db_result_t* result);

/**
 * Get the id of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
extern const db_value_t* zone_db_id(const zone_db_t* zone);

/**
 * Get the policy_id of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
extern const db_value_t* zone_db_policy_id(const zone_db_t* zone);

/**
 * Get the policy_id object related to a zone object.
 * The caller will be given ownership of this object and is responsible for freeing it.
 * \param[in] zone a zone_db_t pointer.
 * \return a policy_t pointer or NULL on error or if no object could be found.
 */
extern policy_t* zone_db_get_policy(const zone_db_t* zone);

/**
 * Get the name of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \return a character pointer or NULL on error or if no name has been set.
 */
extern const char* zone_db_name(const zone_db_t* zone);

/**
 * Get the signconf_needs_writing of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_db_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int zone_db_signconf_needs_writing(const zone_db_t* zone);

/**
 * Get the signconf_path of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \return a character pointer or NULL on error or if no signconf_path has been set.
 */
extern const char* zone_db_signconf_path(const zone_db_t* zone);

/**
 * Get the next_change of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_db_t pointer.
 * \return an integer.
 */
extern int zone_db_next_change(const zone_db_t* zone);

/**
 * Get the ttl_end_ds of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_db_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int zone_db_ttl_end_ds(const zone_db_t* zone);

/**
 * Get the ttl_end_dk of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_db_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int zone_db_ttl_end_dk(const zone_db_t* zone);

/**
 * Get the ttl_end_rs of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_db_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int zone_db_ttl_end_rs(const zone_db_t* zone);

/**
 * Get the roll_ksk_now of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_db_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int zone_db_roll_ksk_now(const zone_db_t* zone);

/**
 * Get the roll_zsk_now of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_db_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int zone_db_roll_zsk_now(const zone_db_t* zone);

/**
 * Get the roll_csk_now of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_db_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int zone_db_roll_csk_now(const zone_db_t* zone);

/**
 * Get the input_adapter_type of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \return a character pointer or NULL on error or if no input_adapter_type has been set.
 */
extern const char* zone_db_input_adapter_type(const zone_db_t* zone);

/**
 * Get the input_adapter_uri of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \return a character pointer or NULL on error or if no input_adapter_uri has been set.
 */
extern const char* zone_db_input_adapter_uri(const zone_db_t* zone);

/**
 * Get the output_adapter_type of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \return a character pointer or NULL on error or if no output_adapter_type has been set.
 */
extern const char* zone_db_output_adapter_type(const zone_db_t* zone);

/**
 * Get the output_adapter_uri of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \return a character pointer or NULL on error or if no output_adapter_uri has been set.
 */
extern const char* zone_db_output_adapter_uri(const zone_db_t* zone);

/**
 * Get the next_ksk_roll of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_db_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int zone_db_next_ksk_roll(const zone_db_t* zone);

/**
 * Get the next_zsk_roll of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_db_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int zone_db_next_zsk_roll(const zone_db_t* zone);

/**
 * Get the next_csk_roll of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_db_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int zone_db_next_csk_roll(const zone_db_t* zone);

/**
 * Set the policy_id of a zone object. If this fails the original value may have been lost.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] policy_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_policy_id(zone_db_t* zone, const db_value_t* policy_id);

/**
 * Set the name of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] name_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_name(zone_db_t* zone, const char* name_text);

/**
 * Set the signconf_needs_writing of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] signconf_needs_writing an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_signconf_needs_writing(zone_db_t* zone, unsigned int signconf_needs_writing);

/**
 * Set the signconf_path of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] signconf_path_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_signconf_path(zone_db_t* zone, const char* signconf_path_text);

/**
 * Set the next_change of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] next_change an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_next_change(zone_db_t* zone, int next_change);

/**
 * Set the ttl_end_ds of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] ttl_end_ds an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_ttl_end_ds(zone_db_t* zone, unsigned int ttl_end_ds);

/**
 * Set the ttl_end_dk of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] ttl_end_dk an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_ttl_end_dk(zone_db_t* zone, unsigned int ttl_end_dk);

/**
 * Set the ttl_end_rs of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] ttl_end_rs an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_ttl_end_rs(zone_db_t* zone, unsigned int ttl_end_rs);

/**
 * Set the roll_ksk_now of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] roll_ksk_now an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_roll_ksk_now(zone_db_t* zone, unsigned int roll_ksk_now);

/**
 * Set the roll_zsk_now of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] roll_zsk_now an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_roll_zsk_now(zone_db_t* zone, unsigned int roll_zsk_now);

/**
 * Set the roll_csk_now of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] roll_csk_now an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_roll_csk_now(zone_db_t* zone, unsigned int roll_csk_now);

/**
 * Set the input_adapter_type of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] input_adapter_type_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_input_adapter_type(zone_db_t* zone, const char* input_adapter_type_text);

/**
 * Set the input_adapter_uri of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] input_adapter_uri_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_input_adapter_uri(zone_db_t* zone, const char* input_adapter_uri_text);

/**
 * Set the output_adapter_type of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] output_adapter_type_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_output_adapter_type(zone_db_t* zone, const char* output_adapter_type_text);

/**
 * Set the output_adapter_uri of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] output_adapter_uri_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_output_adapter_uri(zone_db_t* zone, const char* output_adapter_uri_text);

/**
 * Set the next_ksk_roll of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] next_ksk_roll an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_next_ksk_roll(zone_db_t* zone, unsigned int next_ksk_roll);

/**
 * Set the next_zsk_roll of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] next_zsk_roll an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_next_zsk_roll(zone_db_t* zone, unsigned int next_zsk_roll);

/**
 * Set the next_csk_roll of a zone object.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] next_csk_roll an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_set_next_csk_roll(zone_db_t* zone, unsigned int next_csk_roll);

/**
 * Create a clause for policy_id of a zone object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] policy_id a db_value_t pointer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
extern db_clause_t* zone_db_policy_id_clause(db_clause_list_t* clause_list, const db_value_t* policy_id);

/**
 * Create a zone object in the database.
 * \param[in] zone a zone_db_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_create(zone_db_t* zone);

/**
 * Get a zone object from the database by a id specified in `id`.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_get_by_id(zone_db_t* zone, const db_value_t* id);

/**
 * Get a zone object from the database by a name specified in `name`.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] name a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_get_by_name(zone_db_t* zone, const char* name);

/**
 * Get a new zone object from the database by a name specified in `name`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] name a character pointer.
 * \return a zone_db_t pointer or NULL on error or if it does not exist.
 */
extern zone_db_t* zone_db_new_get_by_name(const db_connection_t* connection, const char* name);

/**
 * Update a zone object in the database.
 * \param[in] zone a zone_db_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_update(zone_db_t* zone);

/**
 * Delete a zone object from the database.
 * \param[in] zone a zone_db_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_delete(zone_db_t* zone);

/**
 * Count the number of zone objects in the database, if a selection of
 * objects should be counted then it can be limited by a database clause list
 * otherwise all objects are counted.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer or NULL if all objects.
 * \param[out] count a size_t pointer to where the count should be stored.
 * should be counted.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_db_count(zone_db_t* zone, db_clause_list_t* clause_list, size_t* count);

/**
 * A list of zone objects.
 */
struct zone_list_db {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    zone_db_t* zone;
    int object_store;
    zone_db_t** object_list;
    size_t object_list_size;
    size_t object_list_position;
    int object_list_first;
    int associated_fetch;
    policy_list_t* policy_id_list;
};

/**
 * Create a new zone object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a zone_list_db_t pointer or NULL on error.
 */
extern zone_list_db_t* zone_list_db_new(const db_connection_t* connection);

/**
 * Create a new zone object list that is a copy of another.
 * \param[in] zone_list_db a zone_list_db_t pointer.
 * \return a zone_list_db_t pointer or NULL on error.
 */
extern zone_list_db_t* zone_list_db_new_copy(const zone_list_db_t* zone_copy);

/**
 * Specify that objects should be stored within the list as they are fetch,
 * this is optimal if the list is to be iterated over more then once.
 * \param[in] zone_list_db a zone_list_db_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_list_db_object_store(zone_list_db_t* zone_list_db);

/**
 * Delete a zone object list.
 * \param[in] zone_list_db a zone_list_db_t pointer.
 */
extern void zone_list_db_free(zone_list_db_t* zone_list_db);

/**
 * Copy the content of another zone object list.
 * \param[in] zone_list_db a zone_list_db_t pointer.
 * \param[in] from_zone_list_db a zone_list_db_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_list_db_copy(zone_list_db_t* zone_list_db, const zone_list_db_t* from_zone_list_db);

/**
 * Get all zone objects.
 * \param[in] zone_list_db a zone_list_db_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_list_db_get(zone_list_db_t* zone_list_db);

/**
 * Get a new list with all zone objects.
 * \param[in] connection a db_connection_t pointer.
 * \return a zone_list_db_t pointer or NULL on error.
 */
extern zone_list_db_t* zone_list_db_new_get(const db_connection_t* connection);

/**
 * Get zone objects from the database by a clause list.
 * \param[in] zone_list_db a zone_list_db_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_list_db_get_by_clauses(zone_list_db_t* zone_list_db, const db_clause_list_t* clause_list);

/**
 * Get zone objects from the database by a policy_id specified in `policy_id`.
 * \param[in] zone_list_db a zone_list_db_t pointer.
 * \param[in] policy_id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int zone_list_db_get_by_policy_id(zone_list_db_t* zone_list_db, const db_value_t* policy_id);

/**
 * Get a new list of zone objects from the database by a policy_id specified in `policy_id`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] policy_id a db_value_t pointer.
 * \return a zone_list_db_t pointer or NULL on error.
 */
extern zone_list_db_t* zone_list_db_new_get_by_policy_id(const db_connection_t* connection, const db_value_t* policy_id);

/**
 * Get the first zone object in a zone object list and reset the
 * position of the list.
 * \param[in] zone_list_db a zone_list_db_t pointer.
 * \return a zone_db_t pointer or NULL on error or if there are no
 * zone objects in the zone object list.
 */
extern const zone_db_t* zone_list_db_begin(zone_list_db_t* zone_list_db);

/**
 * Get the next zone object in a zone object list.
 * Ownership of this object is retained within the list and the object is only
 * valid until the next call to this function.
 * \param[in] zone_list_db a zone_list_db_t pointer.
 * \return a zone_db_t pointer or NULL on error or if there are no more
 * zone objects in the zone object list.
 */
extern const zone_db_t* zone_list_db_next(zone_list_db_t* zone_list_db);

/**
 * Get the next zone object in a zone object list.
 * The caller will be given ownership of this object and is responsible for
 * freeing it.
 * \param[in] zone_list_db a zone_list_db_t pointer.
 * \return a zone_db_t pointer or NULL on error or if there are no more
 * zone objects in the zone object list.
 */
extern zone_db_t* zone_list_db_get_next(zone_list_db_t* zone_list_db);

/**
 * Get the size of a zone object list.
 * \param[in] zone_list_db a zone_list_db_t pointer.
 * \return a size_t with the size of the list or zero on error, if the list is
 * empty or if the backend does not support returning the size.
 */
extern size_t zone_list_db_size(zone_list_db_t* zone_list_db);

#endif
