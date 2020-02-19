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

#ifndef __policy_h
#define __policy_h

#include "db_object.h"

struct policy;
struct policy_list;
typedef struct policy policy_t;
typedef struct policy_list policy_list_t;

typedef enum policy_denial_type {
    POLICY_DENIAL_TYPE_INVALID = -1,
    POLICY_DENIAL_TYPE_NSEC = 0,
    POLICY_DENIAL_TYPE_NSEC3 = 1
} policy_denial_type_t;
extern const db_enum_t policy_enum_set_denial_type[];

typedef enum policy_zone_soa_serial {
    POLICY_ZONE_SOA_SERIAL_INVALID = -1,
    POLICY_ZONE_SOA_SERIAL_COUNTER = 0,
    POLICY_ZONE_SOA_SERIAL_DATECOUNTER = 1,
    POLICY_ZONE_SOA_SERIAL_UNIXTIME = 2,
    POLICY_ZONE_SOA_SERIAL_KEEP = 3
} policy_zone_soa_serial_t;

#include "policy_ext.h"

/**
 * A policy object.
 */
struct policy {
    db_object_t* dbo;
    db_value_t id;
    db_value_t rev;
    char* name;
    /* if passthrough set, no modifications to the zonefile should
     * be made. I.e. No signatures added or removed */
    unsigned int passthrough;
    char* description;
    unsigned int signatures_resign;
    unsigned int signatures_refresh;
    unsigned int signatures_jitter;
    unsigned int signatures_inception_offset;
    unsigned int signatures_validity_default;
    unsigned int signatures_validity_denial;
    unsigned int signatures_validity_keyset;
    unsigned int signatures_max_zone_ttl;
    policy_denial_type_t denial_type;
    unsigned int denial_optout;
    unsigned int denial_ttl;
    unsigned int denial_resalt;
    unsigned int denial_algorithm;
    unsigned int denial_iterations;
    unsigned int denial_salt_length;
    char* denial_salt;
    unsigned int denial_salt_last_change;
    unsigned int keys_ttl;
    unsigned int keys_retire_safety;
    unsigned int keys_publish_safety;
    unsigned int keys_shared;
    unsigned int keys_purge_after;
    unsigned int zone_propagation_delay;
    unsigned int zone_soa_ttl;
    unsigned int zone_soa_minimum;
    policy_zone_soa_serial_t zone_soa_serial;
    unsigned int parent_registration_delay;
    unsigned int parent_propagation_delay;
    unsigned int parent_ds_ttl;
    unsigned int parent_soa_ttl;
    unsigned int parent_soa_minimum;
    policy_key_list_t* policy_key_list;
    zone_list_db_t* zone_list;
    hsm_key_list_t* hsm_key_list;
};

/**
 * Create a new policy object.
 * \param[in] connection a db_connection_t pointer.
 * \return a policy_t pointer or NULL on error.
 */
extern policy_t* policy_new(const db_connection_t* connection);

/**
 * Create a new policy object that is a copy of another policy object.
 * \param[in] policy a policy_t pointer.
 * \return a policy_t pointer or NULL on error.
 */
extern policy_t* policy_new_copy(const policy_t* policy);

/**
 * Delete a policy object, this does not delete it from the database.
 * \param[in] policy a policy_t pointer.
 */
extern void policy_free(policy_t* policy);

/**
 * Copy the content of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] policy_copy a policy_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_copy(policy_t* policy, const policy_t* policy_copy);

/**
 * Set the content of a policy object based on a database result.
 * \param[in] policy a policy_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_from_result(policy_t* policy, const db_result_t* result);

/**
 * Get the id of a policy object.
 * \param[in] policy a policy_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
extern const db_value_t* policy_id(const policy_t* policy);

/**
 * Get the name of a policy object.
 * \param[in] policy a policy_t pointer.
 * \return a character pointer or NULL on error or if no name has been set.
 */
extern const char* policy_name(const policy_t* policy);

/**
 * Get the passthrough of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_passthrough(const policy_t* policy);

/**
 * Get the description of a policy object.
 * \param[in] policy a policy_t pointer.
 * \return a character pointer or NULL on error or if no description has been set.
 */
extern const char* policy_description(const policy_t* policy);

/**
 * Get the signatures_resign of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_signatures_resign(const policy_t* policy);

/**
 * Get the signatures_refresh of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_signatures_refresh(const policy_t* policy);

/**
 * Get the signatures_jitter of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_signatures_jitter(const policy_t* policy);

/**
 * Get the signatures_inception_offset of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_signatures_inception_offset(const policy_t* policy);

/**
 * Get the signatures_validity_default of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_signatures_validity_default(const policy_t* policy);

/**
 * Get the signatures_validity_denial of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_signatures_validity_denial(const policy_t* policy);

/**
 * Get the signatures_validity_keyset of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_signatures_validity_keyset(const policy_t* policy);

/**
 * Get the signatures_max_zone_ttl of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_signatures_max_zone_ttl(const policy_t* policy);

/**
 * Get the denial_type of a policy object.
 * \param[in] policy a policy_t pointer.
 * \return a policy_denial_type_t which may be POLICY_DENIAL_TYPE_INVALID on error or if no denial_type has been set.
 */
extern policy_denial_type_t policy_denial_type(const policy_t* policy);

/**
 * Get the denial_optout of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_denial_optout(const policy_t* policy);

/**
 * Get the denial_ttl of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_denial_ttl(const policy_t* policy);

/**
 * Get the denial_resalt of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_denial_resalt(const policy_t* policy);

/**
 * Get the denial_algorithm of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_denial_algorithm(const policy_t* policy);

/**
 * Get the denial_iterations of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_denial_iterations(const policy_t* policy);

/**
 * Get the denial_salt_length of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_denial_salt_length(const policy_t* policy);

/**
 * Get the denial_salt of a policy object.
 * \param[in] policy a policy_t pointer.
 * \return a character pointer or NULL on error or if no denial_salt has been set.
 */
extern const char* policy_denial_salt(const policy_t* policy);

/**
 * Get the denial_salt_last_change of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_denial_salt_last_change(const policy_t* policy);

/**
 * Get the keys_ttl of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_keys_ttl(const policy_t* policy);

/**
 * Get the keys_retire_safety of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_keys_retire_safety(const policy_t* policy);

/**
 * Get the keys_publish_safety of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_keys_publish_safety(const policy_t* policy);

/**
 * Get the keys_shared of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_keys_shared(const policy_t* policy);

/**
 * Get the keys_purge_after of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_keys_purge_after(const policy_t* policy);

/**
 * Get the zone_propagation_delay of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_zone_propagation_delay(const policy_t* policy);

/**
 * Get the zone_soa_ttl of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_zone_soa_ttl(const policy_t* policy);

/**
 * Get the zone_soa_minimum of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_zone_soa_minimum(const policy_t* policy);

/**
 * Get the zone_soa_serial as text of a policy object.
 * \param[in] policy a policy_t pointer.
 * \return a character pointer or NULL on error or if no zone_soa_serial has been set.
 */
extern const char* policy_zone_soa_serial_text(const policy_t* policy);
extern const char* policy_zone_soa_serial_text2(unsigned int zone_soa_serial);

/**
 * Get the parent_registration_delay of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_parent_registration_delay(const policy_t* policy);

/**
 * Get the parent_propagation_delay of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_parent_propagation_delay(const policy_t* policy);

/**
 * Get the parent_ds_ttl of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_parent_ds_ttl(const policy_t* policy);

/**
 * Get the parent_soa_ttl of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_parent_soa_ttl(const policy_t* policy);

/**
 * Get the parent_soa_minimum of a policy object. Undefined behavior if `policy` is NULL.
 * \param[in] policy a policy_t pointer.
 * \return an unsigned integer.
 */
extern unsigned int policy_parent_soa_minimum(const policy_t* policy);

/**
 * Get the zone objects related to a policy object.
 * \param[in] policy a policy_t pointer.
 * \return a zone_list_db_t pointer or NULL on error.
 */
extern zone_list_db_t* policy_zone_list(policy_t* policy);

/**
 * Retrieve zone objects related to a policy object.
 * Use policy_zone_list() to get the list afterwards.
 * This will refetch objects if already retrieved.
 * \param[in] policy a policy_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_retrieve_zone_list(policy_t* policy);

/**
 * Set the name of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] name_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_name(policy_t* policy, const char* name_text);

/**
 * Set the passthrough of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] passthrough an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_passthrough(policy_t* policy, unsigned int passthrough);

/**
 * Set the description of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] description_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_description(policy_t* policy, const char* description_text);

/**
 * Set the signatures_resign of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] signatures_resign an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_signatures_resign(policy_t* policy, unsigned int signatures_resign);

/**
 * Set the signatures_refresh of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] signatures_refresh an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_signatures_refresh(policy_t* policy, unsigned int signatures_refresh);

/**
 * Set the signatures_jitter of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] signatures_jitter an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_signatures_jitter(policy_t* policy, unsigned int signatures_jitter);

/**
 * Set the signatures_inception_offset of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] signatures_inception_offset an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_signatures_inception_offset(policy_t* policy, unsigned int signatures_inception_offset);

/**
 * Set the signatures_validity_default of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] signatures_validity_default an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_signatures_validity_default(policy_t* policy, unsigned int signatures_validity_default);

/**
 * Set the signatures_validity_denial of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] signatures_validity_denial an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_signatures_validity_denial(policy_t* policy, unsigned int signatures_validity_denial);

/**
 * Set the signatures_validity_keyset of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] signatures_validity_keyset an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_signatures_validity_keyset(policy_t* policy, unsigned int signatures_validity_keyset);

/**
 * Set the signatures_max_zone_ttl of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] signatures_max_zone_ttl an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_signatures_max_zone_ttl(policy_t* policy, unsigned int signatures_max_zone_ttl);

/**
 * Set the denial_type of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] denial_type a policy_denial_type_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_denial_type(policy_t* policy, policy_denial_type_t denial_type);

/**
 * Set the denial_optout of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] denial_optout an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_denial_optout(policy_t* policy, unsigned int denial_optout);

/**
 * Set the denial_ttl of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] denial_ttl an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_denial_ttl(policy_t* policy, unsigned int denial_ttl);

/**
 * Set the denial_resalt of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] denial_resalt an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_denial_resalt(policy_t* policy, unsigned int denial_resalt);

/**
 * Set the denial_algorithm of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] denial_algorithm an unsigned integer with a maximum value of 255.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_denial_algorithm(policy_t* policy, unsigned int denial_algorithm);

/**
 * Set the denial_iterations of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] denial_iterations an unsigned integer with a maximum value of 65535.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_denial_iterations(policy_t* policy, unsigned int denial_iterations);

/**
 * Set the denial_salt_length of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] denial_salt_length an unsigned integer with a maximum value of 255.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_denial_salt_length(policy_t* policy, unsigned int denial_salt_length);

/**
 * Set the denial_salt of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] denial_salt_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_denial_salt(policy_t* policy, const char* denial_salt_text);

/**
 * Set the denial_salt_last_change of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] denial_salt_last_change an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_denial_salt_last_change(policy_t* policy, unsigned int denial_salt_last_change);

/**
 * Set the keys_ttl of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] keys_ttl an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_keys_ttl(policy_t* policy, unsigned int keys_ttl);

/**
 * Set the keys_retire_safety of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] keys_retire_safety an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_keys_retire_safety(policy_t* policy, unsigned int keys_retire_safety);

/**
 * Set the keys_publish_safety of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] keys_publish_safety an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_keys_publish_safety(policy_t* policy, unsigned int keys_publish_safety);

/**
 * Set the keys_shared of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] keys_shared an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_keys_shared(policy_t* policy, unsigned int keys_shared);

/**
 * Set the keys_purge_after of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] keys_purge_after an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_keys_purge_after(policy_t* policy, unsigned int keys_purge_after);

/**
 * Set the zone_propagation_delay of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] zone_propagation_delay an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_zone_propagation_delay(policy_t* policy, unsigned int zone_propagation_delay);

/**
 * Set the zone_soa_ttl of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] zone_soa_ttl an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_zone_soa_ttl(policy_t* policy, unsigned int zone_soa_ttl);

/**
 * Set the zone_soa_minimum of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] zone_soa_minimum an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_zone_soa_minimum(policy_t* policy, unsigned int zone_soa_minimum);

/**
 * Set the zone_soa_serial of a policy object from text.
 * \param[in] policy a policy_t pointer.
 * \param[in] zone_soa_serial a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_zone_soa_serial_text(policy_t* policy, const char* zone_soa_serial);

/**
 * Set the parent_registration_delay of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] parent_registration_delay an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_parent_registration_delay(policy_t* policy, unsigned int parent_registration_delay);

/**
 * Set the parent_propagation_delay of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] parent_propagation_delay an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_parent_propagation_delay(policy_t* policy, unsigned int parent_propagation_delay);

/**
 * Set the parent_ds_ttl of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] parent_ds_ttl an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_parent_ds_ttl(policy_t* policy, unsigned int parent_ds_ttl);

/**
 * Set the parent_soa_ttl of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] parent_soa_ttl an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_parent_soa_ttl(policy_t* policy, unsigned int parent_soa_ttl);

/**
 * Set the parent_soa_minimum of a policy object.
 * \param[in] policy a policy_t pointer.
 * \param[in] parent_soa_minimum an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_set_parent_soa_minimum(policy_t* policy, unsigned int parent_soa_minimum);

/**
 * Create a clause for denial_type of a policy object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] denial_type a policy_denial_type_t.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
extern db_clause_t* policy_denial_type_clause(db_clause_list_t* clause_list, policy_denial_type_t denial_type);

/**
 * Create a policy object in the database.
 * \param[in] policy a policy_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_create(policy_t* policy);

/**
 * Get a policy object from the database by a id specified in `id`.
 * \param[in] policy a policy_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_get_by_id(policy_t* policy, const db_value_t* id);

/**
 * Get a policy object from the database by a name specified in `name`.
 * \param[in] policy a policy_t pointer.
 * \param[in] name a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_get_by_name(policy_t* policy, const char* name);

/**
 * Get a new policy object from the database by a name specified in `name`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] name a character pointer.
 * \return a policy_t pointer or NULL on error or if it does not exist.
 */
extern policy_t* policy_new_get_by_name(const db_connection_t* connection, const char* name);

/**
 * Update a policy object in the database.
 * \param[in] policy a policy_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_update(policy_t* policy);

/**
 * Delete a policy object from the database.
 * \param[in] policy a policy_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_delete(policy_t* policy);

/**
 * A list of policy objects.
 */
struct policy_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    policy_t* policy;
    int object_store;
    policy_t** object_list;
    size_t object_list_size;
    size_t object_list_position;
    int object_list_first;
    int associated_fetch;
};

/**
 * Create a new policy object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a policy_list_t pointer or NULL on error.
 */
extern policy_list_t* policy_list_new(const db_connection_t* connection);

/**
 * Create a new policy object list that is a copy of another.
 * \param[in] policy_list a policy_list_t pointer.
 * \return a policy_list_t pointer or NULL on error.
 */
extern policy_list_t* policy_list_new_copy(const policy_list_t* policy_copy);

/**
 * Specify that objects should be stored within the list as they are fetch,
 * this is optimal if the list is to be iterated over more then once.
 * \param[in] policy_list a policy_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_list_object_store(policy_list_t* policy_list);

/**
 * Delete a policy object list.
 * \param[in] policy_list a policy_list_t pointer.
 */
extern void policy_list_free(policy_list_t* policy_list);

/**
 * Copy the content of another policy object list.
 * \param[in] policy_list a policy_list_t pointer.
 * \param[in] from_policy_list a policy_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_list_copy(policy_list_t* policy_list, const policy_list_t* from_policy_list);

/**
 * Get all policy objects.
 * \param[in] policy_list a policy_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_list_get(policy_list_t* policy_list);

/**
 * Get a new list with all policy objects.
 * \param[in] connection a db_connection_t pointer.
 * \return a policy_list_t pointer or NULL on error.
 */
extern policy_list_t* policy_list_new_get(const db_connection_t* connection);

/**
 * Get policy objects from the database by a clause list.
 * \param[in] policy_list a policy_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_list_get_by_clauses(policy_list_t* policy_list, const db_clause_list_t* clause_list);

/**
 * Get a new list of policy objects from the database by a clause list.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a policy_list_t pointer or NULL on error.
 */
extern policy_list_t* policy_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list);

/**
 * Get the first policy object in a policy object list and reset the
 * position of the list.
 * \param[in] policy_list a policy_list_t pointer.
 * \return a policy_t pointer or NULL on error or if there are no
 * policy objects in the policy object list.
 */
extern const policy_t* policy_list_begin(policy_list_t* policy_list);

/**
 * Get the next policy object in a policy object list.
 * Ownership of this object is retained within the list and the object is only
 * valid until the next call to this function.
 * \param[in] policy_list a policy_list_t pointer.
 * \return a policy_t pointer or NULL on error or if there are no more
 * policy objects in the policy object list.
 */
extern const policy_t* policy_list_next(policy_list_t* policy_list);

/**
 * Get the next policy object in a policy object list.
 * The caller will be given ownership of this object and is responsible for
 * freeing it.
 * \param[in] policy_list a policy_list_t pointer.
 * \return a policy_t pointer or NULL on error or if there are no more
 * policy objects in the policy object list.
 */
extern policy_t* policy_list_get_next(policy_list_t* policy_list);

size_t
policy_list_size(policy_list_t* policy_list);

#endif
