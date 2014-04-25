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

#include "policy.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

static const db_enum_t __enum_set_denial_type[] = {
    { "NSEC", (policy_denial_type_t)POLICY_DENIAL_TYPE_NSEC },
    { "NSEC3", (policy_denial_type_t)POLICY_DENIAL_TYPE_NSEC3 },
    { NULL, 0 }
};

static const db_enum_t __enum_set_zone_soa_serial[] = {
    { "counter", (policy_zone_soa_serial_t)POLICY_ZONE_SOA_SERIAL_COUNTER },
    { "datecounter", (policy_zone_soa_serial_t)POLICY_ZONE_SOA_SERIAL_DATECOUNTER },
    { "unixtime", (policy_zone_soa_serial_t)POLICY_ZONE_SOA_SERIAL_UNIXTIME },
    { "keep", (policy_zone_soa_serial_t)POLICY_ZONE_SOA_SERIAL_KEEP },
    { NULL, 0 }
};

/**
 * Create a new policy object.
 * \param[in] connection a db_connection_t pointer.
 * \return a policy_t pointer or NULL on error.
 */
static db_object_t* __policy_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "policy")
        || db_object_set_primary_key_name(object, "id")
        || !(object_field_list = db_object_field_list_new()))
    {
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "id")
        || db_object_field_set_type(object_field, DB_TYPE_PRIMARY_KEY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "name")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "description")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesResign")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesRefresh")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesJitter")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesInceptionOffset")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesValidityDefault")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesValidityDenial")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesMaxZoneTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialType")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_denial_type)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialOptout")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialResalt")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialAlgorithm")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialIterations")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialSaltLength")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialSalt")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialSaltLastChange")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysRetireSafety")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysPublishSafety")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysShared")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysPurgeAfter")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zonePropagationDelay")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zoneSoaTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zoneSoaMinimum")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zoneSoaSerial")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_zone_soa_serial)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentPropagationDelay")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentDsTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentSoaTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentSoaMinimum")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (db_object_set_object_field_list(object, object_field_list)) {
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    return object;
}

/* POLICY */

static mm_alloc_t __policy_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(policy_t));

policy_t* policy_new(const db_connection_t* connection) {
    policy_t* policy =
        (policy_t*)mm_alloc_new0(&__policy_alloc);

    if (policy) {
        if (!(policy->dbo = __policy_new_object(connection))) {
            mm_alloc_delete(&__policy_alloc, policy);
            return NULL;
        }
        db_value_reset(&(policy->id));
        policy->signatures_max_zone_ttl = 86400;
        policy->denial_type = POLICY_DENIAL_TYPE_INVALID;
        policy->zone_soa_serial = POLICY_ZONE_SOA_SERIAL_INVALID;
    }

    return policy;
}

void policy_free(policy_t* policy) {
    if (policy) {
        if (policy->dbo) {
            db_object_free(policy->dbo);
        }
        db_value_reset(&(policy->id));
        if (policy->name) {
            free(policy->name);
        }
        if (policy->description) {
            free(policy->description);
        }
        if (policy->denial_salt) {
            free(policy->denial_salt);
        }
        mm_alloc_delete(&__policy_alloc, policy);
    }
}

void policy_reset(policy_t* policy) {
    if (policy) {
        db_value_reset(&(policy->id));
        if (policy->name) {
            free(policy->name);
        }
        policy->name = NULL;
        if (policy->description) {
            free(policy->description);
        }
        policy->description = NULL;
        policy->signatures_resign = 0;
        policy->signatures_refresh = 0;
        policy->signatures_jitter = 0;
        policy->signatures_inception_offset = 0;
        policy->signatures_validity_default = 0;
        policy->signatures_validity_denial = 0;
        policy->signatures_max_zone_ttl = 86400;
        policy->denial_type = POLICY_DENIAL_TYPE_INVALID;
        policy->denial_optout = 0;
        policy->denial_ttl = 0;
        policy->denial_resalt = 0;
        policy->denial_algorithm = 0;
        policy->denial_iterations = 0;
        policy->denial_salt_length = 0;
        if (policy->denial_salt) {
            free(policy->denial_salt);
        }
        policy->denial_salt = NULL;
        policy->denial_salt_last_change = 0;
        policy->keys_ttl = 0;
        policy->keys_retire_safety = 0;
        policy->keys_publish_safety = 0;
        policy->keys_shared = 0;
        policy->keys_purge_after = 0;
        policy->zone_propagation_delay = 0;
        policy->zone_soa_ttl = 0;
        policy->zone_soa_minimum = 0;
        policy->zone_soa_serial = POLICY_ZONE_SOA_SERIAL_INVALID;
        policy->parent_propagation_delay = 0;
        policy->parent_ds_ttl = 0;
        policy->parent_soa_ttl = 0;
        policy->parent_soa_minimum = 0;
    }
}

int policy_copy(policy_t* policy, const policy_t* policy_copy) {
    char* name_text = NULL;
    char* description_text = NULL;
    char* denial_salt_text = NULL;
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy_copy->name) {
        if (!(name_text = strdup(policy_copy->name))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    if (policy_copy->description) {
        if (!(description_text = strdup(policy_copy->description))) {
            if (name_text) {
                free(name_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (policy_copy->denial_salt) {
        if (!(denial_salt_text = strdup(policy_copy->denial_salt))) {
            if (name_text) {
                free(name_text);
            }
            if (description_text) {
                free(description_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (db_value_copy(&(policy->id), &(policy_copy->id))) {
        if (name_text) {
            free(name_text);
        }
        if (description_text) {
            free(description_text);
        }
        if (denial_salt_text) {
            free(denial_salt_text);
        }
        return DB_ERROR_UNKNOWN;
    }
    if (policy->name) {
        free(policy->name);
    }
    policy->name = name_text;
    if (policy->description) {
        free(policy->description);
    }
    policy->description = description_text;
    policy->signatures_resign = policy_copy->signatures_resign;
    policy->signatures_refresh = policy_copy->signatures_refresh;
    policy->signatures_jitter = policy_copy->signatures_jitter;
    policy->signatures_inception_offset = policy_copy->signatures_inception_offset;
    policy->signatures_validity_default = policy_copy->signatures_validity_default;
    policy->signatures_validity_denial = policy_copy->signatures_validity_denial;
    policy->signatures_max_zone_ttl = policy_copy->signatures_max_zone_ttl;
    policy->denial_type = policy_copy->denial_type;
    policy->denial_optout = policy_copy->denial_optout;
    policy->denial_ttl = policy_copy->denial_ttl;
    policy->denial_resalt = policy_copy->denial_resalt;
    policy->denial_algorithm = policy_copy->denial_algorithm;
    policy->denial_iterations = policy_copy->denial_iterations;
    policy->denial_salt_length = policy_copy->denial_salt_length;
    if (policy->denial_salt) {
        free(policy->denial_salt);
    }
    policy->denial_salt = denial_salt_text;
    policy->denial_salt_last_change = policy_copy->denial_salt_last_change;
    policy->keys_ttl = policy_copy->keys_ttl;
    policy->keys_retire_safety = policy_copy->keys_retire_safety;
    policy->keys_publish_safety = policy_copy->keys_publish_safety;
    policy->keys_shared = policy_copy->keys_shared;
    policy->keys_purge_after = policy_copy->keys_purge_after;
    policy->zone_propagation_delay = policy_copy->zone_propagation_delay;
    policy->zone_soa_ttl = policy_copy->zone_soa_ttl;
    policy->zone_soa_minimum = policy_copy->zone_soa_minimum;
    policy->zone_soa_serial = policy_copy->zone_soa_serial;
    policy->parent_propagation_delay = policy_copy->parent_propagation_delay;
    policy->parent_ds_ttl = policy_copy->parent_ds_ttl;
    policy->parent_soa_ttl = policy_copy->parent_soa_ttl;
    policy->parent_soa_minimum = policy_copy->parent_soa_minimum;
    return DB_OK;
}

int policy_from_result(policy_t* policy, const db_result_t* result) {
    const db_value_set_t* value_set;
    int denial_type;
    int zone_soa_serial;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(policy->id));
    if (policy->name) {
        free(policy->name);
    }
    policy->name = NULL;
    if (policy->description) {
        free(policy->description);
    }
    policy->description = NULL;
    if (policy->denial_salt) {
        free(policy->denial_salt);
    }
    policy->denial_salt = NULL;
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 32
        || db_value_copy(&(policy->id), db_value_set_at(value_set, 0))
        || db_value_to_text(db_value_set_at(value_set, 1), &(policy->name))
        || db_value_to_text(db_value_set_at(value_set, 2), &(policy->description))
        || db_value_to_uint32(db_value_set_at(value_set, 3), &(policy->signatures_resign))
        || db_value_to_uint32(db_value_set_at(value_set, 4), &(policy->signatures_refresh))
        || db_value_to_uint32(db_value_set_at(value_set, 5), &(policy->signatures_jitter))
        || db_value_to_uint32(db_value_set_at(value_set, 6), &(policy->signatures_inception_offset))
        || db_value_to_uint32(db_value_set_at(value_set, 7), &(policy->signatures_validity_default))
        || db_value_to_uint32(db_value_set_at(value_set, 8), &(policy->signatures_validity_denial))
        || db_value_to_uint32(db_value_set_at(value_set, 9), &(policy->signatures_max_zone_ttl))
        || db_value_to_enum_value(db_value_set_at(value_set, 10), &denial_type, __enum_set_denial_type)
        || db_value_to_uint32(db_value_set_at(value_set, 11), &(policy->denial_optout))
        || db_value_to_uint32(db_value_set_at(value_set, 12), &(policy->denial_ttl))
        || db_value_to_uint32(db_value_set_at(value_set, 13), &(policy->denial_resalt))
        || db_value_to_uint32(db_value_set_at(value_set, 14), &(policy->denial_algorithm))
        || db_value_to_uint32(db_value_set_at(value_set, 15), &(policy->denial_iterations))
        || db_value_to_uint32(db_value_set_at(value_set, 16), &(policy->denial_salt_length))
        || db_value_to_text(db_value_set_at(value_set, 17), &(policy->denial_salt))
        || db_value_to_uint32(db_value_set_at(value_set, 18), &(policy->denial_salt_last_change))
        || db_value_to_uint32(db_value_set_at(value_set, 19), &(policy->keys_ttl))
        || db_value_to_uint32(db_value_set_at(value_set, 20), &(policy->keys_retire_safety))
        || db_value_to_uint32(db_value_set_at(value_set, 21), &(policy->keys_publish_safety))
        || db_value_to_uint32(db_value_set_at(value_set, 22), &(policy->keys_shared))
        || db_value_to_uint32(db_value_set_at(value_set, 23), &(policy->keys_purge_after))
        || db_value_to_uint32(db_value_set_at(value_set, 24), &(policy->zone_propagation_delay))
        || db_value_to_uint32(db_value_set_at(value_set, 25), &(policy->zone_soa_ttl))
        || db_value_to_uint32(db_value_set_at(value_set, 26), &(policy->zone_soa_minimum))
        || db_value_to_enum_value(db_value_set_at(value_set, 27), &zone_soa_serial, __enum_set_zone_soa_serial)
        || db_value_to_uint32(db_value_set_at(value_set, 28), &(policy->parent_propagation_delay))
        || db_value_to_uint32(db_value_set_at(value_set, 29), &(policy->parent_ds_ttl))
        || db_value_to_uint32(db_value_set_at(value_set, 30), &(policy->parent_soa_ttl))
        || db_value_to_uint32(db_value_set_at(value_set, 31), &(policy->parent_soa_minimum)))
    {
        return DB_ERROR_UNKNOWN;
    }

    if (denial_type == (policy_denial_type_t)POLICY_DENIAL_TYPE_NSEC) {
        policy->denial_type = POLICY_DENIAL_TYPE_NSEC;
    }
    else if (denial_type == (policy_denial_type_t)POLICY_DENIAL_TYPE_NSEC3) {
        policy->denial_type = POLICY_DENIAL_TYPE_NSEC3;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    if (zone_soa_serial == (policy_zone_soa_serial_t)POLICY_ZONE_SOA_SERIAL_COUNTER) {
        policy->zone_soa_serial = POLICY_ZONE_SOA_SERIAL_COUNTER;
    }
    else if (zone_soa_serial == (policy_zone_soa_serial_t)POLICY_ZONE_SOA_SERIAL_DATECOUNTER) {
        policy->zone_soa_serial = POLICY_ZONE_SOA_SERIAL_DATECOUNTER;
    }
    else if (zone_soa_serial == (policy_zone_soa_serial_t)POLICY_ZONE_SOA_SERIAL_UNIXTIME) {
        policy->zone_soa_serial = POLICY_ZONE_SOA_SERIAL_UNIXTIME;
    }
    else if (zone_soa_serial == (policy_zone_soa_serial_t)POLICY_ZONE_SOA_SERIAL_KEEP) {
        policy->zone_soa_serial = POLICY_ZONE_SOA_SERIAL_KEEP;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

const db_value_t* policy_id(const policy_t* policy) {
    if (!policy) {
        return NULL;
    }

    return &(policy->id);
}

const char* policy_name(const policy_t* policy) {
    if (!policy) {
        return NULL;
    }

    return policy->name;
}

const char* policy_description(const policy_t* policy) {
    if (!policy) {
        return NULL;
    }

    return policy->description;
}

unsigned int policy_signatures_resign(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->signatures_resign;
}

unsigned int policy_signatures_refresh(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->signatures_refresh;
}

unsigned int policy_signatures_jitter(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->signatures_jitter;
}

unsigned int policy_signatures_inception_offset(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->signatures_inception_offset;
}

unsigned int policy_signatures_validity_default(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->signatures_validity_default;
}

unsigned int policy_signatures_validity_denial(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->signatures_validity_denial;
}

unsigned int policy_signatures_max_zone_ttl(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->signatures_max_zone_ttl;
}

policy_denial_type_t policy_denial_type(const policy_t* policy) {
    if (!policy) {
        return POLICY_DENIAL_TYPE_INVALID;
    }

    return policy->denial_type;
}

const char* policy_denial_type_text(const policy_t* policy) {
    const db_enum_t* enum_set = __enum_set_denial_type;

    if (!policy) {
        return NULL;
    }

    while (enum_set->text) {
        if (enum_set->value == policy->denial_type) {
            return enum_set->text;
        }
        enum_set++;
    }
    return NULL;
}

unsigned int policy_denial_optout(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->denial_optout;
}

unsigned int policy_denial_ttl(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->denial_ttl;
}

unsigned int policy_denial_resalt(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->denial_resalt;
}

unsigned int policy_denial_algorithm(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->denial_algorithm;
}

unsigned int policy_denial_iterations(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->denial_iterations;
}

unsigned int policy_denial_salt_length(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->denial_salt_length;
}

const char* policy_denial_salt(const policy_t* policy) {
    if (!policy) {
        return NULL;
    }

    return policy->denial_salt;
}

unsigned int policy_denial_salt_last_change(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->denial_salt_last_change;
}

unsigned int policy_keys_ttl(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->keys_ttl;
}

unsigned int policy_keys_retire_safety(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->keys_retire_safety;
}

unsigned int policy_keys_publish_safety(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->keys_publish_safety;
}

unsigned int policy_keys_shared(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->keys_shared;
}

unsigned int policy_keys_purge_after(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->keys_purge_after;
}

unsigned int policy_zone_propagation_delay(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->zone_propagation_delay;
}

unsigned int policy_zone_soa_ttl(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->zone_soa_ttl;
}

unsigned int policy_zone_soa_minimum(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->zone_soa_minimum;
}

policy_zone_soa_serial_t policy_zone_soa_serial(const policy_t* policy) {
    if (!policy) {
        return POLICY_ZONE_SOA_SERIAL_INVALID;
    }

    return policy->zone_soa_serial;
}

const char* policy_zone_soa_serial_text(const policy_t* policy) {
    const db_enum_t* enum_set = __enum_set_zone_soa_serial;

    if (!policy) {
        return NULL;
    }

    while (enum_set->text) {
        if (enum_set->value == policy->zone_soa_serial) {
            return enum_set->text;
        }
        enum_set++;
    }
    return NULL;
}

unsigned int policy_parent_propagation_delay(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->parent_propagation_delay;
}

unsigned int policy_parent_ds_ttl(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->parent_ds_ttl;
}

unsigned int policy_parent_soa_ttl(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->parent_soa_ttl;
}

unsigned int policy_parent_soa_minimum(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->parent_soa_minimum;
}

int policy_set_name(policy_t* policy, const char* name_text) {
    char* new_name;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!name_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_name = strdup(name_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy->name) {
        free(policy->name);
    }
    policy->name = new_name;

    return DB_OK;
}

int policy_set_description(policy_t* policy, const char* description_text) {
    char* new_description;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!description_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_description = strdup(description_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy->description) {
        free(policy->description);
    }
    policy->description = new_description;

    return DB_OK;
}

int policy_set_signatures_resign(policy_t* policy, unsigned int signatures_resign) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->signatures_resign = signatures_resign;

    return DB_OK;
}

int policy_set_signatures_refresh(policy_t* policy, unsigned int signatures_refresh) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->signatures_refresh = signatures_refresh;

    return DB_OK;
}

int policy_set_signatures_jitter(policy_t* policy, unsigned int signatures_jitter) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->signatures_jitter = signatures_jitter;

    return DB_OK;
}

int policy_set_signatures_inception_offset(policy_t* policy, unsigned int signatures_inception_offset) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->signatures_inception_offset = signatures_inception_offset;

    return DB_OK;
}

int policy_set_signatures_validity_default(policy_t* policy, unsigned int signatures_validity_default) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->signatures_validity_default = signatures_validity_default;

    return DB_OK;
}

int policy_set_signatures_validity_denial(policy_t* policy, unsigned int signatures_validity_denial) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->signatures_validity_denial = signatures_validity_denial;

    return DB_OK;
}

int policy_set_signatures_max_zone_ttl(policy_t* policy, unsigned int signatures_max_zone_ttl) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->signatures_max_zone_ttl = signatures_max_zone_ttl;

    return DB_OK;
}

int policy_set_denial_type(policy_t* policy, policy_denial_type_t denial_type) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->denial_type = denial_type;

    return DB_OK;
}

int policy_set_denial_type_text(policy_t* policy, const char* denial_type) {
    const db_enum_t* enum_set = __enum_set_denial_type;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    while (enum_set->text) {
        if (!strcmp(enum_set->text, denial_type)) {
            policy->denial_type = enum_set->value;
            return DB_OK;
        }
        enum_set++;
    }
    return DB_ERROR_UNKNOWN;
}

int policy_set_denial_optout(policy_t* policy, unsigned int denial_optout) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->denial_optout = denial_optout;

    return DB_OK;
}

int policy_set_denial_ttl(policy_t* policy, unsigned int denial_ttl) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->denial_ttl = denial_ttl;

    return DB_OK;
}

int policy_set_denial_resalt(policy_t* policy, unsigned int denial_resalt) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->denial_resalt = denial_resalt;

    return DB_OK;
}

int policy_set_denial_algorithm(policy_t* policy, unsigned int denial_algorithm) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->denial_algorithm = denial_algorithm;

    return DB_OK;
}

int policy_set_denial_iterations(policy_t* policy, unsigned int denial_iterations) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->denial_iterations = denial_iterations;

    return DB_OK;
}

int policy_set_denial_salt_length(policy_t* policy, unsigned int denial_salt_length) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->denial_salt_length = denial_salt_length;

    return DB_OK;
}

int policy_set_denial_salt(policy_t* policy, const char* denial_salt_text) {
    char* new_denial_salt;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!denial_salt_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_denial_salt = strdup(denial_salt_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy->denial_salt) {
        free(policy->denial_salt);
    }
    policy->denial_salt = new_denial_salt;

    return DB_OK;
}

int policy_set_denial_salt_last_change(policy_t* policy, unsigned int denial_salt_last_change) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->denial_salt_last_change = denial_salt_last_change;

    return DB_OK;
}

int policy_set_keys_ttl(policy_t* policy, unsigned int keys_ttl) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->keys_ttl = keys_ttl;

    return DB_OK;
}

int policy_set_keys_retire_safety(policy_t* policy, unsigned int keys_retire_safety) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->keys_retire_safety = keys_retire_safety;

    return DB_OK;
}

int policy_set_keys_publish_safety(policy_t* policy, unsigned int keys_publish_safety) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->keys_publish_safety = keys_publish_safety;

    return DB_OK;
}

int policy_set_keys_shared(policy_t* policy, unsigned int keys_shared) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->keys_shared = keys_shared;

    return DB_OK;
}

int policy_set_keys_purge_after(policy_t* policy, unsigned int keys_purge_after) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->keys_purge_after = keys_purge_after;

    return DB_OK;
}

int policy_set_zone_propagation_delay(policy_t* policy, unsigned int zone_propagation_delay) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->zone_propagation_delay = zone_propagation_delay;

    return DB_OK;
}

int policy_set_zone_soa_ttl(policy_t* policy, unsigned int zone_soa_ttl) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->zone_soa_ttl = zone_soa_ttl;

    return DB_OK;
}

int policy_set_zone_soa_minimum(policy_t* policy, unsigned int zone_soa_minimum) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->zone_soa_minimum = zone_soa_minimum;

    return DB_OK;
}

int policy_set_zone_soa_serial(policy_t* policy, policy_zone_soa_serial_t zone_soa_serial) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->zone_soa_serial = zone_soa_serial;

    return DB_OK;
}

int policy_set_zone_soa_serial_text(policy_t* policy, const char* zone_soa_serial) {
    const db_enum_t* enum_set = __enum_set_zone_soa_serial;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    while (enum_set->text) {
        if (!strcmp(enum_set->text, zone_soa_serial)) {
            policy->zone_soa_serial = enum_set->value;
            return DB_OK;
        }
        enum_set++;
    }
    return DB_ERROR_UNKNOWN;
}

int policy_set_parent_propagation_delay(policy_t* policy, unsigned int parent_propagation_delay) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->parent_propagation_delay = parent_propagation_delay;

    return DB_OK;
}

int policy_set_parent_ds_ttl(policy_t* policy, unsigned int parent_ds_ttl) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->parent_ds_ttl = parent_ds_ttl;

    return DB_OK;
}

int policy_set_parent_soa_ttl(policy_t* policy, unsigned int parent_soa_ttl) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->parent_soa_ttl = parent_soa_ttl;

    return DB_OK;
}

int policy_set_parent_soa_minimum(policy_t* policy, unsigned int parent_soa_minimum) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->parent_soa_minimum = parent_soa_minimum;

    return DB_OK;
}

int policy_create(policy_t* policy) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!db_value_not_empty(&(policy->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->name) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->description) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->denial_salt) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "name")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "description")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesResign")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesRefresh")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesJitter")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesInceptionOffset")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesValidityDefault")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesValidityDenial")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesMaxZoneTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialType")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_denial_type)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialOptout")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialResalt")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialAlgorithm")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialIterations")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialSaltLength")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialSalt")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialSaltLastChange")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysRetireSafety")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysPublishSafety")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysShared")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysPurgeAfter")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zonePropagationDelay")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zoneSoaTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zoneSoaMinimum")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zoneSoaSerial")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_zone_soa_serial)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentPropagationDelay")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentDsTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentSoaTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentSoaMinimum")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(31))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_text(db_value_set_get(value_set, 0), policy->name)
        || db_value_from_text(db_value_set_get(value_set, 1), policy->description)
        || db_value_from_uint32(db_value_set_get(value_set, 2), policy->signatures_resign)
        || db_value_from_uint32(db_value_set_get(value_set, 3), policy->signatures_refresh)
        || db_value_from_uint32(db_value_set_get(value_set, 4), policy->signatures_jitter)
        || db_value_from_uint32(db_value_set_get(value_set, 5), policy->signatures_inception_offset)
        || db_value_from_uint32(db_value_set_get(value_set, 6), policy->signatures_validity_default)
        || db_value_from_uint32(db_value_set_get(value_set, 7), policy->signatures_validity_denial)
        || db_value_from_uint32(db_value_set_get(value_set, 8), policy->signatures_max_zone_ttl)
        || db_value_from_enum_value(db_value_set_get(value_set, 9), policy->denial_type, __enum_set_denial_type)
        || db_value_from_uint32(db_value_set_get(value_set, 10), policy->denial_optout)
        || db_value_from_uint32(db_value_set_get(value_set, 11), policy->denial_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 12), policy->denial_resalt)
        || db_value_from_uint32(db_value_set_get(value_set, 13), policy->denial_algorithm)
        || db_value_from_uint32(db_value_set_get(value_set, 14), policy->denial_iterations)
        || db_value_from_uint32(db_value_set_get(value_set, 15), policy->denial_salt_length)
        || db_value_from_text(db_value_set_get(value_set, 16), policy->denial_salt)
        || db_value_from_uint32(db_value_set_get(value_set, 17), policy->denial_salt_last_change)
        || db_value_from_uint32(db_value_set_get(value_set, 18), policy->keys_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 19), policy->keys_retire_safety)
        || db_value_from_uint32(db_value_set_get(value_set, 20), policy->keys_publish_safety)
        || db_value_from_uint32(db_value_set_get(value_set, 21), policy->keys_shared)
        || db_value_from_uint32(db_value_set_get(value_set, 22), policy->keys_purge_after)
        || db_value_from_uint32(db_value_set_get(value_set, 23), policy->zone_propagation_delay)
        || db_value_from_uint32(db_value_set_get(value_set, 24), policy->zone_soa_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 25), policy->zone_soa_minimum)
        || db_value_from_enum_value(db_value_set_get(value_set, 26), policy->zone_soa_serial, __enum_set_zone_soa_serial)
        || db_value_from_uint32(db_value_set_get(value_set, 27), policy->parent_propagation_delay)
        || db_value_from_uint32(db_value_set_get(value_set, 28), policy->parent_ds_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 29), policy->parent_soa_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 30), policy->parent_soa_minimum))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(policy->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int policy_get_by_id(policy_t* policy, const db_value_t* id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!id) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(id)) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    result_list = db_object_read(policy->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (policy_from_result(policy, result)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }
                
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int policy_get_by_name(policy_t* policy, const char* name) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!name) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "name")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_text(db_clause_get_value(clause), name)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    result_list = db_object_read(policy->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (policy_from_result(policy, result)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }
                
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int policy_update(policy_t* policy) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->name) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->description) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->denial_salt) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "name")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "description")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesResign")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesRefresh")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesJitter")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesInceptionOffset")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesValidityDefault")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesValidityDenial")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signaturesMaxZoneTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialType")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_denial_type)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialOptout")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialResalt")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialAlgorithm")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialIterations")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialSaltLength")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialSalt")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denialSaltLastChange")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysRetireSafety")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysPublishSafety")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysShared")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keysPurgeAfter")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zonePropagationDelay")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zoneSoaTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zoneSoaMinimum")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zoneSoaSerial")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_zone_soa_serial)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentPropagationDelay")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentDsTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentSoaTtl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentSoaMinimum")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(31))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_text(db_value_set_get(value_set, 0), policy->name)
        || db_value_from_text(db_value_set_get(value_set, 1), policy->description)
        || db_value_from_uint32(db_value_set_get(value_set, 2), policy->signatures_resign)
        || db_value_from_uint32(db_value_set_get(value_set, 3), policy->signatures_refresh)
        || db_value_from_uint32(db_value_set_get(value_set, 4), policy->signatures_jitter)
        || db_value_from_uint32(db_value_set_get(value_set, 5), policy->signatures_inception_offset)
        || db_value_from_uint32(db_value_set_get(value_set, 6), policy->signatures_validity_default)
        || db_value_from_uint32(db_value_set_get(value_set, 7), policy->signatures_validity_denial)
        || db_value_from_uint32(db_value_set_get(value_set, 8), policy->signatures_max_zone_ttl)
        || db_value_from_enum_value(db_value_set_get(value_set, 9), policy->denial_type, __enum_set_denial_type)
        || db_value_from_uint32(db_value_set_get(value_set, 10), policy->denial_optout)
        || db_value_from_uint32(db_value_set_get(value_set, 11), policy->denial_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 12), policy->denial_resalt)
        || db_value_from_uint32(db_value_set_get(value_set, 13), policy->denial_algorithm)
        || db_value_from_uint32(db_value_set_get(value_set, 14), policy->denial_iterations)
        || db_value_from_uint32(db_value_set_get(value_set, 15), policy->denial_salt_length)
        || db_value_from_text(db_value_set_get(value_set, 16), policy->denial_salt)
        || db_value_from_uint32(db_value_set_get(value_set, 17), policy->denial_salt_last_change)
        || db_value_from_uint32(db_value_set_get(value_set, 18), policy->keys_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 19), policy->keys_retire_safety)
        || db_value_from_uint32(db_value_set_get(value_set, 20), policy->keys_publish_safety)
        || db_value_from_uint32(db_value_set_get(value_set, 21), policy->keys_shared)
        || db_value_from_uint32(db_value_set_get(value_set, 22), policy->keys_purge_after)
        || db_value_from_uint32(db_value_set_get(value_set, 23), policy->zone_propagation_delay)
        || db_value_from_uint32(db_value_set_get(value_set, 24), policy->zone_soa_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 25), policy->zone_soa_minimum)
        || db_value_from_enum_value(db_value_set_get(value_set, 26), policy->zone_soa_serial, __enum_set_zone_soa_serial)
        || db_value_from_uint32(db_value_set_get(value_set, 27), policy->parent_propagation_delay)
        || db_value_from_uint32(db_value_set_get(value_set, 28), policy->parent_ds_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 29), policy->parent_soa_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 30), policy->parent_soa_minimum))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(policy->id))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(policy->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int policy_delete(policy_t* policy) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->id))) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(policy->id))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(policy->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* POLICY LIST */

static mm_alloc_t __policy_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(policy_list_t));

policy_list_t* policy_list_new(const db_connection_t* connection) {
    policy_list_t* policy_list =
        (policy_list_t*)mm_alloc_new0(&__policy_list_alloc);

    if (policy_list) {
        if (!(policy_list->dbo = __policy_new_object(connection))) {
            mm_alloc_delete(&__policy_list_alloc, policy_list);
            return NULL;
        }
    }

    return policy_list;
}

void policy_list_free(policy_list_t* policy_list) {
    if (policy_list) {
        if (policy_list->dbo) {
            db_object_free(policy_list->dbo);
        }
        if (policy_list->result_list) {
            db_result_list_free(policy_list->result_list);
        }
        if (policy_list->policy) {
            policy_free(policy_list->policy);
        }
        mm_alloc_delete(&__policy_list_alloc, policy_list);
    }
}

int policy_list_get(policy_list_t* policy_list) {
    if (!policy_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy_list->result_list) {
        db_result_list_free(policy_list->result_list);
    }
    if (!(policy_list->result_list = db_object_read(policy_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const policy_t* policy_list_begin(policy_list_t* policy_list) {
    const db_result_t* result;

    if (!policy_list) {
        return NULL;
    }
    if (!policy_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(policy_list->result_list))) {
        return NULL;
    }
    if (!policy_list->policy) {
        if (!(policy_list->policy = policy_new(db_object_connection(policy_list->dbo)))) {
            return NULL;
        }
    }
    if (policy_from_result(policy_list->policy, result)) {
        return NULL;
    }
    return policy_list->policy;
}

const policy_t* policy_list_next(policy_list_t* policy_list) {
    const db_result_t* result;

    if (!policy_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(policy_list->result_list))) {
        return NULL;
    }
    if (!policy_list->policy) {
        if (!(policy_list->policy = policy_new(db_object_connection(policy_list->dbo)))) {
            return NULL;
        }
    }
    if (policy_from_result(policy_list->policy, result)) {
        return NULL;
    }
    return policy_list->policy;
}
