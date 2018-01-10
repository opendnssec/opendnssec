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


#include <string.h>

const db_enum_t policy_enum_set_denial_type[] = {
    { "NSEC", (policy_denial_type_t)POLICY_DENIAL_TYPE_NSEC },
    { "NSEC3", (policy_denial_type_t)POLICY_DENIAL_TYPE_NSEC3 },
    { NULL, 0 }
};

const db_enum_t policy_enum_set_zone_soa_serial[] = {
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
        || db_object_field_set_name(object_field, "rev")
        || db_object_field_set_type(object_field, DB_TYPE_REVISION)
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
        || db_object_field_set_name(object_field, "signaturesValidityKeyset")
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
        || db_object_field_set_enum_set(object_field, policy_enum_set_denial_type)
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
        || db_object_field_set_enum_set(object_field, policy_enum_set_zone_soa_serial)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentRegistrationDelay")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
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

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "passthrough")
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

policy_t* policy_new(const db_connection_t* connection) {
    policy_t* policy =
        (policy_t*)calloc(1, sizeof(policy_t));

    if (policy) {
        if (!(policy->dbo = __policy_new_object(connection))) {
            free(policy);
            return NULL;
        }
        db_value_reset(&(policy->id));
        db_value_reset(&(policy->rev));
        policy->signatures_max_zone_ttl = 86400;
        policy->denial_type = POLICY_DENIAL_TYPE_INVALID;
        policy->denial_salt = strdup("");
        policy->zone_soa_serial = POLICY_ZONE_SOA_SERIAL_INVALID;
    }

    return policy;
}

policy_t* policy_new_copy(const policy_t* policy) {
    policy_t* new_policy;

    if (!policy) {
        return NULL;
    }
    if (!policy->dbo) {
        return NULL;
    }

    if (!(new_policy = policy_new(db_object_connection(policy->dbo)))
        || policy_copy(new_policy, policy))
    {
        policy_free(new_policy);
        return NULL;
    }
    return new_policy;
}

void policy_free(policy_t* policy) {
    if (policy) {
        if (policy->dbo) {
            db_object_free(policy->dbo);
        }
        db_value_reset(&(policy->id));
        db_value_reset(&(policy->rev));
        if (policy->name) {
            free(policy->name);
        }
        if (policy->description) {
            free(policy->description);
        }
        if (policy->denial_salt) {
            free(policy->denial_salt);
        }
        if (policy->policy_key_list) {
            policy_key_list_free(policy->policy_key_list);
        }
        if (policy->zone_list) {
            zone_list_db_free(policy->zone_list);
        }
        if (policy->hsm_key_list) {
            hsm_key_list_free(policy->hsm_key_list);
        }
        free(policy);
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
    if (db_value_copy(&(policy->rev), &(policy_copy->rev))) {
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
    if (policy->policy_key_list) {
        policy_key_list_free(policy->policy_key_list);
        policy->policy_key_list = NULL;
    }
    if (policy_copy->policy_key_list
        && !(policy->policy_key_list = policy_key_list_new_copy(policy_copy->policy_key_list)))
    {
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
    if (policy->zone_list) {
        zone_list_db_free(policy->zone_list);
        policy->zone_list = NULL;
    }
    if (policy_copy->zone_list
        && !(policy->zone_list = zone_list_db_new_copy(policy_copy->zone_list)))
    {
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
    if (policy->hsm_key_list) {
        hsm_key_list_free(policy->hsm_key_list);
        policy->hsm_key_list = NULL;
    }
    if (policy_copy->hsm_key_list
        && !(policy->hsm_key_list = hsm_key_list_new_copy(policy_copy->hsm_key_list)))
    {
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
    policy->signatures_validity_keyset = policy_copy->signatures_validity_keyset;
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
    policy->parent_registration_delay = policy_copy->parent_registration_delay;
    policy->parent_propagation_delay = policy_copy->parent_propagation_delay;
    policy->parent_ds_ttl = policy_copy->parent_ds_ttl;
    policy->parent_soa_ttl = policy_copy->parent_soa_ttl;
    policy->parent_soa_minimum = policy_copy->parent_soa_minimum;
    policy->passthrough = policy_copy->passthrough;
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
    db_value_reset(&(policy->rev));
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
    policy->signatures_validity_keyset = 0;
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 36
        || db_value_copy(&(policy->id), db_value_set_at(value_set, 0))
        || db_value_copy(&(policy->rev), db_value_set_at(value_set, 1))
        || db_value_to_text(db_value_set_at(value_set, 2), &(policy->name))
        || db_value_to_text(db_value_set_at(value_set, 3), &(policy->description))
        || db_value_to_uint32(db_value_set_at(value_set, 4), &(policy->signatures_resign))
        || db_value_to_uint32(db_value_set_at(value_set, 5), &(policy->signatures_refresh))
        || db_value_to_uint32(db_value_set_at(value_set, 6), &(policy->signatures_jitter))
        || db_value_to_uint32(db_value_set_at(value_set, 7), &(policy->signatures_inception_offset))
        || db_value_to_uint32(db_value_set_at(value_set, 8), &(policy->signatures_validity_default))
        || db_value_to_uint32(db_value_set_at(value_set, 9), &(policy->signatures_validity_denial))
        || (db_value_to_uint32(db_value_set_at(value_set, 10), &(policy->signatures_validity_keyset)) && 0)
        || db_value_to_uint32(db_value_set_at(value_set, 11), &(policy->signatures_max_zone_ttl))
        || db_value_to_enum_value(db_value_set_at(value_set, 12), &denial_type, policy_enum_set_denial_type)
        || db_value_to_uint32(db_value_set_at(value_set, 13), &(policy->denial_optout))
        || db_value_to_uint32(db_value_set_at(value_set, 14), &(policy->denial_ttl))
        || db_value_to_uint32(db_value_set_at(value_set, 15), &(policy->denial_resalt))
        || db_value_to_uint32(db_value_set_at(value_set, 16), &(policy->denial_algorithm))
        || db_value_to_uint32(db_value_set_at(value_set, 17), &(policy->denial_iterations))
        || db_value_to_uint32(db_value_set_at(value_set, 18), &(policy->denial_salt_length))
        || db_value_to_text(db_value_set_at(value_set, 19), &(policy->denial_salt))
        || db_value_to_uint32(db_value_set_at(value_set, 20), &(policy->denial_salt_last_change))
        || db_value_to_uint32(db_value_set_at(value_set, 21), &(policy->keys_ttl))
        || db_value_to_uint32(db_value_set_at(value_set, 22), &(policy->keys_retire_safety))
        || db_value_to_uint32(db_value_set_at(value_set, 23), &(policy->keys_publish_safety))
        || db_value_to_uint32(db_value_set_at(value_set, 24), &(policy->keys_shared))
        || db_value_to_uint32(db_value_set_at(value_set, 25), &(policy->keys_purge_after))
        || db_value_to_uint32(db_value_set_at(value_set, 26), &(policy->zone_propagation_delay))
        || db_value_to_uint32(db_value_set_at(value_set, 27), &(policy->zone_soa_ttl))
        || db_value_to_uint32(db_value_set_at(value_set, 28), &(policy->zone_soa_minimum))
        || db_value_to_enum_value(db_value_set_at(value_set, 29), &zone_soa_serial, policy_enum_set_zone_soa_serial)
        || db_value_to_uint32(db_value_set_at(value_set, 30), &(policy->parent_registration_delay))
        || db_value_to_uint32(db_value_set_at(value_set, 31), &(policy->parent_propagation_delay))
        || db_value_to_uint32(db_value_set_at(value_set, 32), &(policy->parent_ds_ttl))
        || db_value_to_uint32(db_value_set_at(value_set, 33), &(policy->parent_soa_ttl))
        || db_value_to_uint32(db_value_set_at(value_set, 34), &(policy->parent_soa_minimum))
        || db_value_to_uint32(db_value_set_at(value_set, 35), &(policy->passthrough)))
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

unsigned int policy_signatures_validity_keyset(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->signatures_validity_keyset;
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

const char* policy_zone_soa_serial_text(const policy_t* policy) {
    const db_enum_t* enum_set = policy_enum_set_zone_soa_serial;

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

const char* policy_zone_soa_serial_text2(unsigned int zone_soa_serial)
{
    const db_enum_t* enum_set = policy_enum_set_zone_soa_serial;
    while (enum_set->text) {
        if (enum_set->value == zone_soa_serial) {
            return enum_set->text;
        }
        enum_set++;
    }
    return NULL;
}

unsigned int policy_parent_registration_delay(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->parent_registration_delay;
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

unsigned int policy_passthrough(const policy_t* policy) {
    if (!policy) {
        return 0;
    }

    return policy->passthrough;
}

zone_list_db_t* policy_zone_list(policy_t* policy) {

    if (!policy) {
        return NULL;
    }
    if (!policy->dbo) {
        return NULL;
    }

    if (!policy->zone_list
        && policy_retrieve_zone_list(policy))
    {
        return NULL;
    }

    return policy->zone_list;
}

int policy_retrieve_zone_list(policy_t* policy) {
    db_clause_list_t* clause_list;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy->zone_list) {
        zone_list_db_free(policy->zone_list);
        policy->zone_list = NULL;
    }

    if (!(clause_list = db_clause_list_new())
        || !zone_db_policy_id_clause(clause_list, policy_id(policy))
        || !(policy->zone_list = zone_list_db_new(db_object_connection(policy->dbo)))
        || zone_list_db_object_store(policy->zone_list)
        || zone_list_db_get_by_clauses(policy->zone_list, clause_list))
    {
        zone_list_db_free(policy->zone_list);
        policy->zone_list = NULL;
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    db_clause_list_free(clause_list);

    return DB_OK;
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

int policy_set_signatures_validity_keyset(policy_t* policy, unsigned int signatures_validity_keyset) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->signatures_validity_keyset = signatures_validity_keyset;

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
    if (denial_type == POLICY_DENIAL_TYPE_INVALID) {
        return DB_ERROR_UNKNOWN;
    }

    policy->denial_type = denial_type;

    return DB_OK;
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

    if (denial_algorithm > 255) {
        return DB_ERROR_UNKNOWN;
    }

    policy->denial_algorithm = denial_algorithm;

    return DB_OK;
}

int policy_set_denial_iterations(policy_t* policy, unsigned int denial_iterations) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    if (denial_iterations > 65535) {
        return DB_ERROR_UNKNOWN;
    }

    policy->denial_iterations = denial_iterations;

    return DB_OK;
}

int policy_set_denial_salt_length(policy_t* policy, unsigned int denial_salt_length) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    if (denial_salt_length > 255) {
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

int policy_set_zone_soa_serial_text(policy_t* policy, const char* zone_soa_serial) {
    const db_enum_t* enum_set = policy_enum_set_zone_soa_serial;

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

int policy_set_parent_registration_delay(policy_t* policy, unsigned int parent_registration_delay) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->parent_registration_delay = parent_registration_delay;

    return DB_OK;
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

int policy_set_passthrough(policy_t* policy, unsigned int passthrough) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }

    policy->passthrough = passthrough;

    return DB_OK;
}

db_clause_t* policy_denial_type_clause(db_clause_list_t* clause_list, policy_denial_type_t denial_type) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "denialType")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_enum_value(db_clause_get_value(clause), denial_type, policy_enum_set_denial_type)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
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
    if (!db_value_not_empty(&(policy->rev))) {
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
        || db_object_field_set_name(object_field, "signaturesValidityKeyset")
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
        || db_object_field_set_enum_set(object_field, policy_enum_set_denial_type)
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
        || db_object_field_set_enum_set(object_field, policy_enum_set_zone_soa_serial)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentRegistrationDelay")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
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

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "passthrough")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(34))) {
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
        || (db_value_from_uint32(db_value_set_get(value_set, 8), policy->signatures_validity_keyset) && 0) /* not an error, the database layer cannot handle optional fields */
        || db_value_from_uint32(db_value_set_get(value_set, 9), policy->signatures_max_zone_ttl)
        || db_value_from_enum_value(db_value_set_get(value_set, 10), policy->denial_type, policy_enum_set_denial_type)
        || db_value_from_uint32(db_value_set_get(value_set, 11), policy->denial_optout)
        || db_value_from_uint32(db_value_set_get(value_set, 12), policy->denial_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 13), policy->denial_resalt)
        || db_value_from_uint32(db_value_set_get(value_set, 14), policy->denial_algorithm)
        || db_value_from_uint32(db_value_set_get(value_set, 15), policy->denial_iterations)
        || db_value_from_uint32(db_value_set_get(value_set, 16), policy->denial_salt_length)
        || db_value_from_text(db_value_set_get(value_set, 17), policy->denial_salt)
        || db_value_from_uint32(db_value_set_get(value_set, 18), policy->denial_salt_last_change)
        || db_value_from_uint32(db_value_set_get(value_set, 19), policy->keys_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 20), policy->keys_retire_safety)
        || db_value_from_uint32(db_value_set_get(value_set, 21), policy->keys_publish_safety)
        || db_value_from_uint32(db_value_set_get(value_set, 22), policy->keys_shared)
        || db_value_from_uint32(db_value_set_get(value_set, 23), policy->keys_purge_after)
        || db_value_from_uint32(db_value_set_get(value_set, 24), policy->zone_propagation_delay)
        || db_value_from_uint32(db_value_set_get(value_set, 25), policy->zone_soa_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 26), policy->zone_soa_minimum)
        || db_value_from_enum_value(db_value_set_get(value_set, 27), policy->zone_soa_serial, policy_enum_set_zone_soa_serial)
        || db_value_from_uint32(db_value_set_get(value_set, 28), policy->parent_registration_delay)
        || db_value_from_uint32(db_value_set_get(value_set, 29), policy->parent_propagation_delay)
        || db_value_from_uint32(db_value_set_get(value_set, 30), policy->parent_ds_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 31), policy->parent_soa_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 32), policy->parent_soa_minimum)
        || db_value_from_uint32(db_value_set_get(value_set, 33), policy->passthrough))
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
        result = db_result_list_next(result_list);
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
        result = db_result_list_next(result_list);
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

policy_t* policy_new_get_by_name(const db_connection_t* connection, const char* name) {
    policy_t* policy;

    if (!connection) {
        return NULL;
    }
    if (!name) {
        return NULL;
    }

    if (!(policy = policy_new(connection))
        || policy_get_by_name(policy, name))
    {
        policy_free(policy);
        return NULL;
    }

    return policy;
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
    if (db_value_not_empty(&(policy->rev))) {
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
        || db_object_field_set_name(object_field, "signaturesValidityKeyset")
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
        || db_object_field_set_enum_set(object_field, policy_enum_set_denial_type)
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
        || db_object_field_set_enum_set(object_field, policy_enum_set_zone_soa_serial)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parentRegistrationDelay")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
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

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "passthrough")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(34))) {
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
        || (db_value_from_uint32(db_value_set_get(value_set, 8), policy->signatures_validity_keyset) && 0) /* the database layer cannot handle optional fields */
        || db_value_from_uint32(db_value_set_get(value_set, 9), policy->signatures_max_zone_ttl)
        || db_value_from_enum_value(db_value_set_get(value_set, 10), policy->denial_type, policy_enum_set_denial_type)
        || db_value_from_uint32(db_value_set_get(value_set, 11), policy->denial_optout)
        || db_value_from_uint32(db_value_set_get(value_set, 12), policy->denial_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 13), policy->denial_resalt)
        || db_value_from_uint32(db_value_set_get(value_set, 14), policy->denial_algorithm)
        || db_value_from_uint32(db_value_set_get(value_set, 15), policy->denial_iterations)
        || db_value_from_uint32(db_value_set_get(value_set, 16), policy->denial_salt_length)
        || db_value_from_text(db_value_set_get(value_set, 17), policy->denial_salt)
        || db_value_from_uint32(db_value_set_get(value_set, 18), policy->denial_salt_last_change)
        || db_value_from_uint32(db_value_set_get(value_set, 19), policy->keys_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 20), policy->keys_retire_safety)
        || db_value_from_uint32(db_value_set_get(value_set, 21), policy->keys_publish_safety)
        || db_value_from_uint32(db_value_set_get(value_set, 22), policy->keys_shared)
        || db_value_from_uint32(db_value_set_get(value_set, 23), policy->keys_purge_after)
        || db_value_from_uint32(db_value_set_get(value_set, 24), policy->zone_propagation_delay)
        || db_value_from_uint32(db_value_set_get(value_set, 25), policy->zone_soa_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 26), policy->zone_soa_minimum)
        || db_value_from_enum_value(db_value_set_get(value_set, 27), policy->zone_soa_serial, policy_enum_set_zone_soa_serial)
        || db_value_from_uint32(db_value_set_get(value_set, 28), policy->parent_registration_delay)
        || db_value_from_uint32(db_value_set_get(value_set, 29), policy->parent_propagation_delay)
        || db_value_from_uint32(db_value_set_get(value_set, 30), policy->parent_ds_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 31), policy->parent_soa_ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 32), policy->parent_soa_minimum)
        || db_value_from_uint32(db_value_set_get(value_set, 33), policy->passthrough))
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

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "rev")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(policy->rev))
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

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "rev")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(policy->rev))
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



policy_list_t* policy_list_new(const db_connection_t* connection) {
    policy_list_t* policy_list =
        (policy_list_t*)calloc(1, sizeof(policy_list_t));

    if (policy_list) {
        if (!(policy_list->dbo = __policy_new_object(connection))) {
            free(policy_list);
            return NULL;
        }
    }

    return policy_list;
}

policy_list_t* policy_list_new_copy(const policy_list_t* from_policy_list) {
    policy_list_t* policy_list;

    if (!from_policy_list) {
        return NULL;
    }
    if (!from_policy_list->dbo) {
        return NULL;
    }

    if (!(policy_list = policy_list_new(db_object_connection(from_policy_list->dbo)))
        || policy_list_copy(policy_list, from_policy_list))
    {
        policy_list_free(policy_list);
        return NULL;
    }
    return policy_list;
}

int policy_list_object_store(policy_list_t* policy_list) {
    if (!policy_list) {
        return DB_ERROR_UNKNOWN;
    }

    policy_list->object_store = 1;

    return DB_OK;
}

void policy_list_free(policy_list_t* policy_list) {
    size_t i;

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
        for (i = 0; i < policy_list->object_list_size; i++) {
            if (policy_list->object_list[i]) {
                policy_free(policy_list->object_list[i]);
            }
        }
        if (policy_list->object_list) {
            free(policy_list->object_list);
        }
        free(policy_list);
    }
}

int policy_list_copy(policy_list_t* policy_list, const policy_list_t* from_policy_list) {
    size_t i;

    if (!policy_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!from_policy_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (from_policy_list->object_list && !from_policy_list->object_list_size) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy_list->result_list) {
        db_result_list_free(policy_list->result_list);
        policy_list->result_list = NULL;
    }
    if (from_policy_list->result_list
        && !(policy_list->result_list = db_result_list_new_copy(from_policy_list->result_list)))
    {
        return DB_ERROR_UNKNOWN;
    }

    policy_list->object_store = from_policy_list->object_store;
    for (i = 0; i < policy_list->object_list_size; i++) {
        if (policy_list->object_list[i]) {
            policy_free(policy_list->object_list[i]);
        }
    }
    policy_list->object_list_size = 0;
    if (policy_list->object_list) {
        free(policy_list->object_list);
        policy_list->object_list = NULL;
    }
    if (from_policy_list->object_list) {
        if (!(policy_list->object_list = (policy_t**)calloc(from_policy_list->object_list_size, sizeof(policy_t*)))) {
            return DB_ERROR_UNKNOWN;
        }
        policy_list->object_list_size = from_policy_list->object_list_size;
        for (i = 0; i < from_policy_list->object_list_size; i++) {
            if (!from_policy_list->object_list[i]) {
                continue;
            }
            if (!(policy_list->object_list[i] = policy_new_copy(from_policy_list->object_list[i]))) {
                return DB_ERROR_UNKNOWN;
            }
        }
    }
    policy_list->object_list_position = 0;;
    policy_list->object_list_first = 1;
    policy_list->associated_fetch = from_policy_list->associated_fetch;

    return DB_OK;
}

static int policy_list_get_associated(policy_list_t* policy_list) {
    size_t j, count;
    int cmp;
    size_t i;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    const policy_t* policy;
    policy_key_list_t* policy_key_list;
    const policy_key_t* policy_key;
    zone_list_db_t* zone_list;
    const zone_db_t* zone;
    hsm_key_list_t* hsm_key_list;
    const hsm_key_t* hsm_key;

    if (!policy_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_list->associated_fetch) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_list->result_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (policy_list->object_list) {
        return DB_ERROR_UNKNOWN;
    }

    policy = policy_list_begin(policy_list);
    while (policy) {
        policy = policy_list_next(policy_list);
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    policy = policy_list_begin(policy_list);
    while (policy) {
        if (!(clause = db_clause_new())
            || db_clause_set_field(clause, "policyId")
            || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
            || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_OR)
            || db_value_copy(db_clause_get_value(clause), policy_id(policy))
            || db_clause_list_add(clause_list, clause))
        {
            db_clause_free(clause);
            db_clause_list_free(clause_list);
            return DB_ERROR_UNKNOWN;
        }

        policy = policy_list_next(policy_list);
    }

    if (!(policy_key_list = policy_key_list_new(db_object_connection(policy_list->dbo)))
        || policy_key_list_object_store(policy_key_list)
        || policy_key_list_get_by_clauses(policy_key_list, clause_list))
    {
        policy_key_list_free(policy_key_list);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    for (i = 0; i < policy_list->object_list_size; i++) {
        if (!(policy_list->object_list[i])) {
            return DB_ERROR_UNKNOWN;
        }

        count = 0;
        policy_key = policy_key_list_begin(policy_key_list);
        while (policy_key) {
            if (db_value_cmp(policy_id(policy_list->object_list[i]), policy_key_policy_id(policy_key), &cmp)) {
                policy_key_list_free(policy_key_list);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }
            if (!cmp) {
                count++;
            }
            policy_key = policy_key_list_next(policy_key_list);
        }
        if (policy_list->object_list[i]->policy_key_list) {
            policy_key_list_free(policy_list->object_list[i]->policy_key_list);
            policy_list->object_list[i]->policy_key_list = NULL;
        }
        if (!(policy_list->object_list[i]->policy_key_list = policy_key_list_new(db_object_connection(policy_list->dbo)))) {
            policy_key_list_free(policy_key_list);
            db_clause_list_free(clause_list);
            return DB_ERROR_UNKNOWN;
        }
        if (count) {
            if (!(policy_list->object_list[i]->policy_key_list->object_list = (policy_key_t**)calloc(count, sizeof(policy_key_t*)))) {
                policy_key_list_free(policy_key_list);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }

            j = 0;
            policy_key = policy_key_list_begin(policy_key_list);
            while (policy_key) {
                if (j >= count) {
                    policy_key_list_free(policy_key_list);
                    db_clause_list_free(clause_list);
                    return DB_ERROR_UNKNOWN;
                }
                if (db_value_cmp(policy_id(policy_list->object_list[i]), policy_key_policy_id(policy_key), &cmp)) {
                    policy_key_list_free(policy_key_list);
                    db_clause_list_free(clause_list);
                    return DB_ERROR_UNKNOWN;
                }
                if (!cmp) {
                    if (!(policy_list->object_list[i]->policy_key_list->object_list[j] = policy_key_new_copy(policy_key))) {
                        policy_key_list_free(policy_key_list);
                        db_clause_list_free(clause_list);
                        return DB_ERROR_UNKNOWN;
                    }
                    j++;
                }
                policy_key = policy_key_list_next(policy_key_list);
            }
            if (j != count) {
                policy_key_list_free(policy_key_list);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }
        }
        policy_list->object_list[i]->policy_key_list->object_store = 1;
        policy_list->object_list[i]->policy_key_list->object_list_size = count;
        policy_list->object_list[i]->policy_key_list->object_list_first = 1;
    }

    if (!(zone_list = zone_list_db_new(db_object_connection(policy_list->dbo)))
        || zone_list_db_object_store(zone_list)
        || zone_list_db_get_by_clauses(zone_list, clause_list))
    {
        zone_list_db_free(zone_list);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    for (i = 0; i < policy_list->object_list_size; i++) {
        if (!(policy_list->object_list[i])) {
            zone_list_db_free(zone_list);
            db_clause_list_free(clause_list);
            return DB_ERROR_UNKNOWN;
        }

        count = 0;
        zone = zone_list_db_begin(zone_list);
        while (zone) {
            if (db_value_cmp(policy_id(policy_list->object_list[i]), zone_db_policy_id(zone), &cmp)) {
                zone_list_db_free(zone_list);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }
            if (!cmp) {
                count++;
            }
            zone = zone_list_db_next(zone_list);
        }
        if (policy_list->object_list[i]->zone_list) {
            zone_list_db_free(policy_list->object_list[i]->zone_list);
            policy_list->object_list[i]->zone_list = NULL;
        }
        if (!(policy_list->object_list[i]->zone_list = zone_list_db_new(db_object_connection(policy_list->dbo)))) {
            zone_list_db_free(zone_list);
            db_clause_list_free(clause_list);
            return DB_ERROR_UNKNOWN;
        }
        if (count) {
            if (!(policy_list->object_list[i]->zone_list->object_list = (zone_db_t**)calloc(count, sizeof(zone_db_t*)))) {
                zone_list_db_free(zone_list);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }

            j = 0;
            zone = zone_list_db_begin(zone_list);
            while (zone) {
                if (j >= count) {
                    zone_list_db_free(zone_list);
                    db_clause_list_free(clause_list);
                    return DB_ERROR_UNKNOWN;
                }
                if (db_value_cmp(policy_id(policy_list->object_list[i]), zone_db_policy_id(zone), &cmp)) {
                    zone_list_db_free(zone_list);
                    db_clause_list_free(clause_list);
                    return DB_ERROR_UNKNOWN;
                }
                if (!cmp) {
                    if (!(policy_list->object_list[i]->zone_list->object_list[j] = zone_db_new_copy(zone))) {
                        zone_list_db_free(zone_list);
                        db_clause_list_free(clause_list);
                        return DB_ERROR_UNKNOWN;
                    }
                    j++;
                }
                zone = zone_list_db_next(zone_list);
            }
            if (j != count) {
                zone_list_db_free(zone_list);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }
        }
        policy_list->object_list[i]->zone_list->object_store = 1;
        policy_list->object_list[i]->zone_list->object_list_size = count;
        policy_list->object_list[i]->zone_list->object_list_first = 1;
    }
    zone_list_db_free(zone_list);

    if (!(hsm_key_list = hsm_key_list_new(db_object_connection(policy_list->dbo)))
        || hsm_key_list_object_store(hsm_key_list)
        || hsm_key_list_get_by_clauses(hsm_key_list, clause_list))
    {
        hsm_key_list_free(hsm_key_list);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    for (i = 0; i < policy_list->object_list_size; i++) {
        if (!(policy_list->object_list[i])) {
            hsm_key_list_free(hsm_key_list);
            return DB_ERROR_UNKNOWN;
        }

        count = 0;
        hsm_key = hsm_key_list_begin(hsm_key_list);
        while (hsm_key) {
            if (db_value_cmp(policy_id(policy_list->object_list[i]), hsm_key_policy_id(hsm_key), &cmp)) {
                hsm_key_list_free(hsm_key_list);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }
            if (!cmp) {
                count++;
            }
            hsm_key = hsm_key_list_next(hsm_key_list);
        }
        if (policy_list->object_list[i]->hsm_key_list) {
            hsm_key_list_free(policy_list->object_list[i]->hsm_key_list);
            policy_list->object_list[i]->hsm_key_list = NULL;
        }
        if (!(policy_list->object_list[i]->hsm_key_list = hsm_key_list_new(db_object_connection(policy_list->dbo)))) {
            hsm_key_list_free(hsm_key_list);
            db_clause_list_free(clause_list);
            return DB_ERROR_UNKNOWN;
        }
        if (count) {
            if (!(policy_list->object_list[i]->hsm_key_list->object_list = (hsm_key_t**)calloc(count, sizeof(hsm_key_t*)))) {
                hsm_key_list_free(hsm_key_list);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }

            j = 0;
            hsm_key = hsm_key_list_begin(hsm_key_list);
            while (hsm_key) {
                if (j >= count) {
                    hsm_key_list_free(hsm_key_list);
                    db_clause_list_free(clause_list);
                    return DB_ERROR_UNKNOWN;
                }
                if (db_value_cmp(policy_id(policy_list->object_list[i]), hsm_key_policy_id(hsm_key), &cmp)) {
                    hsm_key_list_free(hsm_key_list);
                    db_clause_list_free(clause_list);
                    return DB_ERROR_UNKNOWN;
                }
                if (!cmp) {
                    if (!(policy_list->object_list[i]->hsm_key_list->object_list[j] = hsm_key_new_copy(hsm_key))) {
                        hsm_key_list_free(hsm_key_list);
                        db_clause_list_free(clause_list);
                        return DB_ERROR_UNKNOWN;
                    }
                    j++;
                }
                hsm_key = hsm_key_list_next(hsm_key_list);
            }
            if (j != count) {
                hsm_key_list_free(hsm_key_list);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }
        }
        policy_list->object_list[i]->hsm_key_list->object_store = 1;
        policy_list->object_list[i]->hsm_key_list->object_list_size = count;
        policy_list->object_list[i]->hsm_key_list->object_list_first = 1;
    }
    db_clause_list_free(clause_list);
    hsm_key_list_free(hsm_key_list);

    policy_list->object_list_first = 1;
    return DB_OK;
}

int policy_list_get(policy_list_t* policy_list) {
    size_t i;

    if (!policy_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy_list->result_list) {
        db_result_list_free(policy_list->result_list);
    }
    if (policy_list->object_list_size) {
        for (i = 0; i < policy_list->object_list_size; i++) {
            if (policy_list->object_list[i]) {
                policy_free(policy_list->object_list[i]);
            }
        }
        policy_list->object_list_size = 0;
        policy_list->object_list_first = 0;
    }
    if (policy_list->object_list) {
        free(policy_list->object_list);
        policy_list->object_list = NULL;
    }
    if (!(policy_list->result_list = db_object_read(policy_list->dbo, NULL, NULL))
        || db_result_list_fetch_all(policy_list->result_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    if (policy_list->associated_fetch
        && policy_list_get_associated(policy_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

policy_list_t* policy_list_new_get(const db_connection_t* connection) {
    policy_list_t* policy_list;

    if (!connection) {
        return NULL;
    }

    if (!(policy_list = policy_list_new(connection))
        || policy_list_get(policy_list))
    {
        policy_list_free(policy_list);
        return NULL;
    }

    return policy_list;
}

int policy_list_get_by_clauses(policy_list_t* policy_list, const db_clause_list_t* clause_list) {
    size_t i;

    if (!policy_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!clause_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy_list->result_list) {
        db_result_list_free(policy_list->result_list);
    }
    if (policy_list->object_list_size) {
        for (i = 0; i < policy_list->object_list_size; i++) {
            if (policy_list->object_list[i]) {
                policy_free(policy_list->object_list[i]);
            }
        }
        policy_list->object_list_size = 0;
        policy_list->object_list_first = 0;
    }
    if (policy_list->object_list) {
        free(policy_list->object_list);
        policy_list->object_list = NULL;
    }
    if (!(policy_list->result_list = db_object_read(policy_list->dbo, NULL, clause_list))
        || db_result_list_fetch_all(policy_list->result_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    if (policy_list->associated_fetch
        && policy_list_get_associated(policy_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

policy_list_t* policy_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list) {
    policy_list_t* policy_list;

    if (!connection) {
        return NULL;
    }
    if (!clause_list) {
        return NULL;
    }

    if (!(policy_list = policy_list_new(connection))
        || policy_list_get_by_clauses(policy_list, clause_list))
    {
        policy_list_free(policy_list);
        return NULL;
    }

    return policy_list;
}

const policy_t* policy_list_begin(policy_list_t* policy_list) {
    const db_result_t* result;

    if (!policy_list) {
        return NULL;
    }

    if (policy_list->object_store) {
        if (!policy_list->object_list) {
            if (!policy_list->result_list) {
                return NULL;
            }
            if (!db_result_list_size(policy_list->result_list)) {
                return NULL;
            }
            if (!(policy_list->object_list = (policy_t**)calloc(db_result_list_size(policy_list->result_list), sizeof(policy_t*)))) {
                return NULL;
            }
            policy_list->object_list_size = db_result_list_size(policy_list->result_list);
        }
        if (!(policy_list->object_list[0])) {
            if (!policy_list->result_list) {
                return NULL;
            }
            if (!(result = db_result_list_begin(policy_list->result_list))) {
                return NULL;
            }
            if (!(policy_list->object_list[0] = policy_new(db_object_connection(policy_list->dbo)))) {
                return NULL;
            }
            if (policy_from_result(policy_list->object_list[0], result)) {
                return NULL;
            }
        }
        policy_list->object_list_position = 0;
        return policy_list->object_list[0];
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

    if (policy_list->object_store) {
        if (!policy_list->object_list) {
            if (!policy_list->result_list) {
                return NULL;
            }
            if (!db_result_list_size(policy_list->result_list)) {
                return NULL;
            }
            if (!(policy_list->object_list = (policy_t**)calloc(db_result_list_size(policy_list->result_list), sizeof(policy_t*)))) {
                return NULL;
            }
            policy_list->object_list_size = db_result_list_size(policy_list->result_list);
            policy_list->object_list_position = 0;
        }
        else if (policy_list->object_list_first) {
            policy_list->object_list_first = 0;
            policy_list->object_list_position = 0;
        }
        else {
            policy_list->object_list_position++;
        }
        if (policy_list->object_list_position >= policy_list->object_list_size) {
            return NULL;
        }
        if (!(policy_list->object_list[policy_list->object_list_position])) {
            if (!policy_list->result_list) {
                return NULL;
            }
            if (!(result = db_result_list_next(policy_list->result_list))) {
                return NULL;
            }
            if (!(policy_list->object_list[policy_list->object_list_position] = policy_new(db_object_connection(policy_list->dbo)))) {
                return NULL;
            }
            if (policy_from_result(policy_list->object_list[policy_list->object_list_position], result)) {
                return NULL;
            }
        }
        return policy_list->object_list[policy_list->object_list_position];
    }

    if (!policy_list->result_list) {
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

policy_t* policy_list_get_next(policy_list_t* policy_list) {
    const db_result_t* result;
    policy_t* policy;

    if (!policy_list) {
        return NULL;
    }

    if (policy_list->object_store) {
        if (!(policy = policy_new(db_object_connection(policy_list->dbo)))) {
            return NULL;
        }
        if (policy_copy(policy, policy_list_next(policy_list))) {
            policy_free(policy);
            return NULL;
        }
        return policy;
    }

    if (!policy_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(policy_list->result_list))) {
        return NULL;
    }
    if (!(policy = policy_new(db_object_connection(policy_list->dbo)))) {
        return NULL;
    }
    if (policy_from_result(policy, result)) {
        policy_free(policy);
        return NULL;
    }
    return policy;
}

size_t
policy_list_size(policy_list_t* policy_list)
{
    if (!policy_list)
        return 0;
    if (policy_list->object_store && policy_list->object_list)
        return policy_list->object_list_size;
    if (!policy_list->result_list)
        return 0;
    return db_result_list_size(policy_list->result_list);
}
