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

#include "hsm_key.h"
#include "db_error.h"


#include <string.h>

const db_enum_t hsm_key_enum_set_state[] = {
    { "UNUSED", (hsm_key_state_t)HSM_KEY_STATE_UNUSED },
    { "PRIVATE", (hsm_key_state_t)HSM_KEY_STATE_PRIVATE },
    { "SHARED", (hsm_key_state_t)HSM_KEY_STATE_SHARED },
    { "DELETE", (hsm_key_state_t)HSM_KEY_STATE_DELETE },
    { NULL, 0 }
};

const db_enum_t hsm_key_enum_set_role[] = {
    { "KSK", (hsm_key_role_t)HSM_KEY_ROLE_KSK },
    { "ZSK", (hsm_key_role_t)HSM_KEY_ROLE_ZSK },
    { "CSK", (hsm_key_role_t)HSM_KEY_ROLE_CSK },
    { NULL, 0 }
};

const db_enum_t hsm_key_enum_set_key_type[] = {
    { "RSA", (hsm_key_key_type_t)HSM_KEY_KEY_TYPE_RSA },
    { NULL, 0 }
};

const db_enum_t hsm_key_enum_set_backup[] = {
    { "Not Required", (hsm_key_backup_t)HSM_KEY_BACKUP_NO_BACKUP },
    { "Required", (hsm_key_backup_t)HSM_KEY_BACKUP_BACKUP_REQUIRED },
    { "Prepared", (hsm_key_backup_t)HSM_KEY_BACKUP_BACKUP_REQUESTED },
    { "Done", (hsm_key_backup_t)HSM_KEY_BACKUP_BACKUP_DONE },
    { NULL, 0 }
};

/**
 * Create a new hsm key object.
 * \param[in] connection a db_connection_t pointer.
 * \return a hsm_key_t pointer or NULL on error.
 */
static db_object_t* __hsm_key_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "hsmKey")
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
        || db_object_field_set_name(object_field, "policyId")
        || db_object_field_set_type(object_field, DB_TYPE_ANY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "locator")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "state")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, hsm_key_enum_set_state)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "bits")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "algorithm")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "role")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, hsm_key_enum_set_role)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "inception")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "isRevoked")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keyType")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, hsm_key_enum_set_key_type)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "repository")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "backup")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, hsm_key_enum_set_backup)
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

/* HSM KEY */



hsm_key_t* hsm_key_new(const db_connection_t* connection) {
    hsm_key_t* hsm_key =
        (hsm_key_t*)calloc(1, sizeof(hsm_key_t));

    if (hsm_key) {
        if (!(hsm_key->dbo = __hsm_key_new_object(connection))) {
            free(hsm_key);
            return NULL;
        }
        db_value_reset(&(hsm_key->id));
        db_value_reset(&(hsm_key->rev));
        db_value_reset(&(hsm_key->policy_id));
        hsm_key->state = HSM_KEY_STATE_UNUSED;
        hsm_key->bits = 2048;
        hsm_key->algorithm = 1;
        hsm_key->role = HSM_KEY_ROLE_ZSK;
        hsm_key->key_type = HSM_KEY_KEY_TYPE_RSA;
        hsm_key->backup = HSM_KEY_BACKUP_NO_BACKUP;
    }

    return hsm_key;
}

hsm_key_t* hsm_key_new_copy(const hsm_key_t* hsm_key) {
    hsm_key_t* new_hsm_key;

    if (!hsm_key) {
        return NULL;
    }
    if (!hsm_key->dbo) {
        return NULL;
    }

    if (!(new_hsm_key = hsm_key_new(db_object_connection(hsm_key->dbo)))
        || hsm_key_copy(new_hsm_key, hsm_key))
    {
        hsm_key_free(new_hsm_key);
        return NULL;
    }
    return new_hsm_key;
}

void hsm_key_free(hsm_key_t* hsm_key) {
    if (hsm_key) {
        if (hsm_key->dbo) {
            db_object_free(hsm_key->dbo);
        }
        db_value_reset(&(hsm_key->id));
        db_value_reset(&(hsm_key->rev));
        db_value_reset(&(hsm_key->policy_id));
        if (hsm_key->private_policy_id) {
            policy_free(hsm_key->private_policy_id);
        }
        if (hsm_key->locator) {
            free(hsm_key->locator);
        }
        if (hsm_key->repository) {
            free(hsm_key->repository);
        }
        free(hsm_key);
    }
}

int hsm_key_copy(hsm_key_t* hsm_key, const hsm_key_t* hsm_key_copy) {
    char* locator_text = NULL;
    char* repository_text = NULL;

    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (hsm_key_copy->locator) {
        if (!(locator_text = strdup(hsm_key_copy->locator))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    if (hsm_key_copy->repository) {
        if (!(repository_text = strdup(hsm_key_copy->repository))) {
            if (locator_text) {
                free(locator_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (db_value_copy(&(hsm_key->id), &(hsm_key_copy->id))) {
        if (locator_text) {
            free(locator_text);
        }
        if (repository_text) {
            free(repository_text);
        }
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_copy(&(hsm_key->rev), &(hsm_key_copy->rev))) {
        if (locator_text) {
            free(locator_text);
        }
        if (repository_text) {
            free(repository_text);
        }
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_copy(&(hsm_key->policy_id), &(hsm_key_copy->policy_id))) {
        if (locator_text) {
            free(locator_text);
        }
        if (repository_text) {
            free(repository_text);
        }
        return DB_ERROR_UNKNOWN;
    }
    if (hsm_key->private_policy_id) {
        policy_free(hsm_key->private_policy_id);
        hsm_key->private_policy_id = NULL;
    }
    if (hsm_key_copy->private_policy_id
        && !(hsm_key->private_policy_id = policy_new_copy(hsm_key_copy->private_policy_id)))
    {
        if (locator_text) {
            free(locator_text);
        }
        if (repository_text) {
            free(repository_text);
        }
        return DB_ERROR_UNKNOWN;
    }
    hsm_key->associated_policy_id = NULL;
    if (!hsm_key_copy->private_policy_id
        && hsm_key_copy->associated_policy_id
        && !(hsm_key->private_policy_id = policy_new_copy(hsm_key_copy->associated_policy_id)))
    {
        if (locator_text) {
            free(locator_text);
        }
        if (repository_text) {
            free(repository_text);
        }
        return DB_ERROR_UNKNOWN;
    }
    if (hsm_key->locator) {
        free(hsm_key->locator);
    }
    hsm_key->locator = locator_text;
    hsm_key->state = hsm_key_copy->state;
    hsm_key->bits = hsm_key_copy->bits;
    hsm_key->algorithm = hsm_key_copy->algorithm;
    hsm_key->role = hsm_key_copy->role;
    hsm_key->inception = hsm_key_copy->inception;
    hsm_key->is_revoked = hsm_key_copy->is_revoked;
    hsm_key->key_type = hsm_key_copy->key_type;
    if (hsm_key->repository) {
        free(hsm_key->repository);
    }
    hsm_key->repository = repository_text;
    hsm_key->backup = hsm_key_copy->backup;
    return DB_OK;
}

int hsm_key_from_result(hsm_key_t* hsm_key, const db_result_t* result) {
    const db_value_set_t* value_set;
    int state;
    int role;
    int key_type;
    int backup;

    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(hsm_key->id));
    db_value_reset(&(hsm_key->rev));
    db_value_reset(&(hsm_key->policy_id));
    if (hsm_key->locator) {
        free(hsm_key->locator);
    }
    hsm_key->locator = NULL;
    if (hsm_key->repository) {
        free(hsm_key->repository);
    }
    hsm_key->repository = NULL;
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 13
        || db_value_copy(&(hsm_key->id), db_value_set_at(value_set, 0))
        || db_value_copy(&(hsm_key->rev), db_value_set_at(value_set, 1))
        || db_value_copy(&(hsm_key->policy_id), db_value_set_at(value_set, 2))
        || db_value_to_text(db_value_set_at(value_set, 3), &(hsm_key->locator))
        || db_value_to_enum_value(db_value_set_at(value_set, 4), &state, hsm_key_enum_set_state)
        || db_value_to_uint32(db_value_set_at(value_set, 5), &(hsm_key->bits))
        || db_value_to_uint32(db_value_set_at(value_set, 6), &(hsm_key->algorithm))
        || db_value_to_enum_value(db_value_set_at(value_set, 7), &role, hsm_key_enum_set_role)
        || db_value_to_uint32(db_value_set_at(value_set, 8), &(hsm_key->inception))
        || db_value_to_uint32(db_value_set_at(value_set, 9), &(hsm_key->is_revoked))
        || db_value_to_enum_value(db_value_set_at(value_set, 10), &key_type, hsm_key_enum_set_key_type)
        || db_value_to_text(db_value_set_at(value_set, 11), &(hsm_key->repository))
        || db_value_to_enum_value(db_value_set_at(value_set, 12), &backup, hsm_key_enum_set_backup))
    {
        return DB_ERROR_UNKNOWN;
    }

    if (state == (hsm_key_state_t)HSM_KEY_STATE_UNUSED) {
        hsm_key->state = HSM_KEY_STATE_UNUSED;
    }
    else if (state == (hsm_key_state_t)HSM_KEY_STATE_PRIVATE) {
        hsm_key->state = HSM_KEY_STATE_PRIVATE;
    }
    else if (state == (hsm_key_state_t)HSM_KEY_STATE_SHARED) {
        hsm_key->state = HSM_KEY_STATE_SHARED;
    }
    else if (state == (hsm_key_state_t)HSM_KEY_STATE_DELETE) {
        hsm_key->state = HSM_KEY_STATE_DELETE;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    if (role == (hsm_key_role_t)HSM_KEY_ROLE_KSK) {
        hsm_key->role = HSM_KEY_ROLE_KSK;
    }
    else if (role == (hsm_key_role_t)HSM_KEY_ROLE_ZSK) {
        hsm_key->role = HSM_KEY_ROLE_ZSK;
    }
    else if (role == (hsm_key_role_t)HSM_KEY_ROLE_CSK) {
        hsm_key->role = HSM_KEY_ROLE_CSK;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    if (key_type == (hsm_key_key_type_t)HSM_KEY_KEY_TYPE_RSA) {
        hsm_key->key_type = HSM_KEY_KEY_TYPE_RSA;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    if (backup == (hsm_key_backup_t)HSM_KEY_BACKUP_NO_BACKUP) {
        hsm_key->backup = HSM_KEY_BACKUP_NO_BACKUP;
    }
    else if (backup == (hsm_key_backup_t)HSM_KEY_BACKUP_BACKUP_REQUIRED) {
        hsm_key->backup = HSM_KEY_BACKUP_BACKUP_REQUIRED;
    }
    else if (backup == (hsm_key_backup_t)HSM_KEY_BACKUP_BACKUP_REQUESTED) {
        hsm_key->backup = HSM_KEY_BACKUP_BACKUP_REQUESTED;
    }
    else if (backup == (hsm_key_backup_t)HSM_KEY_BACKUP_BACKUP_DONE) {
        hsm_key->backup = HSM_KEY_BACKUP_BACKUP_DONE;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

const db_value_t* hsm_key_id(const hsm_key_t* hsm_key) {
    if (!hsm_key) {
        return NULL;
    }

    return &(hsm_key->id);
}

const db_value_t* hsm_key_policy_id(const hsm_key_t* hsm_key) {
    if (!hsm_key) {
        return NULL;
    }

    return &(hsm_key->policy_id);
}

const char* hsm_key_locator(const hsm_key_t* hsm_key) {
    if (!hsm_key) {
        return NULL;
    }

    return hsm_key->locator;
}

hsm_key_state_t hsm_key_state(const hsm_key_t* hsm_key) {
    if (!hsm_key) {
        return HSM_KEY_STATE_INVALID;
    }

    return hsm_key->state;
}

unsigned int hsm_key_bits(const hsm_key_t* hsm_key) {
    if (!hsm_key) {
        return 0;
    }

    return hsm_key->bits;
}

unsigned int hsm_key_algorithm(const hsm_key_t* hsm_key) {
    if (!hsm_key) {
        return 0;
    }

    return hsm_key->algorithm;
}

hsm_key_role_t hsm_key_role(const hsm_key_t* hsm_key) {
    if (!hsm_key) {
        return HSM_KEY_ROLE_INVALID;
    }

    return hsm_key->role;
}

unsigned int hsm_key_inception(const hsm_key_t* hsm_key) {
    if (!hsm_key) {
        return 0;
    }

    return hsm_key->inception;
}

const char* hsm_key_repository(const hsm_key_t* hsm_key) {
    if (!hsm_key) {
        return NULL;
    }

    return hsm_key->repository;
}

hsm_key_backup_t hsm_key_backup(const hsm_key_t* hsm_key) {
    if (!hsm_key) {
        return HSM_KEY_BACKUP_INVALID;
    }

    return hsm_key->backup;
}

int hsm_key_set_policy_id(hsm_key_t* hsm_key, const db_value_t* policy_id) {
    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_id) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(policy_id)) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(hsm_key->policy_id));
    if (db_value_copy(&(hsm_key->policy_id), policy_id)) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int hsm_key_set_locator(hsm_key_t* hsm_key, const char* locator_text) {
    char* new_locator;

    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!locator_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_locator = strdup(locator_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (hsm_key->locator) {
        free(hsm_key->locator);
    }
    hsm_key->locator = new_locator;

    return DB_OK;
}

int hsm_key_set_state(hsm_key_t* hsm_key, hsm_key_state_t state) {
    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (state == HSM_KEY_STATE_INVALID) {
        return DB_ERROR_UNKNOWN;
    }

    hsm_key->state = state;

    return DB_OK;
}

int hsm_key_set_bits(hsm_key_t* hsm_key, unsigned int bits) {
    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    hsm_key->bits = bits;

    return DB_OK;
}

int hsm_key_set_algorithm(hsm_key_t* hsm_key, unsigned int algorithm) {
    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    hsm_key->algorithm = algorithm;

    return DB_OK;
}

int hsm_key_set_role(hsm_key_t* hsm_key, hsm_key_role_t role) {
    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (role == HSM_KEY_ROLE_INVALID) {
        return DB_ERROR_UNKNOWN;
    }

    hsm_key->role = role;

    return DB_OK;
}

int hsm_key_set_inception(hsm_key_t* hsm_key, unsigned int inception) {
    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    hsm_key->inception = inception;

    return DB_OK;
}

int hsm_key_set_key_type(hsm_key_t* hsm_key, hsm_key_key_type_t key_type) {
    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (key_type == HSM_KEY_KEY_TYPE_INVALID) {
        return DB_ERROR_UNKNOWN;
    }

    hsm_key->key_type = key_type;

    return DB_OK;
}

int hsm_key_set_repository(hsm_key_t* hsm_key, const char* repository_text) {
    char* new_repository;

    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!repository_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_repository = strdup(repository_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (hsm_key->repository) {
        free(hsm_key->repository);
    }
    hsm_key->repository = new_repository;

    return DB_OK;
}

int hsm_key_set_backup(hsm_key_t* hsm_key, hsm_key_backup_t backup) {
    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (backup == HSM_KEY_BACKUP_INVALID) {
        return DB_ERROR_UNKNOWN;
    }

    hsm_key->backup = backup;

    return DB_OK;
}

db_clause_t* hsm_key_policy_id_clause(db_clause_list_t* clause_list, const db_value_t* policy_id) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!policy_id) {
        return NULL;
    }
    if (db_value_not_empty(policy_id)) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "policyId")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_copy(db_clause_get_value(clause), policy_id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* hsm_key_state_clause(db_clause_list_t* clause_list, hsm_key_state_t state) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "state")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_enum_value(db_clause_get_value(clause), state, hsm_key_enum_set_state)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* hsm_key_bits_clause(db_clause_list_t* clause_list, unsigned int bits) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "bits")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), bits)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* hsm_key_algorithm_clause(db_clause_list_t* clause_list, unsigned int algorithm) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "algorithm")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), algorithm)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* hsm_key_role_clause(db_clause_list_t* clause_list, hsm_key_role_t role) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "role")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_enum_value(db_clause_get_value(clause), role, hsm_key_enum_set_role)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* hsm_key_is_revoked_clause(db_clause_list_t* clause_list, unsigned int is_revoked) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "isRevoked")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), is_revoked)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* hsm_key_key_type_clause(db_clause_list_t* clause_list, hsm_key_key_type_t key_type) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "keyType")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_enum_value(db_clause_get_value(clause), key_type, hsm_key_enum_set_key_type)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* hsm_key_repository_clause(db_clause_list_t* clause_list, const char* repository_text) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!repository_text) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "repository")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_text(db_clause_get_value(clause), repository_text)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* hsm_key_backup_clause(db_clause_list_t* clause_list, hsm_key_backup_t backup) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "backup")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_enum_value(db_clause_get_value(clause), backup, hsm_key_enum_set_backup)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

int hsm_key_create(hsm_key_t* hsm_key) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!db_value_not_empty(&(hsm_key->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (!db_value_not_empty(&(hsm_key->rev))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(hsm_key->policy_id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key->locator) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key->repository) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "policyId")
        || db_object_field_set_type(object_field, DB_TYPE_ANY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "locator")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "state")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, hsm_key_enum_set_state)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "bits")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "algorithm")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "role")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, hsm_key_enum_set_role)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "inception")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "isRevoked")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keyType")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, hsm_key_enum_set_key_type)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "repository")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "backup")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, hsm_key_enum_set_backup)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(11))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_copy(db_value_set_get(value_set, 0), &(hsm_key->policy_id))
        || db_value_from_text(db_value_set_get(value_set, 1), hsm_key->locator)
        || db_value_from_enum_value(db_value_set_get(value_set, 2), hsm_key->state, hsm_key_enum_set_state)
        || db_value_from_uint32(db_value_set_get(value_set, 3), hsm_key->bits)
        || db_value_from_uint32(db_value_set_get(value_set, 4), hsm_key->algorithm)
        || db_value_from_enum_value(db_value_set_get(value_set, 5), hsm_key->role, hsm_key_enum_set_role)
        || db_value_from_uint32(db_value_set_get(value_set, 6), hsm_key->inception)
        || db_value_from_uint32(db_value_set_get(value_set, 7), hsm_key->is_revoked)
        || db_value_from_enum_value(db_value_set_get(value_set, 8), hsm_key->key_type, hsm_key_enum_set_key_type)
        || db_value_from_text(db_value_set_get(value_set, 9), hsm_key->repository)
        || db_value_from_enum_value(db_value_set_get(value_set, 10), hsm_key->backup, hsm_key_enum_set_backup))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(hsm_key->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int hsm_key_get_by_id(hsm_key_t* hsm_key, const db_value_t* id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key->dbo) {
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

    result_list = db_object_read(hsm_key->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_next(result_list);
        if (result) {
            if (hsm_key_from_result(hsm_key, result)) {
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

int hsm_key_get_by_locator(hsm_key_t* hsm_key, const char* locator) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!locator) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "locator")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_text(db_clause_get_value(clause), locator)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    result_list = db_object_read(hsm_key->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_next(result_list);
        if (result) {
            if (hsm_key_from_result(hsm_key, result)) {
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

hsm_key_t* hsm_key_new_get_by_locator(const db_connection_t* connection, const char* locator) {
    hsm_key_t* hsm_key;

    if (!connection) {
        return NULL;
    }
    if (!locator) {
        return NULL;
    }

    if (!(hsm_key = hsm_key_new(connection))
        || hsm_key_get_by_locator(hsm_key, locator))
    {
        hsm_key_free(hsm_key);
        return NULL;
    }

    return hsm_key;
}

int hsm_key_update(hsm_key_t* hsm_key) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(hsm_key->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(hsm_key->rev))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(hsm_key->policy_id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key->locator) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key->repository) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "policyId")
        || db_object_field_set_type(object_field, DB_TYPE_ANY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "locator")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "state")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, hsm_key_enum_set_state)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "bits")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "algorithm")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "role")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, hsm_key_enum_set_role)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "inception")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "isRevoked")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keyType")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, hsm_key_enum_set_key_type)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "repository")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "backup")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, hsm_key_enum_set_backup)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(11))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_copy(db_value_set_get(value_set, 0), &(hsm_key->policy_id))
        || db_value_from_text(db_value_set_get(value_set, 1), hsm_key->locator)
        || db_value_from_enum_value(db_value_set_get(value_set, 2), hsm_key->state, hsm_key_enum_set_state)
        || db_value_from_uint32(db_value_set_get(value_set, 3), hsm_key->bits)
        || db_value_from_uint32(db_value_set_get(value_set, 4), hsm_key->algorithm)
        || db_value_from_enum_value(db_value_set_get(value_set, 5), hsm_key->role, hsm_key_enum_set_role)
        || db_value_from_uint32(db_value_set_get(value_set, 6), hsm_key->inception)
        || db_value_from_uint32(db_value_set_get(value_set, 7), hsm_key->is_revoked)
        || db_value_from_enum_value(db_value_set_get(value_set, 8), hsm_key->key_type, hsm_key_enum_set_key_type)
        || db_value_from_text(db_value_set_get(value_set, 9), hsm_key->repository)
        || db_value_from_enum_value(db_value_set_get(value_set, 10), hsm_key->backup, hsm_key_enum_set_backup))
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
        || db_value_copy(db_clause_get_value(clause), &(hsm_key->id))
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
        || db_value_copy(db_clause_get_value(clause), &(hsm_key->rev))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(hsm_key->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int hsm_key_delete(hsm_key_t* hsmkey) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!hsmkey) return DB_ERROR_UNKNOWN;
    if (!hsmkey->dbo) return DB_ERROR_UNKNOWN;
    if (db_value_not_empty(&(hsmkey->id))) return DB_ERROR_UNKNOWN;
    if (!(clause_list = db_clause_list_new())) return DB_ERROR_UNKNOWN;

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(hsmkey->id))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "rev")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(hsmkey->rev))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(hsmkey->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

int hsm_key_count(hsm_key_t* hsm_key, db_clause_list_t* clause_list, size_t* count) {
    if (!hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!count) {
        return DB_ERROR_UNKNOWN;
    }

    return db_object_count(hsm_key->dbo, NULL, clause_list, count);
}

/* HSM KEY LIST */



hsm_key_list_t* hsm_key_list_new(const db_connection_t* connection) {
    hsm_key_list_t* hsm_key_list =
        (hsm_key_list_t*)calloc(1, sizeof(hsm_key_list_t));

    if (hsm_key_list) {
        if (!(hsm_key_list->dbo = __hsm_key_new_object(connection))) {
            free(hsm_key_list);
            return NULL;
        }
    }

    return hsm_key_list;
}

int hsm_key_list_get(hsm_key_list_t* hsm_key_list) {
    size_t i;

    if (!hsm_key_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (hsm_key_list->result_list) {
        db_result_list_free(hsm_key_list->result_list);
    }
    if (hsm_key_list->object_list_size) {
        for (i = 0; i < hsm_key_list->object_list_size; i++) {
            if (hsm_key_list->object_list[i]) {
                hsm_key_free(hsm_key_list->object_list[i]);
            }
        }
        hsm_key_list->object_list_size = 0;
        hsm_key_list->object_list_first = 0;
    }
    if (hsm_key_list->object_list) {
        free(hsm_key_list->object_list);
        hsm_key_list->object_list = NULL;
    }
    if (!(hsm_key_list->result_list = db_object_read(hsm_key_list->dbo, NULL, NULL))
        || db_result_list_fetch_all(hsm_key_list->result_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

hsm_key_list_t*
hsm_key_list_new_get(const db_connection_t* connection)
{
    hsm_key_list_t* hsm_key_list;
    if (!connection) return NULL;
    if (!(hsm_key_list = hsm_key_list_new(connection)) || hsm_key_list_get(hsm_key_list)) {
        hsm_key_list_free(hsm_key_list);
        return NULL;
    }
    return hsm_key_list;
}

size_t
hsm_key_list_size(hsm_key_list_t* hsm_key_list)
{
    if (!hsm_key_list) return 0;
    if (hsm_key_list->object_store && hsm_key_list->object_list)
        return hsm_key_list->object_list_size;
    if (!hsm_key_list->result_list) return 0;
    return db_result_list_size(hsm_key_list->result_list);
}

hsm_key_list_t* hsm_key_list_new_copy(const hsm_key_list_t* from_hsm_key_list) {
    hsm_key_list_t* hsm_key_list;

    if (!from_hsm_key_list) {
        return NULL;
    }
    if (!from_hsm_key_list->dbo) {
        return NULL;
    }

    if (!(hsm_key_list = hsm_key_list_new(db_object_connection(from_hsm_key_list->dbo)))
        || hsm_key_list_copy(hsm_key_list, from_hsm_key_list))
    {
        hsm_key_list_free(hsm_key_list);
        return NULL;
    }
    return hsm_key_list;
}

int hsm_key_list_object_store(hsm_key_list_t* hsm_key_list) {
    if (!hsm_key_list) {
        return DB_ERROR_UNKNOWN;
    }

    hsm_key_list->object_store = 1;

    return DB_OK;
}

void hsm_key_list_free(hsm_key_list_t* hsm_key_list) {
    size_t i;

    if (hsm_key_list) {
        if (hsm_key_list->dbo) {
            db_object_free(hsm_key_list->dbo);
        }
        if (hsm_key_list->result_list) {
            db_result_list_free(hsm_key_list->result_list);
        }
        if (hsm_key_list->hsm_key) {
            hsm_key_free(hsm_key_list->hsm_key);
        }
        for (i = 0; i < hsm_key_list->object_list_size; i++) {
            if (hsm_key_list->object_list[i]) {
                hsm_key_free(hsm_key_list->object_list[i]);
            }
        }
        if (hsm_key_list->object_list) {
            free(hsm_key_list->object_list);
        }
        if (hsm_key_list->policy_id_list) {
            policy_list_free(hsm_key_list->policy_id_list);
        }
        free(hsm_key_list);
    }
}

int hsm_key_list_copy(hsm_key_list_t* hsm_key_list, const hsm_key_list_t* from_hsm_key_list) {
    size_t i;

    if (!hsm_key_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!from_hsm_key_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (from_hsm_key_list->object_list && !from_hsm_key_list->object_list_size) {
        return DB_ERROR_UNKNOWN;
    }

    if (hsm_key_list->result_list) {
        db_result_list_free(hsm_key_list->result_list);
        hsm_key_list->result_list = NULL;
    }
    if (from_hsm_key_list->result_list
        && !(hsm_key_list->result_list = db_result_list_new_copy(from_hsm_key_list->result_list)))
    {
        return DB_ERROR_UNKNOWN;
    }

    hsm_key_list->object_store = from_hsm_key_list->object_store;
    for (i = 0; i < hsm_key_list->object_list_size; i++) {
        if (hsm_key_list->object_list[i]) {
            hsm_key_free(hsm_key_list->object_list[i]);
        }
    }
    hsm_key_list->object_list_size = 0;
    if (hsm_key_list->object_list) {
        free(hsm_key_list->object_list);
        hsm_key_list->object_list = NULL;
    }
    if (from_hsm_key_list->object_list) {
        if (!(hsm_key_list->object_list = (hsm_key_t**)calloc(from_hsm_key_list->object_list_size, sizeof(hsm_key_t*)))) {
            return DB_ERROR_UNKNOWN;
        }
        hsm_key_list->object_list_size = from_hsm_key_list->object_list_size;
        for (i = 0; i < from_hsm_key_list->object_list_size; i++) {
            if (!from_hsm_key_list->object_list[i]) {
                continue;
            }
            if (!(hsm_key_list->object_list[i] = hsm_key_new_copy(from_hsm_key_list->object_list[i]))) {
                return DB_ERROR_UNKNOWN;
            }
        }
    }
    hsm_key_list->object_list_position = 0;;
    hsm_key_list->object_list_first = 1;
    hsm_key_list->associated_fetch = from_hsm_key_list->associated_fetch;

    if (from_hsm_key_list->policy_id_list
        && !(hsm_key_list->policy_id_list = policy_list_new_copy(from_hsm_key_list->policy_id_list)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

static int hsm_key_list_get_associated(hsm_key_list_t* hsm_key_list) {
    const db_clause_t* clause_walk;
    const policy_t* policy_policy_id;
    int cmp;
    size_t i;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    const hsm_key_t* hsm_key;

    if (!hsm_key_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_list->associated_fetch) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_list->result_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (hsm_key_list->object_list) {
        return DB_ERROR_UNKNOWN;
    }

    if (hsm_key_list->policy_id_list) {
        policy_list_free(hsm_key_list->policy_id_list);
        hsm_key_list->policy_id_list = NULL;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    hsm_key = hsm_key_list_begin(hsm_key_list);
    while (hsm_key) {
        cmp = 1;
        clause_walk = db_clause_list_begin(clause_list);
        while (clause_walk) {
            if (db_value_cmp(db_clause_value(clause_walk), hsm_key_policy_id(hsm_key), &cmp)) {
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }
            if (!cmp) {
                break;
            }
            clause_walk = db_clause_next(clause_walk);
        }
        if (cmp) {
            if (!(clause = db_clause_new())
                || db_clause_set_field(clause, "id")
                || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
                || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_OR)
                || db_value_copy(db_clause_get_value(clause), hsm_key_policy_id(hsm_key))
                || db_clause_list_add(clause_list, clause))
            {
                db_clause_free(clause);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }
        }

        hsm_key = hsm_key_list_next(hsm_key_list);
    }

    if (!(hsm_key_list->policy_id_list = policy_list_new(db_object_connection(hsm_key_list->dbo)))
        || policy_list_object_store(hsm_key_list->policy_id_list)
        || policy_list_get_by_clauses(hsm_key_list->policy_id_list, clause_list))
    {
        if (hsm_key_list->policy_id_list) {
            policy_list_free(hsm_key_list->policy_id_list);
            hsm_key_list->policy_id_list = NULL;
        }
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    db_clause_list_free(clause_list);

    for (i = 0; i < hsm_key_list->object_list_size; i++) {
        if (!(hsm_key_list->object_list[i])) {
            return DB_ERROR_UNKNOWN;
        }

        policy_policy_id = policy_list_begin(hsm_key_list->policy_id_list);
        while (policy_policy_id) {
            if (db_value_cmp(hsm_key_policy_id(hsm_key_list->object_list[i]), policy_id(policy_policy_id), &cmp)) {
                return DB_ERROR_UNKNOWN;
            }
            if (!cmp) {
                hsm_key_list->object_list[i]->associated_policy_id = policy_policy_id;
            }

            policy_policy_id = policy_list_next(hsm_key_list->policy_id_list);
        }
    }

    hsm_key_list->object_list_first = 1;
    return DB_OK;
}

int hsm_key_list_get_by_clauses(hsm_key_list_t* hsm_key_list, const db_clause_list_t* clause_list) {
    size_t i;

    if (!hsm_key_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!clause_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (hsm_key_list->result_list) {
        db_result_list_free(hsm_key_list->result_list);
    }
    if (hsm_key_list->object_list_size) {
        for (i = 0; i < hsm_key_list->object_list_size; i++) {
            if (hsm_key_list->object_list[i]) {
                hsm_key_free(hsm_key_list->object_list[i]);
            }
        }
        hsm_key_list->object_list_size = 0;
        hsm_key_list->object_list_first = 0;
    }
    if (hsm_key_list->object_list) {
        free(hsm_key_list->object_list);
        hsm_key_list->object_list = NULL;
    }
    if (!(hsm_key_list->result_list = db_object_read(hsm_key_list->dbo, NULL, clause_list))
        || db_result_list_fetch_all(hsm_key_list->result_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    if (hsm_key_list->associated_fetch
        && hsm_key_list_get_associated(hsm_key_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

hsm_key_list_t* hsm_key_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list) {
    hsm_key_list_t* hsm_key_list;

    if (!connection) {
        return NULL;
    }
    if (!clause_list) {
        return NULL;
    }

    if (!(hsm_key_list = hsm_key_list_new(connection))
        || hsm_key_list_get_by_clauses(hsm_key_list, clause_list))
    {
        hsm_key_list_free(hsm_key_list);
        return NULL;
    }

    return hsm_key_list;
}

int hsm_key_list_get_by_policy_id(hsm_key_list_t* hsm_key_list, const db_value_t* policy_id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    size_t i;

    if (!hsm_key_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_id) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(policy_id)) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "policyId")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), policy_id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    if (hsm_key_list->result_list) {
        db_result_list_free(hsm_key_list->result_list);
    }
    if (hsm_key_list->object_list_size) {
        for (i = 0; i < hsm_key_list->object_list_size; i++) {
            if (hsm_key_list->object_list[i]) {
                hsm_key_free(hsm_key_list->object_list[i]);
            }
        }
        hsm_key_list->object_list_size = 0;
        hsm_key_list->object_list_first = 0;
    }
    if (hsm_key_list->object_list) {
        free(hsm_key_list->object_list);
        hsm_key_list->object_list = NULL;
    }
    if (!(hsm_key_list->result_list = db_object_read(hsm_key_list->dbo, NULL, clause_list))
        || db_result_list_fetch_all(hsm_key_list->result_list))
    {
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    db_clause_list_free(clause_list);
    if (hsm_key_list->associated_fetch
        && hsm_key_list_get_associated(hsm_key_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

hsm_key_list_t* hsm_key_list_new_get_by_policy_id(const db_connection_t* connection, const db_value_t* policy_id) {
    hsm_key_list_t* hsm_key_list;

    if (!connection) {
        return NULL;
    }
    if (!policy_id) {
        return NULL;
    }
    if (db_value_not_empty(policy_id)) {
        return NULL;
    }

    if (!(hsm_key_list = hsm_key_list_new(connection))
        || hsm_key_list_get_by_policy_id(hsm_key_list, policy_id))
    {
        hsm_key_list_free(hsm_key_list);
        return NULL;
    }

    return hsm_key_list;
}

const hsm_key_t* hsm_key_list_begin(hsm_key_list_t* hsm_key_list) {
    const db_result_t* result;

    if (!hsm_key_list) {
        return NULL;
    }

    if (hsm_key_list->object_store) {
        if (!hsm_key_list->object_list) {
            if (!hsm_key_list->result_list) {
                return NULL;
            }
            if (!db_result_list_size(hsm_key_list->result_list)) {
                return NULL;
            }
            if (!(hsm_key_list->object_list = (hsm_key_t**)calloc(db_result_list_size(hsm_key_list->result_list), sizeof(hsm_key_t*)))) {
                return NULL;
            }
            hsm_key_list->object_list_size = db_result_list_size(hsm_key_list->result_list);
        }
        if (!(hsm_key_list->object_list[0])) {
            if (!hsm_key_list->result_list) {
                return NULL;
            }
            if (!(result = db_result_list_begin(hsm_key_list->result_list))) {
                return NULL;
            }
            if (!(hsm_key_list->object_list[0] = hsm_key_new(db_object_connection(hsm_key_list->dbo)))) {
                return NULL;
            }
            if (hsm_key_from_result(hsm_key_list->object_list[0], result)) {
                return NULL;
            }
        }
        hsm_key_list->object_list_position = 0;
        return hsm_key_list->object_list[0];
    }

    if (!hsm_key_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(hsm_key_list->result_list))) {
        return NULL;
    }
    if (!hsm_key_list->hsm_key) {
        if (!(hsm_key_list->hsm_key = hsm_key_new(db_object_connection(hsm_key_list->dbo)))) {
            return NULL;
        }
    }
    if (hsm_key_from_result(hsm_key_list->hsm_key, result)) {
        return NULL;
    }
    return hsm_key_list->hsm_key;
}

hsm_key_t* hsm_key_list_get_begin(hsm_key_list_t* hsm_key_list) {
    const db_result_t* result;
    hsm_key_t* hsm_key;

    if (!hsm_key_list) {
        return NULL;
    }

    if (hsm_key_list->object_store) {
        if (!(hsm_key = hsm_key_new(db_object_connection(hsm_key_list->dbo)))) {
            return NULL;
        }
        if (hsm_key_copy(hsm_key, hsm_key_list_begin(hsm_key_list))) {
            hsm_key_free(hsm_key);
            return NULL;
        }
        return hsm_key;
    }

    if (!hsm_key_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(hsm_key_list->result_list))) {
        return NULL;
    }
    if (!(hsm_key = hsm_key_new(db_object_connection(hsm_key_list->dbo)))) {
        return NULL;
    }
    if (hsm_key_from_result(hsm_key, result)) {
        hsm_key_free(hsm_key);
        return NULL;
    }
    return hsm_key;
}

const hsm_key_t* hsm_key_list_next(hsm_key_list_t* hsm_key_list) {
    const db_result_t* result;

    if (!hsm_key_list) {
        return NULL;
    }

    if (hsm_key_list->object_store) {
        if (!hsm_key_list->object_list) {
            if (!hsm_key_list->result_list) {
                return NULL;
            }
            if (!db_result_list_size(hsm_key_list->result_list)) {
                return NULL;
            }
            if (!(hsm_key_list->object_list = (hsm_key_t**)calloc(db_result_list_size(hsm_key_list->result_list), sizeof(hsm_key_t*)))) {
                return NULL;
            }
            hsm_key_list->object_list_size = db_result_list_size(hsm_key_list->result_list);
            hsm_key_list->object_list_position = 0;
        }
        else if (hsm_key_list->object_list_first) {
            hsm_key_list->object_list_first = 0;
            hsm_key_list->object_list_position = 0;
        }
        else {
            hsm_key_list->object_list_position++;
        }
        if (hsm_key_list->object_list_position >= hsm_key_list->object_list_size) {
            return NULL;
        }
        if (!(hsm_key_list->object_list[hsm_key_list->object_list_position])) {
            if (!hsm_key_list->result_list) {
                return NULL;
            }
            if (!(result = db_result_list_next(hsm_key_list->result_list))) {
                return NULL;
            }
            if (!(hsm_key_list->object_list[hsm_key_list->object_list_position] = hsm_key_new(db_object_connection(hsm_key_list->dbo)))) {
                return NULL;
            }
            if (hsm_key_from_result(hsm_key_list->object_list[hsm_key_list->object_list_position], result)) {
                return NULL;
            }
        }
        return hsm_key_list->object_list[hsm_key_list->object_list_position];
    }

    if (!hsm_key_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(hsm_key_list->result_list))) {
        return NULL;
    }
    if (!hsm_key_list->hsm_key) {
        if (!(hsm_key_list->hsm_key = hsm_key_new(db_object_connection(hsm_key_list->dbo)))) {
            return NULL;
        }
    }
    if (hsm_key_from_result(hsm_key_list->hsm_key, result)) {
        return NULL;
    }
    return hsm_key_list->hsm_key;
}

hsm_key_t* hsm_key_list_get_next(hsm_key_list_t* hsm_key_list) {
    const db_result_t* result;
    hsm_key_t* hsm_key;

    if (!hsm_key_list) {
        return NULL;
    }

    if (hsm_key_list->object_store) {
        if (!(hsm_key = hsm_key_new(db_object_connection(hsm_key_list->dbo)))) {
            return NULL;
        }
        if (hsm_key_copy(hsm_key, hsm_key_list_next(hsm_key_list))) {
            hsm_key_free(hsm_key);
            return NULL;
        }
        return hsm_key;
    }

    if (!hsm_key_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(hsm_key_list->result_list))) {
        return NULL;
    }
    if (!(hsm_key = hsm_key_new(db_object_connection(hsm_key_list->dbo)))) {
        return NULL;
    }
    if (hsm_key_from_result(hsm_key, result)) {
        hsm_key_free(hsm_key);
        return NULL;
    }
    return hsm_key;
}
