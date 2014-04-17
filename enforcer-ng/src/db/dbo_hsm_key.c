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

#include "dbo_hsm_key.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

static const db_enum_t __enum_set_role[] = {
    { "KSK", (dbo_hsm_key_role_t)DBO_HSM_KEY_ROLE_KSK },
    { "ZSK", (dbo_hsm_key_role_t)DBO_HSM_KEY_ROLE_ZSK },
    { "CSK", (dbo_hsm_key_role_t)DBO_HSM_KEY_ROLE_CSK },
    { NULL, 0 }
};

/**
 * Create a new dbo hsm key object.
 * \param[in] connection a db_connection_t pointer.
 * \return a dbo_hsm_key_t pointer or NULL on error.
 */
static db_object_t* __dbo_hsm_key_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "HsmKey")
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
        || db_object_field_set_name(object_field, "candidate_for_sharing")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
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
        || db_object_field_set_name(object_field, "policy")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
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
        || db_object_field_set_enum_set(object_field, __enum_set_role)
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
        || db_object_field_set_name(object_field, "isrevoked")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "key_type")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
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
        || db_object_field_set_name(object_field, "backmeup")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "backedup")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "requirebackup")
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

/* DBO HSM KEY */

static mm_alloc_t __dbo_hsm_key_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(dbo_hsm_key_t));

dbo_hsm_key_t* dbo_hsm_key_new(const db_connection_t* connection) {
    dbo_hsm_key_t* dbo_hsm_key =
        (dbo_hsm_key_t*)mm_alloc_new0(&__dbo_hsm_key_alloc);

    if (dbo_hsm_key) {
        if (!(dbo_hsm_key->dbo = __dbo_hsm_key_new_object(connection))) {
            mm_alloc_delete(&__dbo_hsm_key_alloc, dbo_hsm_key);
            return NULL;
        }
        dbo_hsm_key->bits = 2048;
        dbo_hsm_key->policy = strdup("default");
        dbo_hsm_key->algorithm = 1;
        dbo_hsm_key->role = DBO_HSM_KEY_ROLE_ZSK;
    }

    return dbo_hsm_key;
}

void dbo_hsm_key_free(dbo_hsm_key_t* dbo_hsm_key) {
    if (dbo_hsm_key) {
        if (dbo_hsm_key->dbo) {
            db_object_free(dbo_hsm_key->dbo);
        }
        if (dbo_hsm_key->locator) {
            free(dbo_hsm_key->locator);
        }
        if (dbo_hsm_key->policy) {
            free(dbo_hsm_key->policy);
        }
        if (dbo_hsm_key->key_type) {
            free(dbo_hsm_key->key_type);
        }
        if (dbo_hsm_key->repository) {
            free(dbo_hsm_key->repository);
        }
        mm_alloc_delete(&__dbo_hsm_key_alloc, dbo_hsm_key);
    }
}

void dbo_hsm_key_reset(dbo_hsm_key_t* dbo_hsm_key) {
    if (dbo_hsm_key) {
        dbo_hsm_key->id = 0;
        if (dbo_hsm_key->locator) {
            free(dbo_hsm_key->locator);
        }
        dbo_hsm_key->locator = NULL;
        dbo_hsm_key->candidate_for_sharing = 0;
        dbo_hsm_key->bits = 2048;
        if (dbo_hsm_key->policy) {
            free(dbo_hsm_key->policy);
        }
        dbo_hsm_key->policy = strdup("default");
        dbo_hsm_key->algorithm = 1;
        dbo_hsm_key->role = DBO_HSM_KEY_ROLE_ZSK;
        dbo_hsm_key->inception = 0;
        dbo_hsm_key->isrevoked = 0;
        if (dbo_hsm_key->key_type) {
            free(dbo_hsm_key->key_type);
        }
        dbo_hsm_key->key_type = NULL;
        if (dbo_hsm_key->repository) {
            free(dbo_hsm_key->repository);
        }
        dbo_hsm_key->repository = NULL;
        dbo_hsm_key->backmeup = 0;
        dbo_hsm_key->backedup = 0;
        dbo_hsm_key->requirebackup = 0;
    }
}

int dbo_hsm_key_copy(dbo_hsm_key_t* dbo_hsm_key, const dbo_hsm_key_t* dbo_hsm_key_copy) {
    char* locator_text = NULL;
    char* policy_text = NULL;
    char* key_type_text = NULL;
    char* repository_text = NULL;
    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_hsm_key_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (dbo_hsm_key->locator) {
        if (!(locator_text = strdup(dbo_hsm_key->locator))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    if (dbo_hsm_key->policy) {
        if (!(policy_text = strdup(dbo_hsm_key->policy))) {
            if (locator_text) {
                free(locator_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (dbo_hsm_key->key_type) {
        if (!(key_type_text = strdup(dbo_hsm_key->key_type))) {
            if (locator_text) {
                free(locator_text);
            }
            if (policy_text) {
                free(policy_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (dbo_hsm_key->repository) {
        if (!(repository_text = strdup(dbo_hsm_key->repository))) {
            if (locator_text) {
                free(locator_text);
            }
            if (policy_text) {
                free(policy_text);
            }
            if (key_type_text) {
                free(key_type_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    dbo_hsm_key->id = dbo_hsm_key_copy->id;
    if (dbo_hsm_key->locator) {
        free(dbo_hsm_key->locator);
    }
    dbo_hsm_key->locator = locator_text;
    dbo_hsm_key->candidate_for_sharing = dbo_hsm_key_copy->candidate_for_sharing;
    dbo_hsm_key->bits = dbo_hsm_key_copy->bits;
    if (dbo_hsm_key->policy) {
        free(dbo_hsm_key->policy);
    }
    dbo_hsm_key->policy = policy_text;
    dbo_hsm_key->algorithm = dbo_hsm_key_copy->algorithm;
    dbo_hsm_key->role = dbo_hsm_key_copy->role;
    dbo_hsm_key->inception = dbo_hsm_key_copy->inception;
    dbo_hsm_key->isrevoked = dbo_hsm_key_copy->isrevoked;
    if (dbo_hsm_key->key_type) {
        free(dbo_hsm_key->key_type);
    }
    dbo_hsm_key->key_type = key_type_text;
    if (dbo_hsm_key->repository) {
        free(dbo_hsm_key->repository);
    }
    dbo_hsm_key->repository = repository_text;
    dbo_hsm_key->backmeup = dbo_hsm_key_copy->backmeup;
    dbo_hsm_key->backedup = dbo_hsm_key_copy->backedup;
    dbo_hsm_key->requirebackup = dbo_hsm_key_copy->requirebackup;
    return DB_OK;
}

int dbo_hsm_key_from_result(dbo_hsm_key_t* dbo_hsm_key, const db_result_t* result) {
    const db_value_set_t* value_set;
    int role;

    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    if (dbo_hsm_key->locator) {
        free(dbo_hsm_key->locator);
    }
    dbo_hsm_key->locator = NULL;
    if (dbo_hsm_key->policy) {
        free(dbo_hsm_key->policy);
    }
    dbo_hsm_key->policy = NULL;
    if (dbo_hsm_key->key_type) {
        free(dbo_hsm_key->key_type);
    }
    dbo_hsm_key->key_type = NULL;
    if (dbo_hsm_key->repository) {
        free(dbo_hsm_key->repository);
    }
    dbo_hsm_key->repository = NULL;
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 14
        || db_value_to_int32(db_value_set_at(value_set, 0), &(dbo_hsm_key->id))
        || db_value_to_text(db_value_set_at(value_set, 1), &(dbo_hsm_key->locator))
        || db_value_to_uint32(db_value_set_at(value_set, 2), &(dbo_hsm_key->candidate_for_sharing))
        || db_value_to_uint32(db_value_set_at(value_set, 3), &(dbo_hsm_key->bits))
        || db_value_to_text(db_value_set_at(value_set, 4), &(dbo_hsm_key->policy))
        || db_value_to_uint32(db_value_set_at(value_set, 5), &(dbo_hsm_key->algorithm))
        || db_value_to_enum_value(db_value_set_at(value_set, 6), &role, __enum_set_role)
        || db_value_to_uint32(db_value_set_at(value_set, 7), &(dbo_hsm_key->inception))
        || db_value_to_uint32(db_value_set_at(value_set, 8), &(dbo_hsm_key->isrevoked))
        || db_value_to_text(db_value_set_at(value_set, 9), &(dbo_hsm_key->key_type))
        || db_value_to_text(db_value_set_at(value_set, 10), &(dbo_hsm_key->repository))
        || db_value_to_uint32(db_value_set_at(value_set, 11), &(dbo_hsm_key->backmeup))
        || db_value_to_uint32(db_value_set_at(value_set, 12), &(dbo_hsm_key->backedup))
        || db_value_to_uint32(db_value_set_at(value_set, 13), &(dbo_hsm_key->requirebackup)))
    {
        return DB_ERROR_UNKNOWN;
    }

    if (role == (dbo_hsm_key_role_t)DBO_HSM_KEY_ROLE_KSK) {
        dbo_hsm_key->role = DBO_HSM_KEY_ROLE_KSK;
    }
    if (role == (dbo_hsm_key_role_t)DBO_HSM_KEY_ROLE_ZSK) {
        dbo_hsm_key->role = DBO_HSM_KEY_ROLE_ZSK;
    }
    if (role == (dbo_hsm_key_role_t)DBO_HSM_KEY_ROLE_CSK) {
        dbo_hsm_key->role = DBO_HSM_KEY_ROLE_CSK;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int dbo_hsm_key_id(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return 0;
    }

    return dbo_hsm_key->id;
}

const char* dbo_hsm_key_locator(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return NULL;
    }

    return dbo_hsm_key->locator;
}

unsigned int dbo_hsm_key_candidate_for_sharing(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return 0;
    }

    return dbo_hsm_key->candidate_for_sharing;
}

unsigned int dbo_hsm_key_bits(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return 0;
    }

    return dbo_hsm_key->bits;
}

const char* dbo_hsm_key_policy(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return NULL;
    }

    return dbo_hsm_key->policy;
}

unsigned int dbo_hsm_key_algorithm(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return 0;
    }

    return dbo_hsm_key->algorithm;
}

dbo_hsm_key_role_t dbo_hsm_key_role(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return DBO_HSM_KEY_ROLE_INVALID;
    }

    return dbo_hsm_key->role;
}

const char* dbo_hsm_key_role_text(const dbo_hsm_key_t* dbo_hsm_key) {
    const db_enum_t* enum_set = __enum_set_role;

    if (!dbo_hsm_key) {
        return NULL;
    }

    while (enum_set->text) {
        if (enum_set->value == dbo_hsm_key->role) {
            return enum_set->text;
        }
        enum_set++;
    }
    return NULL;
}

unsigned int dbo_hsm_key_inception(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return 0;
    }

    return dbo_hsm_key->inception;
}

unsigned int dbo_hsm_key_isrevoked(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return 0;
    }

    return dbo_hsm_key->isrevoked;
}

const char* dbo_hsm_key_key_type(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return NULL;
    }

    return dbo_hsm_key->key_type;
}

const char* dbo_hsm_key_repository(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return NULL;
    }

    return dbo_hsm_key->repository;
}

unsigned int dbo_hsm_key_backmeup(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return 0;
    }

    return dbo_hsm_key->backmeup;
}

unsigned int dbo_hsm_key_backedup(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return 0;
    }

    return dbo_hsm_key->backedup;
}

unsigned int dbo_hsm_key_requirebackup(const dbo_hsm_key_t* dbo_hsm_key) {
    if (!dbo_hsm_key) {
        return 0;
    }

    return dbo_hsm_key->requirebackup;
}

int dbo_hsm_key_set_locator(dbo_hsm_key_t* dbo_hsm_key, const char* locator_text) {
    char* new_locator;

    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!locator_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_locator = strdup(locator_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (dbo_hsm_key->locator) {
        free(dbo_hsm_key->locator);
    }
    dbo_hsm_key->locator = new_locator;

    return DB_OK;
}

int dbo_hsm_key_set_candidate_for_sharing(dbo_hsm_key_t* dbo_hsm_key, unsigned int candidate_for_sharing) {
    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_hsm_key->candidate_for_sharing = candidate_for_sharing;

    return DB_OK;
}

int dbo_hsm_key_set_bits(dbo_hsm_key_t* dbo_hsm_key, unsigned int bits) {
    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_hsm_key->bits = bits;

    return DB_OK;
}

int dbo_hsm_key_set_policy(dbo_hsm_key_t* dbo_hsm_key, const char* policy_text) {
    char* new_policy;

    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_policy = strdup(policy_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (dbo_hsm_key->policy) {
        free(dbo_hsm_key->policy);
    }
    dbo_hsm_key->policy = new_policy;

    return DB_OK;
}

int dbo_hsm_key_set_algorithm(dbo_hsm_key_t* dbo_hsm_key, unsigned int algorithm) {
    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_hsm_key->algorithm = algorithm;

    return DB_OK;
}

int dbo_hsm_key_set_role(dbo_hsm_key_t* dbo_hsm_key, dbo_hsm_key_role_t role) {
    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_hsm_key->role = role;

    return DB_OK;
}

int dbo_hsm_key_set_role_text(dbo_hsm_key_t* dbo_hsm_key, const char* role) {
    const db_enum_t* enum_set = __enum_set_role;

    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    while (enum_set->text) {
        if (!strcmp(enum_set->text, role)) {
            dbo_hsm_key->role = enum_set->value;
            return DB_OK;
        }
        enum_set++;
    }
    return DB_ERROR_UNKNOWN;
}

int dbo_hsm_key_set_inception(dbo_hsm_key_t* dbo_hsm_key, unsigned int inception) {
    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_hsm_key->inception = inception;

    return DB_OK;
}

int dbo_hsm_key_set_isrevoked(dbo_hsm_key_t* dbo_hsm_key, unsigned int isrevoked) {
    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_hsm_key->isrevoked = isrevoked;

    return DB_OK;
}

int dbo_hsm_key_set_key_type(dbo_hsm_key_t* dbo_hsm_key, const char* key_type_text) {
    char* new_key_type;

    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_type_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_key_type = strdup(key_type_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (dbo_hsm_key->key_type) {
        free(dbo_hsm_key->key_type);
    }
    dbo_hsm_key->key_type = new_key_type;

    return DB_OK;
}

int dbo_hsm_key_set_repository(dbo_hsm_key_t* dbo_hsm_key, const char* repository_text) {
    char* new_repository;

    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!repository_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_repository = strdup(repository_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (dbo_hsm_key->repository) {
        free(dbo_hsm_key->repository);
    }
    dbo_hsm_key->repository = new_repository;

    return DB_OK;
}

int dbo_hsm_key_set_backmeup(dbo_hsm_key_t* dbo_hsm_key, unsigned int backmeup) {
    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_hsm_key->backmeup = backmeup;

    return DB_OK;
}

int dbo_hsm_key_set_backedup(dbo_hsm_key_t* dbo_hsm_key, unsigned int backedup) {
    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_hsm_key->backedup = backedup;

    return DB_OK;
}

int dbo_hsm_key_set_requirebackup(dbo_hsm_key_t* dbo_hsm_key, unsigned int requirebackup) {
    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_hsm_key->requirebackup = requirebackup;

    return DB_OK;
}

int dbo_hsm_key_create(dbo_hsm_key_t* dbo_hsm_key) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_hsm_key->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (dbo_hsm_key->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
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
        || db_object_field_set_name(object_field, "candidate_for_sharing")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
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
        || db_object_field_set_name(object_field, "policy")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
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
        || db_object_field_set_enum_set(object_field, __enum_set_role)
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
        || db_object_field_set_name(object_field, "isrevoked")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "key_type")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
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
        || db_object_field_set_name(object_field, "backmeup")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "backedup")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "requirebackup")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(13))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_text(db_value_set_get(value_set, 0), dbo_hsm_key->locator)
        || db_value_from_uint32(db_value_set_get(value_set, 1), dbo_hsm_key->candidate_for_sharing)
        || db_value_from_uint32(db_value_set_get(value_set, 2), dbo_hsm_key->bits)
        || db_value_from_text(db_value_set_get(value_set, 3), dbo_hsm_key->policy)
        || db_value_from_uint32(db_value_set_get(value_set, 4), dbo_hsm_key->algorithm)
        || db_value_from_enum_value(db_value_set_get(value_set, 5), dbo_hsm_key->role, __enum_set_role)
        || db_value_from_uint32(db_value_set_get(value_set, 6), dbo_hsm_key->inception)
        || db_value_from_uint32(db_value_set_get(value_set, 7), dbo_hsm_key->isrevoked)
        || db_value_from_text(db_value_set_get(value_set, 8), dbo_hsm_key->key_type)
        || db_value_from_text(db_value_set_get(value_set, 9), dbo_hsm_key->repository)
        || db_value_from_uint32(db_value_set_get(value_set, 10), dbo_hsm_key->backmeup)
        || db_value_from_uint32(db_value_set_get(value_set, 11), dbo_hsm_key->backedup)
        || db_value_from_uint32(db_value_set_get(value_set, 12), dbo_hsm_key->requirebackup))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(dbo_hsm_key->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int dbo_hsm_key_get_by_id(dbo_hsm_key_t* dbo_hsm_key, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_hsm_key->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    result_list = db_object_read(dbo_hsm_key->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            dbo_hsm_key_from_result(dbo_hsm_key, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int dbo_hsm_key_update(dbo_hsm_key_t* dbo_hsm_key) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_hsm_key->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_hsm_key->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
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
        || db_object_field_set_name(object_field, "candidate_for_sharing")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
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
        || db_object_field_set_name(object_field, "policy")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
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
        || db_object_field_set_enum_set(object_field, __enum_set_role)
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
        || db_object_field_set_name(object_field, "isrevoked")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "key_type")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
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
        || db_object_field_set_name(object_field, "backmeup")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "backedup")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "requirebackup")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(13))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_text(db_value_set_get(value_set, 0), dbo_hsm_key->locator)
        || db_value_from_uint32(db_value_set_get(value_set, 1), dbo_hsm_key->candidate_for_sharing)
        || db_value_from_uint32(db_value_set_get(value_set, 2), dbo_hsm_key->bits)
        || db_value_from_text(db_value_set_get(value_set, 3), dbo_hsm_key->policy)
        || db_value_from_uint32(db_value_set_get(value_set, 4), dbo_hsm_key->algorithm)
        || db_value_from_enum_value(db_value_set_get(value_set, 5), dbo_hsm_key->role, __enum_set_role)
        || db_value_from_uint32(db_value_set_get(value_set, 6), dbo_hsm_key->inception)
        || db_value_from_uint32(db_value_set_get(value_set, 7), dbo_hsm_key->isrevoked)
        || db_value_from_text(db_value_set_get(value_set, 8), dbo_hsm_key->key_type)
        || db_value_from_text(db_value_set_get(value_set, 9), dbo_hsm_key->repository)
        || db_value_from_uint32(db_value_set_get(value_set, 10), dbo_hsm_key->backmeup)
        || db_value_from_uint32(db_value_set_get(value_set, 11), dbo_hsm_key->backedup)
        || db_value_from_uint32(db_value_set_get(value_set, 12), dbo_hsm_key->requirebackup))
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
        || db_value_from_int32(db_clause_get_value(clause), dbo_hsm_key->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(dbo_hsm_key->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int dbo_hsm_key_delete(dbo_hsm_key_t* dbo_hsm_key) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!dbo_hsm_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_hsm_key->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_hsm_key->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), dbo_hsm_key->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(dbo_hsm_key->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* DBO HSM KEY LIST */

static mm_alloc_t __dbo_hsm_key_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(dbo_hsm_key_list_t));

dbo_hsm_key_list_t* dbo_hsm_key_list_new(const db_connection_t* connection) {
    dbo_hsm_key_list_t* dbo_hsm_key_list =
        (dbo_hsm_key_list_t*)mm_alloc_new0(&__dbo_hsm_key_list_alloc);

    if (dbo_hsm_key_list) {
        if (!(dbo_hsm_key_list->dbo = __dbo_hsm_key_new_object(connection))) {
            mm_alloc_delete(&__dbo_hsm_key_list_alloc, dbo_hsm_key_list);
            return NULL;
        }
    }

    return dbo_hsm_key_list;
}

void dbo_hsm_key_list_free(dbo_hsm_key_list_t* dbo_hsm_key_list) {
    if (dbo_hsm_key_list) {
        if (dbo_hsm_key_list->dbo) {
            db_object_free(dbo_hsm_key_list->dbo);
        }
        if (dbo_hsm_key_list->result_list) {
            db_result_list_free(dbo_hsm_key_list->result_list);
        }
        if (dbo_hsm_key_list->dbo_hsm_key) {
            dbo_hsm_key_free(dbo_hsm_key_list->dbo_hsm_key);
        }
        mm_alloc_delete(&__dbo_hsm_key_list_alloc, dbo_hsm_key_list);
    }
}

int dbo_hsm_key_list_get(dbo_hsm_key_list_t* dbo_hsm_key_list) {
    if (!dbo_hsm_key_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_hsm_key_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (dbo_hsm_key_list->result_list) {
        db_result_list_free(dbo_hsm_key_list->result_list);
    }
    if (!(dbo_hsm_key_list->result_list = db_object_read(dbo_hsm_key_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const dbo_hsm_key_t* dbo_hsm_key_list_begin(dbo_hsm_key_list_t* dbo_hsm_key_list) {
    const db_result_t* result;

    if (!dbo_hsm_key_list) {
        return NULL;
    }
    if (!dbo_hsm_key_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(dbo_hsm_key_list->result_list))) {
        return NULL;
    }
    if (!dbo_hsm_key_list->dbo_hsm_key) {
        if (!(dbo_hsm_key_list->dbo_hsm_key = dbo_hsm_key_new(db_object_connection(dbo_hsm_key_list->dbo)))) {
            return NULL;
        }
    }
    if (dbo_hsm_key_from_result(dbo_hsm_key_list->dbo_hsm_key, result)) {
        return NULL;
    }
    return dbo_hsm_key_list->dbo_hsm_key;
}

const dbo_hsm_key_t* dbo_hsm_key_list_next(dbo_hsm_key_list_t* dbo_hsm_key_list) {
    const db_result_t* result;

    if (!dbo_hsm_key_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(dbo_hsm_key_list->result_list))) {
        return NULL;
    }
    if (!dbo_hsm_key_list->dbo_hsm_key) {
        if (!(dbo_hsm_key_list->dbo_hsm_key = dbo_hsm_key_new(db_object_connection(dbo_hsm_key_list->dbo)))) {
            return NULL;
        }
    }
    if (dbo_hsm_key_from_result(dbo_hsm_key_list->dbo_hsm_key, result)) {
        return NULL;
    }
    return dbo_hsm_key_list->dbo_hsm_key;
}

