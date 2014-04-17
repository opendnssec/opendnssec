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

#include "ksk.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

static const db_enum_t __enum_set_rollover_type[] = {
    { "KskDoubleRRset", (ksk_rollover_type_t)KSK_ROLLOVER_TYPE_DOUBLE_RRSET },
    { "KskDoubleDS", (ksk_rollover_type_t)KSK_ROLLOVER_TYPE_DOUBLE_DS },
    { "KskDoubleSignature", (ksk_rollover_type_t)KSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE },
    { NULL, 0 }
};

/**
 * Create a new ksk object.
 * \param[in] connection a db_connection_t pointer.
 * \return a ksk_t pointer or NULL on error.
 */
static db_object_t* __ksk_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "Ksk")
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
        || db_object_field_set_name(object_field, "lifetime")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
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
        || db_object_field_set_name(object_field, "standby")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "manual_rollover")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rfc5011")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rollover_type")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_rollover_type)
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

/* KSK */

static mm_alloc_t __ksk_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(ksk_t));

ksk_t* ksk_new(const db_connection_t* connection) {
    ksk_t* ksk =
        (ksk_t*)mm_alloc_new0(&__ksk_alloc);

    if (ksk) {
        if (!(ksk->dbo = __ksk_new_object(connection))) {
            mm_alloc_delete(&__ksk_alloc, ksk);
            return NULL;
        }
        ksk->rollover_type = KSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE;
    }

    return ksk;
}

void ksk_free(ksk_t* ksk) {
    if (ksk) {
        if (ksk->dbo) {
            db_object_free(ksk->dbo);
        }
        if (ksk->repository) {
            free(ksk->repository);
        }
        mm_alloc_delete(&__ksk_alloc, ksk);
    }
}

void ksk_reset(ksk_t* ksk) {
    if (ksk) {
        ksk->id = 0;
        ksk->algorithm = 0;
        ksk->bits = 0;
        ksk->lifetime = 0;
        if (ksk->repository) {
            free(ksk->repository);
        }
        ksk->repository = NULL;
        ksk->standby = 0;
        ksk->manual_rollover = 0;
        ksk->rfc5011 = 0;
        ksk->rollover_type = KSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE;
    }
}

int ksk_copy(ksk_t* ksk, const ksk_t* ksk_copy) {
    char* repository_text = NULL;
    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!ksk_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (ksk->repository) {
        if (!(repository_text = strdup(ksk->repository))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    ksk->id = ksk_copy->id;
    ksk->algorithm = ksk_copy->algorithm;
    ksk->bits = ksk_copy->bits;
    ksk->lifetime = ksk_copy->lifetime;
    if (ksk->repository) {
        free(ksk->repository);
    }
    ksk->repository = repository_text;
    ksk->standby = ksk_copy->standby;
    ksk->manual_rollover = ksk_copy->manual_rollover;
    ksk->rfc5011 = ksk_copy->rfc5011;
    ksk->rollover_type = ksk_copy->rollover_type;
    return DB_OK;
}

int ksk_from_result(ksk_t* ksk, const db_result_t* result) {
    const db_value_set_t* value_set;
    int rollover_type;

    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    if (ksk->repository) {
        free(ksk->repository);
    }
    ksk->repository = NULL;
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 9
        || db_value_to_int32(db_value_set_at(value_set, 0), &(ksk->id))
        || db_value_to_uint32(db_value_set_at(value_set, 1), &(ksk->algorithm))
        || db_value_to_uint32(db_value_set_at(value_set, 2), &(ksk->bits))
        || db_value_to_int32(db_value_set_at(value_set, 3), &(ksk->lifetime))
        || db_value_to_text(db_value_set_at(value_set, 4), &(ksk->repository))
        || db_value_to_uint32(db_value_set_at(value_set, 5), &(ksk->standby))
        || db_value_to_uint32(db_value_set_at(value_set, 6), &(ksk->manual_rollover))
        || db_value_to_uint32(db_value_set_at(value_set, 7), &(ksk->rfc5011))
        || db_value_to_enum_value(db_value_set_at(value_set, 8), &rollover_type, __enum_set_rollover_type))
    {
        return DB_ERROR_UNKNOWN;
    }

    if (rollover_type == (ksk_rollover_type_t)KSK_ROLLOVER_TYPE_DOUBLE_RRSET) {
        ksk->rollover_type = KSK_ROLLOVER_TYPE_DOUBLE_RRSET;
    }
    if (rollover_type == (ksk_rollover_type_t)KSK_ROLLOVER_TYPE_DOUBLE_DS) {
        ksk->rollover_type = KSK_ROLLOVER_TYPE_DOUBLE_DS;
    }
    if (rollover_type == (ksk_rollover_type_t)KSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE) {
        ksk->rollover_type = KSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int ksk_id(const ksk_t* ksk) {
    if (!ksk) {
        return 0;
    }

    return ksk->id;
}

unsigned int ksk_algorithm(const ksk_t* ksk) {
    if (!ksk) {
        return 0;
    }

    return ksk->algorithm;
}

unsigned int ksk_bits(const ksk_t* ksk) {
    if (!ksk) {
        return 0;
    }

    return ksk->bits;
}

int ksk_lifetime(const ksk_t* ksk) {
    if (!ksk) {
        return 0;
    }

    return ksk->lifetime;
}

const char* ksk_repository(const ksk_t* ksk) {
    if (!ksk) {
        return NULL;
    }

    return ksk->repository;
}

unsigned int ksk_standby(const ksk_t* ksk) {
    if (!ksk) {
        return 0;
    }

    return ksk->standby;
}

unsigned int ksk_manual_rollover(const ksk_t* ksk) {
    if (!ksk) {
        return 0;
    }

    return ksk->manual_rollover;
}

unsigned int ksk_rfc5011(const ksk_t* ksk) {
    if (!ksk) {
        return 0;
    }

    return ksk->rfc5011;
}

ksk_rollover_type_t ksk_rollover_type(const ksk_t* ksk) {
    if (!ksk) {
        return KSK_ROLLOVER_TYPE_INVALID;
    }

    return ksk->rollover_type;
}

const char* ksk_rollover_type_text(const ksk_t* ksk) {
    const db_enum_t* enum_set = __enum_set_rollover_type;

    if (!ksk) {
        return NULL;
    }

    while (enum_set->text) {
        if (enum_set->value == ksk->rollover_type) {
            return enum_set->text;
        }
        enum_set++;
    }
    return NULL;
}

int ksk_set_algorithm(ksk_t* ksk, unsigned int algorithm) {
    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }

    ksk->algorithm = algorithm;

    return DB_OK;
}

int ksk_set_bits(ksk_t* ksk, unsigned int bits) {
    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }

    ksk->bits = bits;

    return DB_OK;
}

int ksk_set_lifetime(ksk_t* ksk, int lifetime) {
    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }

    ksk->lifetime = lifetime;

    return DB_OK;
}

int ksk_set_repository(ksk_t* ksk, const char* repository_text) {
    char* new_repository;

    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!repository_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_repository = strdup(repository_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (ksk->repository) {
        free(ksk->repository);
    }
    ksk->repository = new_repository;

    return DB_OK;
}

int ksk_set_standby(ksk_t* ksk, unsigned int standby) {
    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }

    ksk->standby = standby;

    return DB_OK;
}

int ksk_set_manual_rollover(ksk_t* ksk, unsigned int manual_rollover) {
    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }

    ksk->manual_rollover = manual_rollover;

    return DB_OK;
}

int ksk_set_rfc5011(ksk_t* ksk, unsigned int rfc5011) {
    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }

    ksk->rfc5011 = rfc5011;

    return DB_OK;
}

int ksk_set_rollover_type(ksk_t* ksk, ksk_rollover_type_t rollover_type) {
    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }

    ksk->rollover_type = rollover_type;

    return DB_OK;
}

int ksk_set_rollover_type_text(ksk_t* ksk, const char* rollover_type) {
    const db_enum_t* enum_set = __enum_set_rollover_type;

    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }

    while (enum_set->text) {
        if (!strcmp(enum_set->text, rollover_type)) {
            ksk->rollover_type = enum_set->value;
            return DB_OK;
        }
        enum_set++;
    }
    return DB_ERROR_UNKNOWN;
}

int ksk_create(ksk_t* ksk) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!ksk->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (ksk->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
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
        || db_object_field_set_name(object_field, "bits")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "lifetime")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
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
        || db_object_field_set_name(object_field, "standby")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "manual_rollover")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rfc5011")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rollover_type")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_rollover_type)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(8))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_uint32(db_value_set_get(value_set, 0), ksk->algorithm)
        || db_value_from_uint32(db_value_set_get(value_set, 1), ksk->bits)
        || db_value_from_int32(db_value_set_get(value_set, 2), ksk->lifetime)
        || db_value_from_text(db_value_set_get(value_set, 3), ksk->repository)
        || db_value_from_uint32(db_value_set_get(value_set, 4), ksk->standby)
        || db_value_from_uint32(db_value_set_get(value_set, 5), ksk->manual_rollover)
        || db_value_from_uint32(db_value_set_get(value_set, 6), ksk->rfc5011)
        || db_value_from_enum_value(db_value_set_get(value_set, 7), ksk->rollover_type, __enum_set_rollover_type))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(ksk->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int ksk_get_by_id(ksk_t* ksk, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!ksk->dbo) {
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

    result_list = db_object_read(ksk->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (db_result_list_next(result_list)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }

            ksk_from_result(ksk, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int ksk_update(ksk_t* ksk) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!ksk->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!ksk->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
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
        || db_object_field_set_name(object_field, "bits")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "lifetime")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
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
        || db_object_field_set_name(object_field, "standby")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "manual_rollover")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rfc5011")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rollover_type")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_rollover_type)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(8))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_uint32(db_value_set_get(value_set, 0), ksk->algorithm)
        || db_value_from_uint32(db_value_set_get(value_set, 1), ksk->bits)
        || db_value_from_int32(db_value_set_get(value_set, 2), ksk->lifetime)
        || db_value_from_text(db_value_set_get(value_set, 3), ksk->repository)
        || db_value_from_uint32(db_value_set_get(value_set, 4), ksk->standby)
        || db_value_from_uint32(db_value_set_get(value_set, 5), ksk->manual_rollover)
        || db_value_from_uint32(db_value_set_get(value_set, 6), ksk->rfc5011)
        || db_value_from_enum_value(db_value_set_get(value_set, 7), ksk->rollover_type, __enum_set_rollover_type))
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
        || db_value_from_int32(db_clause_get_value(clause), ksk->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(ksk->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int ksk_delete(ksk_t* ksk) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!ksk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!ksk->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!ksk->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), ksk->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(ksk->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* KSK LIST */

static mm_alloc_t __ksk_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(ksk_list_t));

ksk_list_t* ksk_list_new(const db_connection_t* connection) {
    ksk_list_t* ksk_list =
        (ksk_list_t*)mm_alloc_new0(&__ksk_list_alloc);

    if (ksk_list) {
        if (!(ksk_list->dbo = __ksk_new_object(connection))) {
            mm_alloc_delete(&__ksk_list_alloc, ksk_list);
            return NULL;
        }
    }

    return ksk_list;
}

void ksk_list_free(ksk_list_t* ksk_list) {
    if (ksk_list) {
        if (ksk_list->dbo) {
            db_object_free(ksk_list->dbo);
        }
        if (ksk_list->result_list) {
            db_result_list_free(ksk_list->result_list);
        }
        if (ksk_list->ksk) {
            ksk_free(ksk_list->ksk);
        }
        mm_alloc_delete(&__ksk_list_alloc, ksk_list);
    }
}

int ksk_list_get(ksk_list_t* ksk_list) {
    if (!ksk_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!ksk_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (ksk_list->result_list) {
        db_result_list_free(ksk_list->result_list);
    }
    if (!(ksk_list->result_list = db_object_read(ksk_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const ksk_t* ksk_list_begin(ksk_list_t* ksk_list) {
    const db_result_t* result;

    if (!ksk_list) {
        return NULL;
    }
    if (!ksk_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(ksk_list->result_list))) {
        return NULL;
    }
    if (!ksk_list->ksk) {
        if (!(ksk_list->ksk = ksk_new(db_object_connection(ksk_list->dbo)))) {
            return NULL;
        }
    }
    if (ksk_from_result(ksk_list->ksk, result)) {
        return NULL;
    }
    return ksk_list->ksk;
}

const ksk_t* ksk_list_next(ksk_list_t* ksk_list) {
    const db_result_t* result;

    if (!ksk_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(ksk_list->result_list))) {
        return NULL;
    }
    if (!ksk_list->ksk) {
        if (!(ksk_list->ksk = ksk_new(db_object_connection(ksk_list->dbo)))) {
            return NULL;
        }
    }
    if (ksk_from_result(ksk_list->ksk, result)) {
        return NULL;
    }
    return ksk_list->ksk;
}

