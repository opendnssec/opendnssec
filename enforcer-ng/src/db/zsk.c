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

#include "zsk.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

static const db_enum_t __enum_set_rollover_type[] = {
    { "ZskDoubleSignature", (zsk_rollover_type_t)ZSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE },
    { "ZskPrePublication", (zsk_rollover_type_t)ZSK_ROLLOVER_TYPE_PREPUBLICATION },
    { "ZskDoubleRRsig", (zsk_rollover_type_t)ZSK_ROLLOVER_TYPE_DOUBLE_RRSIG },
    { NULL, 0 }
};

/**
 * Create a new zsk object.
 * \param[in] connection a db_connection_t pointer.
 * \return a zsk_t pointer or NULL on error.
 */
static db_object_t* __zsk_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "Zsk")
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

/* ZSK */

static mm_alloc_t __zsk_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(zsk_t));

zsk_t* zsk_new(const db_connection_t* connection) {
    zsk_t* zsk =
        (zsk_t*)mm_alloc_new0(&__zsk_alloc);

    if (zsk) {
        if (!(zsk->dbo = __zsk_new_object(connection))) {
            mm_alloc_delete(&__zsk_alloc, zsk);
            return NULL;
        }
        zsk->rollover_type = ZSK_ROLLOVER_TYPE_PREPUBLICATION;
    }

    return zsk;
}

void zsk_free(zsk_t* zsk) {
    if (zsk) {
        if (zsk->dbo) {
            db_object_free(zsk->dbo);
        }
        if (zsk->repository) {
            free(zsk->repository);
        }
        mm_alloc_delete(&__zsk_alloc, zsk);
    }
}

void zsk_reset(zsk_t* zsk) {
    if (zsk) {
        zsk->id = 0;
        zsk->algorithm = 0;
        zsk->bits = 0;
        zsk->lifetime = 0;
        if (zsk->repository) {
            free(zsk->repository);
        }
        zsk->repository = NULL;
        zsk->standby = 0;
        zsk->manual_rollover = 0;
        zsk->rollover_type = ZSK_ROLLOVER_TYPE_PREPUBLICATION;
    }
}

int zsk_copy(zsk_t* zsk, const zsk_t* zsk_copy) {
    char* repository_text = NULL;
    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zsk_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (zsk->repository) {
        if (!(repository_text = strdup(zsk->repository))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    zsk->id = zsk_copy->id;
    zsk->algorithm = zsk_copy->algorithm;
    zsk->bits = zsk_copy->bits;
    zsk->lifetime = zsk_copy->lifetime;
    if (zsk->repository) {
        free(zsk->repository);
    }
    zsk->repository = repository_text;
    zsk->standby = zsk_copy->standby;
    zsk->manual_rollover = zsk_copy->manual_rollover;
    zsk->rollover_type = zsk_copy->rollover_type;
    return DB_OK;
}

int zsk_from_result(zsk_t* zsk, const db_result_t* result) {
    const db_value_set_t* value_set;
    int rollover_type;

    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    zsk_reset(zsk);
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 8
        || db_value_to_int32(db_value_set_at(value_set, 0), &(zsk->id))
        || db_value_to_uint32(db_value_set_at(value_set, 1), &(zsk->algorithm))
        || db_value_to_uint32(db_value_set_at(value_set, 2), &(zsk->bits))
        || db_value_to_int32(db_value_set_at(value_set, 3), &(zsk->lifetime))
        || db_value_to_text(db_value_set_at(value_set, 4), &(zsk->repository))
        || db_value_to_uint32(db_value_set_at(value_set, 5), &(zsk->standby))
        || db_value_to_uint32(db_value_set_at(value_set, 6), &(zsk->manual_rollover))
        || db_value_to_enum_value(db_value_set_at(value_set, 7), &rollover_type, __enum_set_rollover_type))
    {
        return DB_ERROR_UNKNOWN;
    }

    if (rollover_type == (zsk_rollover_type_t)ZSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE) {
        zsk->rollover_type = ZSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE;
    }
    if (rollover_type == (zsk_rollover_type_t)ZSK_ROLLOVER_TYPE_PREPUBLICATION) {
        zsk->rollover_type = ZSK_ROLLOVER_TYPE_PREPUBLICATION;
    }
    if (rollover_type == (zsk_rollover_type_t)ZSK_ROLLOVER_TYPE_DOUBLE_RRSIG) {
        zsk->rollover_type = ZSK_ROLLOVER_TYPE_DOUBLE_RRSIG;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int zsk_id(const zsk_t* zsk) {
    if (!zsk) {
        return 0;
    }

    return zsk->id;
}

unsigned int zsk_algorithm(const zsk_t* zsk) {
    if (!zsk) {
        return 0;
    }

    return zsk->algorithm;
}

unsigned int zsk_bits(const zsk_t* zsk) {
    if (!zsk) {
        return 0;
    }

    return zsk->bits;
}

int zsk_lifetime(const zsk_t* zsk) {
    if (!zsk) {
        return 0;
    }

    return zsk->lifetime;
}

const char* zsk_repository(const zsk_t* zsk) {
    if (!zsk) {
        return NULL;
    }

    return zsk->repository;
}

unsigned int zsk_standby(const zsk_t* zsk) {
    if (!zsk) {
        return 0;
    }

    return zsk->standby;
}

unsigned int zsk_manual_rollover(const zsk_t* zsk) {
    if (!zsk) {
        return 0;
    }

    return zsk->manual_rollover;
}

zsk_rollover_type_t zsk_rollover_type(const zsk_t* zsk) {
    if (!zsk) {
        return ZSK_ROLLOVER_TYPE_INVALID;
    }

    return zsk->rollover_type;
}

const char* zsk_rollover_type_text(const zsk_t* zsk) {
    const db_enum_t* enum_set = __enum_set_rollover_type;

    if (!zsk) {
        return NULL;
    }

    while (enum_set->text) {
        if (enum_set->value == zsk->rollover_type) {
            return enum_set->text;
        }
        enum_set++;
    }
    return NULL;
}

int zsk_set_algorithm(zsk_t* zsk, unsigned int algorithm) {
    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }

    zsk->algorithm = algorithm;

    return DB_OK;
}

int zsk_set_bits(zsk_t* zsk, unsigned int bits) {
    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }

    zsk->bits = bits;

    return DB_OK;
}

int zsk_set_lifetime(zsk_t* zsk, int lifetime) {
    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }

    zsk->lifetime = lifetime;

    return DB_OK;
}

int zsk_set_repository(zsk_t* zsk, const char* repository_text) {
    char* new_repository;

    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!repository_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_repository = strdup(repository_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (zsk->repository) {
        free(zsk->repository);
    }
    zsk->repository = new_repository;

    return DB_OK;
}

int zsk_set_standby(zsk_t* zsk, unsigned int standby) {
    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }

    zsk->standby = standby;

    return DB_OK;
}

int zsk_set_manual_rollover(zsk_t* zsk, unsigned int manual_rollover) {
    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }

    zsk->manual_rollover = manual_rollover;

    return DB_OK;
}

int zsk_set_rollover_type(zsk_t* zsk, zsk_rollover_type_t rollover_type) {
    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }

    zsk->rollover_type = rollover_type;

    return DB_OK;
}

int zsk_set_rollover_type_text(zsk_t* zsk, const char* rollover_type) {
    const db_enum_t* enum_set = __enum_set_rollover_type;

    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }

    while (enum_set->text) {
        if (!strcmp(enum_set->text, rollover_type)) {
            zsk->rollover_type = enum_set->value;
            return DB_OK;
        }
        enum_set++;
    }
    return DB_ERROR_UNKNOWN;
}

int zsk_create(zsk_t* zsk) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zsk->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (zsk->id) {
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
        || db_object_field_set_name(object_field, "rollover_type")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_rollover_type)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(7))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_uint32(db_value_set_get(value_set, 0), zsk->algorithm)
        || db_value_from_uint32(db_value_set_get(value_set, 1), zsk->bits)
        || db_value_from_int32(db_value_set_get(value_set, 2), zsk->lifetime)
        || db_value_from_text(db_value_set_get(value_set, 3), zsk->repository)
        || db_value_from_uint32(db_value_set_get(value_set, 4), zsk->standby)
        || db_value_from_uint32(db_value_set_get(value_set, 5), zsk->manual_rollover)
        || db_value_from_enum_value(db_value_set_get(value_set, 6), zsk->rollover_type, __enum_set_rollover_type))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(zsk->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int zsk_get_by_id(zsk_t* zsk, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zsk->dbo) {
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

    result_list = db_object_read(zsk->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (db_result_list_next(result_list)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }

            zsk_from_result(zsk, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int zsk_update(zsk_t* zsk) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zsk->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zsk->id) {
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
        || db_object_field_set_name(object_field, "rollover_type")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_rollover_type)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(7))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_uint32(db_value_set_get(value_set, 0), zsk->algorithm)
        || db_value_from_uint32(db_value_set_get(value_set, 1), zsk->bits)
        || db_value_from_int32(db_value_set_get(value_set, 2), zsk->lifetime)
        || db_value_from_text(db_value_set_get(value_set, 3), zsk->repository)
        || db_value_from_uint32(db_value_set_get(value_set, 4), zsk->standby)
        || db_value_from_uint32(db_value_set_get(value_set, 5), zsk->manual_rollover)
        || db_value_from_enum_value(db_value_set_get(value_set, 6), zsk->rollover_type, __enum_set_rollover_type))
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
        || db_value_from_int32(db_clause_get_value(clause), zsk->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(zsk->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int zsk_delete(zsk_t* zsk) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!zsk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zsk->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zsk->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), zsk->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(zsk->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* ZSK LIST */

static mm_alloc_t __zsk_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(zsk_list_t));

zsk_list_t* zsk_list_new(const db_connection_t* connection) {
    zsk_list_t* zsk_list =
        (zsk_list_t*)mm_alloc_new0(&__zsk_list_alloc);

    if (zsk_list) {
        if (!(zsk_list->dbo = __zsk_new_object(connection))) {
            mm_alloc_delete(&__zsk_list_alloc, zsk_list);
            return NULL;
        }
    }

    return zsk_list;
}

void zsk_list_free(zsk_list_t* zsk_list) {
    if (zsk_list) {
        if (zsk_list->dbo) {
            db_object_free(zsk_list->dbo);
        }
        if (zsk_list->result_list) {
            db_result_list_free(zsk_list->result_list);
        }
        if (zsk_list->zsk) {
            zsk_free(zsk_list->zsk);
        }
        mm_alloc_delete(&__zsk_list_alloc, zsk_list);
    }
}

int zsk_list_get(zsk_list_t* zsk_list) {
    if (!zsk_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zsk_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (zsk_list->result_list) {
        db_result_list_free(zsk_list->result_list);
    }
    if (!(zsk_list->result_list = db_object_read(zsk_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const zsk_t* zsk_list_begin(zsk_list_t* zsk_list) {
    const db_result_t* result;

    if (!zsk_list) {
        return NULL;
    }
    if (!zsk_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(zsk_list->result_list))) {
        return NULL;
    }
    if (!zsk_list->zsk) {
        if (!(zsk_list->zsk = zsk_new(db_object_connection(zsk_list->dbo)))) {
            return NULL;
        }
    }
    if (zsk_from_result(zsk_list->zsk, result)) {
        return NULL;
    }
    return zsk_list->zsk;
}

const zsk_t* zsk_list_next(zsk_list_t* zsk_list) {
    const db_result_t* result;

    if (!zsk_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(zsk_list->result_list))) {
        return NULL;
    }
    if (!zsk_list->zsk) {
        if (!(zsk_list->zsk = zsk_new(db_object_connection(zsk_list->dbo)))) {
            return NULL;
        }
    }
    if (zsk_from_result(zsk_list->zsk, result)) {
        return NULL;
    }
    return zsk_list->zsk;
}

