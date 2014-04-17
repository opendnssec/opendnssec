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

#include "csk.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

static const db_enum_t __enum_set_rollover_type[] = {
    { "CskDoubleRRset", (csk_rollover_type_t)CSK_ROLLOVER_TYPE_DOUBLE_RRSET },
    { "CskSingleSignature", (csk_rollover_type_t)CSK_ROLLOVER_TYPE_SINGLE_SIGNATURE },
    { "CskDoubleDS", (csk_rollover_type_t)CSK_ROLLOVER_TYPE_DOUBLE_DS },
    { "CskDoubleSignature", (csk_rollover_type_t)CSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE },
    { "CskPrePublication", (csk_rollover_type_t)CSK_ROLLOVER_TYPE_PREPUBLICATION },
    { NULL, 0 }
};

/**
 * Create a new csk object.
 * \param[in] connection a db_connection_t pointer.
 * \return a csk_t pointer or NULL on error.
 */
static db_object_t* __csk_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "Csk")
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

/* CSK */

static mm_alloc_t __csk_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(csk_t));

csk_t* csk_new(const db_connection_t* connection) {
    csk_t* csk =
        (csk_t*)mm_alloc_new0(&__csk_alloc);

    if (csk) {
        if (!(csk->dbo = __csk_new_object(connection))) {
            mm_alloc_delete(&__csk_alloc, csk);
            return NULL;
        }
        csk->rollover_type = CSK_ROLLOVER_TYPE_PREPUBLICATION;
    }

    return csk;
}

void csk_free(csk_t* csk) {
    if (csk) {
        if (csk->dbo) {
            db_object_free(csk->dbo);
        }
        if (csk->repository) {
            free(csk->repository);
        }
        mm_alloc_delete(&__csk_alloc, csk);
    }
}

void csk_reset(csk_t* csk) {
    if (csk) {
        csk->id = 0;
        csk->algorithm = 0;
        csk->bits = 0;
        csk->lifetime = 0;
        if (csk->repository) {
            free(csk->repository);
        }
        csk->repository = NULL;
        csk->standby = 0;
        csk->manual_rollover = 0;
        csk->rfc5011 = 0;
        csk->rollover_type = CSK_ROLLOVER_TYPE_PREPUBLICATION;
    }
}

int csk_copy(csk_t* csk, const csk_t* csk_copy) {
    char* repository_text = NULL;
    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!csk_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (csk->repository) {
        if (!(repository_text = strdup(csk->repository))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    csk->id = csk_copy->id;
    csk->algorithm = csk_copy->algorithm;
    csk->bits = csk_copy->bits;
    csk->lifetime = csk_copy->lifetime;
    if (csk->repository) {
        free(csk->repository);
    }
    csk->repository = repository_text;
    csk->standby = csk_copy->standby;
    csk->manual_rollover = csk_copy->manual_rollover;
    csk->rfc5011 = csk_copy->rfc5011;
    csk->rollover_type = csk_copy->rollover_type;
    return DB_OK;
}

int csk_from_result(csk_t* csk, const db_result_t* result) {
    const db_value_set_t* value_set;
    int rollover_type;

    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    csk_reset(csk);
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 9
        || db_value_to_int32(db_value_set_at(value_set, 0), &(csk->id))
        || db_value_to_uint32(db_value_set_at(value_set, 1), &(csk->algorithm))
        || db_value_to_uint32(db_value_set_at(value_set, 2), &(csk->bits))
        || db_value_to_int32(db_value_set_at(value_set, 3), &(csk->lifetime))
        || db_value_to_text(db_value_set_at(value_set, 4), &(csk->repository))
        || db_value_to_uint32(db_value_set_at(value_set, 5), &(csk->standby))
        || db_value_to_uint32(db_value_set_at(value_set, 6), &(csk->manual_rollover))
        || db_value_to_uint32(db_value_set_at(value_set, 7), &(csk->rfc5011))
        || db_value_to_enum_value(db_value_set_at(value_set, 8), &rollover_type, __enum_set_rollover_type))
    {
        return DB_ERROR_UNKNOWN;
    }

    if (rollover_type == (csk_rollover_type_t)CSK_ROLLOVER_TYPE_DOUBLE_RRSET) {
        csk->rollover_type = CSK_ROLLOVER_TYPE_DOUBLE_RRSET;
    }
    if (rollover_type == (csk_rollover_type_t)CSK_ROLLOVER_TYPE_SINGLE_SIGNATURE) {
        csk->rollover_type = CSK_ROLLOVER_TYPE_SINGLE_SIGNATURE;
    }
    if (rollover_type == (csk_rollover_type_t)CSK_ROLLOVER_TYPE_DOUBLE_DS) {
        csk->rollover_type = CSK_ROLLOVER_TYPE_DOUBLE_DS;
    }
    if (rollover_type == (csk_rollover_type_t)CSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE) {
        csk->rollover_type = CSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE;
    }
    if (rollover_type == (csk_rollover_type_t)CSK_ROLLOVER_TYPE_PREPUBLICATION) {
        csk->rollover_type = CSK_ROLLOVER_TYPE_PREPUBLICATION;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int csk_id(const csk_t* csk) {
    if (!csk) {
        return 0;
    }

    return csk->id;
}

unsigned int csk_algorithm(const csk_t* csk) {
    if (!csk) {
        return 0;
    }

    return csk->algorithm;
}

unsigned int csk_bits(const csk_t* csk) {
    if (!csk) {
        return 0;
    }

    return csk->bits;
}

int csk_lifetime(const csk_t* csk) {
    if (!csk) {
        return 0;
    }

    return csk->lifetime;
}

const char* csk_repository(const csk_t* csk) {
    if (!csk) {
        return NULL;
    }

    return csk->repository;
}

unsigned int csk_standby(const csk_t* csk) {
    if (!csk) {
        return 0;
    }

    return csk->standby;
}

unsigned int csk_manual_rollover(const csk_t* csk) {
    if (!csk) {
        return 0;
    }

    return csk->manual_rollover;
}

unsigned int csk_rfc5011(const csk_t* csk) {
    if (!csk) {
        return 0;
    }

    return csk->rfc5011;
}

csk_rollover_type_t csk_rollover_type(const csk_t* csk) {
    if (!csk) {
        return CSK_ROLLOVER_TYPE_INVALID;
    }

    return csk->rollover_type;
}

const char* csk_rollover_type_text(const csk_t* csk) {
    const db_enum_t* enum_set = __enum_set_rollover_type;

    if (!csk) {
        return NULL;
    }

    while (enum_set->text) {
        if (enum_set->value == csk->rollover_type) {
            return enum_set->text;
        }
        enum_set++;
    }
    return NULL;
}

int csk_set_algorithm(csk_t* csk, unsigned int algorithm) {
    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }

    csk->algorithm = algorithm;

    return DB_OK;
}

int csk_set_bits(csk_t* csk, unsigned int bits) {
    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }

    csk->bits = bits;

    return DB_OK;
}

int csk_set_lifetime(csk_t* csk, int lifetime) {
    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }

    csk->lifetime = lifetime;

    return DB_OK;
}

int csk_set_repository(csk_t* csk, const char* repository_text) {
    char* new_repository;

    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!repository_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_repository = strdup(repository_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (csk->repository) {
        free(csk->repository);
    }
    csk->repository = new_repository;

    return DB_OK;
}

int csk_set_standby(csk_t* csk, unsigned int standby) {
    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }

    csk->standby = standby;

    return DB_OK;
}

int csk_set_manual_rollover(csk_t* csk, unsigned int manual_rollover) {
    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }

    csk->manual_rollover = manual_rollover;

    return DB_OK;
}

int csk_set_rfc5011(csk_t* csk, unsigned int rfc5011) {
    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }

    csk->rfc5011 = rfc5011;

    return DB_OK;
}

int csk_set_rollover_type(csk_t* csk, csk_rollover_type_t rollover_type) {
    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }

    csk->rollover_type = rollover_type;

    return DB_OK;
}

int csk_set_rollover_type_text(csk_t* csk, const char* rollover_type) {
    const db_enum_t* enum_set = __enum_set_rollover_type;

    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }

    while (enum_set->text) {
        if (!strcmp(enum_set->text, rollover_type)) {
            csk->rollover_type = enum_set->value;
            return DB_OK;
        }
        enum_set++;
    }
    return DB_ERROR_UNKNOWN;
}

int csk_create(csk_t* csk) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!csk->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (csk->id) {
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

    if (db_value_from_uint32(db_value_set_get(value_set, 0), csk->algorithm)
        || db_value_from_uint32(db_value_set_get(value_set, 1), csk->bits)
        || db_value_from_int32(db_value_set_get(value_set, 2), csk->lifetime)
        || db_value_from_text(db_value_set_get(value_set, 3), csk->repository)
        || db_value_from_uint32(db_value_set_get(value_set, 4), csk->standby)
        || db_value_from_uint32(db_value_set_get(value_set, 5), csk->manual_rollover)
        || db_value_from_uint32(db_value_set_get(value_set, 6), csk->rfc5011)
        || db_value_from_enum_value(db_value_set_get(value_set, 7), csk->rollover_type, __enum_set_rollover_type))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(csk->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int csk_get_by_id(csk_t* csk, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!csk->dbo) {
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

    result_list = db_object_read(csk->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (db_result_list_next(result_list)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }

            csk_from_result(csk, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int csk_update(csk_t* csk) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!csk->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!csk->id) {
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

    if (db_value_from_uint32(db_value_set_get(value_set, 0), csk->algorithm)
        || db_value_from_uint32(db_value_set_get(value_set, 1), csk->bits)
        || db_value_from_int32(db_value_set_get(value_set, 2), csk->lifetime)
        || db_value_from_text(db_value_set_get(value_set, 3), csk->repository)
        || db_value_from_uint32(db_value_set_get(value_set, 4), csk->standby)
        || db_value_from_uint32(db_value_set_get(value_set, 5), csk->manual_rollover)
        || db_value_from_uint32(db_value_set_get(value_set, 6), csk->rfc5011)
        || db_value_from_enum_value(db_value_set_get(value_set, 7), csk->rollover_type, __enum_set_rollover_type))
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
        || db_value_from_int32(db_clause_get_value(clause), csk->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(csk->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int csk_delete(csk_t* csk) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!csk) {
        return DB_ERROR_UNKNOWN;
    }
    if (!csk->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!csk->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), csk->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(csk->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* CSK LIST */

static mm_alloc_t __csk_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(csk_list_t));

csk_list_t* csk_list_new(const db_connection_t* connection) {
    csk_list_t* csk_list =
        (csk_list_t*)mm_alloc_new0(&__csk_list_alloc);

    if (csk_list) {
        if (!(csk_list->dbo = __csk_new_object(connection))) {
            mm_alloc_delete(&__csk_list_alloc, csk_list);
            return NULL;
        }
    }

    return csk_list;
}

void csk_list_free(csk_list_t* csk_list) {
    if (csk_list) {
        if (csk_list->dbo) {
            db_object_free(csk_list->dbo);
        }
        if (csk_list->result_list) {
            db_result_list_free(csk_list->result_list);
        }
        if (csk_list->csk) {
            csk_free(csk_list->csk);
        }
        mm_alloc_delete(&__csk_list_alloc, csk_list);
    }
}

int csk_list_get(csk_list_t* csk_list) {
    if (!csk_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!csk_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (csk_list->result_list) {
        db_result_list_free(csk_list->result_list);
    }
    if (!(csk_list->result_list = db_object_read(csk_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const csk_t* csk_list_begin(csk_list_t* csk_list) {
    const db_result_t* result;

    if (!csk_list) {
        return NULL;
    }
    if (!csk_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(csk_list->result_list))) {
        return NULL;
    }
    if (!csk_list->csk) {
        if (!(csk_list->csk = csk_new(db_object_connection(csk_list->dbo)))) {
            return NULL;
        }
    }
    if (csk_from_result(csk_list->csk, result)) {
        return NULL;
    }
    return csk_list->csk;
}

const csk_t* csk_list_next(csk_list_t* csk_list) {
    const db_result_t* result;

    if (!csk_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(csk_list->result_list))) {
        return NULL;
    }
    if (!csk_list->csk) {
        if (!(csk_list->csk = csk_new(db_object_connection(csk_list->dbo)))) {
            return NULL;
        }
    }
    if (csk_from_result(csk_list->csk, result)) {
        return NULL;
    }
    return csk_list->csk;
}

