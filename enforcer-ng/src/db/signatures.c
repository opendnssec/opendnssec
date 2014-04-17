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

#include "signatures.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new signatures object.
 * \param[in] connection a db_connection_t pointer.
 * \return a signatures_t pointer or NULL on error.
 */
static db_object_t* __signatures_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "Signatures")
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
        || db_object_field_set_name(object_field, "resign")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "refresh")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "jitter")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "inceptionOffset")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "valdefault")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "valdenial")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "max_zone_ttl")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
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

/* SIGNATURES */

static mm_alloc_t __signatures_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(signatures_t));

signatures_t* signatures_new(const db_connection_t* connection) {
    signatures_t* signatures =
        (signatures_t*)mm_alloc_new0(&__signatures_alloc);

    if (signatures) {
        if (!(signatures->dbo = __signatures_new_object(connection))) {
            mm_alloc_delete(&__signatures_alloc, signatures);
            return NULL;
        }
        signatures->max_zone_ttl = 86400;
    }

    return signatures;
}

void signatures_free(signatures_t* signatures) {
    if (signatures) {
        if (signatures->dbo) {
            db_object_free(signatures->dbo);
        }
        mm_alloc_delete(&__signatures_alloc, signatures);
    }
}

void signatures_reset(signatures_t* signatures) {
    if (signatures) {
        signatures->id = 0;
        signatures->resign = 0;
        signatures->refresh = 0;
        signatures->jitter = 0;
        signatures->inceptionOffset = 0;
        signatures->valdefault = 0;
        signatures->valdenial = 0;
        signatures->max_zone_ttl = 86400;
    }
}

int signatures_copy(signatures_t* signatures, const signatures_t* signatures_copy) {
    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }
    if (!signatures_copy) {
        return DB_ERROR_UNKNOWN;
    }

    signatures->id = signatures_copy->id;
    signatures->resign = signatures_copy->resign;
    signatures->refresh = signatures_copy->refresh;
    signatures->jitter = signatures_copy->jitter;
    signatures->inceptionOffset = signatures_copy->inceptionOffset;
    signatures->valdefault = signatures_copy->valdefault;
    signatures->valdenial = signatures_copy->valdenial;
    signatures->max_zone_ttl = signatures_copy->max_zone_ttl;
    return DB_OK;
}

int signatures_from_result(signatures_t* signatures, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    signatures_reset(signatures);
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 8
        || db_value_to_int32(db_value_set_at(value_set, 0), &(signatures->id))
        || db_value_to_int32(db_value_set_at(value_set, 1), &(signatures->resign))
        || db_value_to_int32(db_value_set_at(value_set, 2), &(signatures->refresh))
        || db_value_to_int32(db_value_set_at(value_set, 3), &(signatures->jitter))
        || db_value_to_int32(db_value_set_at(value_set, 4), &(signatures->inceptionOffset))
        || db_value_to_int32(db_value_set_at(value_set, 5), &(signatures->valdefault))
        || db_value_to_int32(db_value_set_at(value_set, 6), &(signatures->valdenial))
        || db_value_to_int32(db_value_set_at(value_set, 7), &(signatures->max_zone_ttl)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int signatures_id(const signatures_t* signatures) {
    if (!signatures) {
        return 0;
    }

    return signatures->id;
}

int signatures_resign(const signatures_t* signatures) {
    if (!signatures) {
        return 0;
    }

    return signatures->resign;
}

int signatures_refresh(const signatures_t* signatures) {
    if (!signatures) {
        return 0;
    }

    return signatures->refresh;
}

int signatures_jitter(const signatures_t* signatures) {
    if (!signatures) {
        return 0;
    }

    return signatures->jitter;
}

int signatures_inceptionOffset(const signatures_t* signatures) {
    if (!signatures) {
        return 0;
    }

    return signatures->inceptionOffset;
}

int signatures_valdefault(const signatures_t* signatures) {
    if (!signatures) {
        return 0;
    }

    return signatures->valdefault;
}

int signatures_valdenial(const signatures_t* signatures) {
    if (!signatures) {
        return 0;
    }

    return signatures->valdenial;
}

int signatures_max_zone_ttl(const signatures_t* signatures) {
    if (!signatures) {
        return 0;
    }

    return signatures->max_zone_ttl;
}

int signatures_set_resign(signatures_t* signatures, int resign) {
    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }

    signatures->resign = resign;

    return DB_OK;
}

int signatures_set_refresh(signatures_t* signatures, int refresh) {
    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }

    signatures->refresh = refresh;

    return DB_OK;
}

int signatures_set_jitter(signatures_t* signatures, int jitter) {
    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }

    signatures->jitter = jitter;

    return DB_OK;
}

int signatures_set_inceptionOffset(signatures_t* signatures, int inceptionOffset) {
    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }

    signatures->inceptionOffset = inceptionOffset;

    return DB_OK;
}

int signatures_set_valdefault(signatures_t* signatures, int valdefault) {
    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }

    signatures->valdefault = valdefault;

    return DB_OK;
}

int signatures_set_valdenial(signatures_t* signatures, int valdenial) {
    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }

    signatures->valdenial = valdenial;

    return DB_OK;
}

int signatures_set_max_zone_ttl(signatures_t* signatures, int max_zone_ttl) {
    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }

    signatures->max_zone_ttl = max_zone_ttl;

    return DB_OK;
}

int signatures_create(signatures_t* signatures) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }
    if (!signatures->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (signatures->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "resign")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "refresh")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "jitter")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "inceptionOffset")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "valdefault")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "valdenial")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "max_zone_ttl")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
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

    if (db_value_from_int32(db_value_set_get(value_set, 0), signatures->resign)
        || db_value_from_int32(db_value_set_get(value_set, 1), signatures->refresh)
        || db_value_from_int32(db_value_set_get(value_set, 2), signatures->jitter)
        || db_value_from_int32(db_value_set_get(value_set, 3), signatures->inceptionOffset)
        || db_value_from_int32(db_value_set_get(value_set, 4), signatures->valdefault)
        || db_value_from_int32(db_value_set_get(value_set, 5), signatures->valdenial)
        || db_value_from_int32(db_value_set_get(value_set, 6), signatures->max_zone_ttl))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(signatures->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int signatures_get_by_id(signatures_t* signatures, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }
    if (!signatures->dbo) {
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

    result_list = db_object_read(signatures->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (db_result_list_next(result_list)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }

            signatures_from_result(signatures, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int signatures_update(signatures_t* signatures) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }
    if (!signatures->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!signatures->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "resign")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "refresh")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "jitter")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "inceptionOffset")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "valdefault")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "valdenial")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "max_zone_ttl")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
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

    if (db_value_from_int32(db_value_set_get(value_set, 0), signatures->resign)
        || db_value_from_int32(db_value_set_get(value_set, 1), signatures->refresh)
        || db_value_from_int32(db_value_set_get(value_set, 2), signatures->jitter)
        || db_value_from_int32(db_value_set_get(value_set, 3), signatures->inceptionOffset)
        || db_value_from_int32(db_value_set_get(value_set, 4), signatures->valdefault)
        || db_value_from_int32(db_value_set_get(value_set, 5), signatures->valdenial)
        || db_value_from_int32(db_value_set_get(value_set, 6), signatures->max_zone_ttl))
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
        || db_value_from_int32(db_clause_get_value(clause), signatures->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(signatures->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int signatures_delete(signatures_t* signatures) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }
    if (!signatures->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!signatures->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), signatures->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(signatures->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* SIGNATURES LIST */

static mm_alloc_t __signatures_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(signatures_list_t));

signatures_list_t* signatures_list_new(const db_connection_t* connection) {
    signatures_list_t* signatures_list =
        (signatures_list_t*)mm_alloc_new0(&__signatures_list_alloc);

    if (signatures_list) {
        if (!(signatures_list->dbo = __signatures_new_object(connection))) {
            mm_alloc_delete(&__signatures_list_alloc, signatures_list);
            return NULL;
        }
    }

    return signatures_list;
}

void signatures_list_free(signatures_list_t* signatures_list) {
    if (signatures_list) {
        if (signatures_list->dbo) {
            db_object_free(signatures_list->dbo);
        }
        if (signatures_list->result_list) {
            db_result_list_free(signatures_list->result_list);
        }
        if (signatures_list->signatures) {
            signatures_free(signatures_list->signatures);
        }
        mm_alloc_delete(&__signatures_list_alloc, signatures_list);
    }
}

int signatures_list_get(signatures_list_t* signatures_list) {
    if (!signatures_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!signatures_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (signatures_list->result_list) {
        db_result_list_free(signatures_list->result_list);
    }
    if (!(signatures_list->result_list = db_object_read(signatures_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const signatures_t* signatures_list_begin(signatures_list_t* signatures_list) {
    const db_result_t* result;

    if (!signatures_list) {
        return NULL;
    }
    if (!signatures_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(signatures_list->result_list))) {
        return NULL;
    }
    if (!signatures_list->signatures) {
        if (!(signatures_list->signatures = signatures_new(db_object_connection(signatures_list->dbo)))) {
            return NULL;
        }
    }
    if (signatures_from_result(signatures_list->signatures, result)) {
        return NULL;
    }
    return signatures_list->signatures;
}

const signatures_t* signatures_list_next(signatures_list_t* signatures_list) {
    const db_result_t* result;

    if (!signatures_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(signatures_list->result_list))) {
        return NULL;
    }
    if (!signatures_list->signatures) {
        if (!(signatures_list->signatures = signatures_new(db_object_connection(signatures_list->dbo)))) {
            return NULL;
        }
    }
    if (signatures_from_result(signatures_list->signatures, result)) {
        return NULL;
    }
    return signatures_list->signatures;
}

