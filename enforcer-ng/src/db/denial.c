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

#include "denial.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new denial object.
 * \param[in] connection a db_connection_t pointer.
 * \return a denial_t pointer or NULL on error.
 */
static db_object_t* __denial_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "Denial")
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
        || db_object_field_set_name(object_field, "nsec")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nsec3")
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

/* DENIAL */

static mm_alloc_t __denial_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(denial_t));

denial_t* denial_new(const db_connection_t* connection) {
    denial_t* denial =
        (denial_t*)mm_alloc_new0(&__denial_alloc);

    if (denial) {
        if (!(denial->dbo = __denial_new_object(connection))) {
            mm_alloc_delete(&__denial_alloc, denial);
            return NULL;
        }
    }

    return denial;
}

void denial_free(denial_t* denial) {
    if (denial) {
        if (denial->dbo) {
            db_object_free(denial->dbo);
        }
        mm_alloc_delete(&__denial_alloc, denial);
    }
}

void denial_reset(denial_t* denial) {
    if (denial) {
        denial->id = 0;
        denial->nsec = 0;
        denial->nsec3 = 0;
    }
}

int denial_copy(denial_t* denial, const denial_t* denial_copy) {
    if (!denial) {
        return DB_ERROR_UNKNOWN;
    }
    if (!denial_copy) {
        return DB_ERROR_UNKNOWN;
    }

    denial->id = denial_copy->id;
    denial->nsec = denial_copy->nsec;
    denial->nsec3 = denial_copy->nsec3;
    return DB_OK;
}

int denial_from_result(denial_t* denial, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!denial) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 3
        || db_value_to_int32(db_value_set_at(value_set, 0), &(denial->id))
        || db_value_to_int32(db_value_set_at(value_set, 1), &(denial->nsec))
        || db_value_to_int32(db_value_set_at(value_set, 2), &(denial->nsec3)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int denial_id(const denial_t* denial) {
    if (!denial) {
        return 0;
    }

    return denial->id;
}

int denial_nsec(const denial_t* denial) {
    if (!denial) {
        return 0;
    }

    return denial->nsec;
}

int denial_nsec3(const denial_t* denial) {
    if (!denial) {
        return 0;
    }

    return denial->nsec3;
}

int denial_set_nsec(denial_t* denial, int nsec) {
    if (!denial) {
        return DB_ERROR_UNKNOWN;
    }

    denial->nsec = nsec;

    return DB_OK;
}

int denial_set_nsec3(denial_t* denial, int nsec3) {
    if (!denial) {
        return DB_ERROR_UNKNOWN;
    }

    denial->nsec3 = nsec3;

    return DB_OK;
}

int denial_create(denial_t* denial) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!denial) {
        return DB_ERROR_UNKNOWN;
    }
    if (!denial->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (denial->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nsec")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nsec3")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(2))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_int32(db_value_set_get(value_set, 0), denial->nsec)
        || db_value_from_int32(db_value_set_get(value_set, 1), denial->nsec3))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(denial->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int denial_get_by_id(denial_t* denial, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!denial) {
        return DB_ERROR_UNKNOWN;
    }
    if (!denial->dbo) {
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

    result_list = db_object_read(denial->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (db_result_list_next(result_list)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }

            denial_from_result(denial, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int denial_update(denial_t* denial) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!denial) {
        return DB_ERROR_UNKNOWN;
    }
    if (!denial->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!denial->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nsec")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nsec3")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(2))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_int32(db_value_set_get(value_set, 0), denial->nsec)
        || db_value_from_int32(db_value_set_get(value_set, 1), denial->nsec3))
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
        || db_value_from_int32(db_clause_get_value(clause), denial->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(denial->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int denial_delete(denial_t* denial) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!denial) {
        return DB_ERROR_UNKNOWN;
    }
    if (!denial->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!denial->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), denial->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(denial->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* DENIAL LIST */

static mm_alloc_t __denial_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(denial_list_t));

denial_list_t* denial_list_new(const db_connection_t* connection) {
    denial_list_t* denial_list =
        (denial_list_t*)mm_alloc_new0(&__denial_list_alloc);

    if (denial_list) {
        if (!(denial_list->dbo = __denial_new_object(connection))) {
            mm_alloc_delete(&__denial_list_alloc, denial_list);
            return NULL;
        }
    }

    return denial_list;
}

void denial_list_free(denial_list_t* denial_list) {
    if (denial_list) {
        if (denial_list->dbo) {
            db_object_free(denial_list->dbo);
        }
        if (denial_list->result_list) {
            db_result_list_free(denial_list->result_list);
        }
        if (denial_list->denial) {
            denial_free(denial_list->denial);
        }
        mm_alloc_delete(&__denial_list_alloc, denial_list);
    }
}

int denial_list_get(denial_list_t* denial_list) {
    if (!denial_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!denial_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (denial_list->result_list) {
        db_result_list_free(denial_list->result_list);
    }
    if (!(denial_list->result_list = db_object_read(denial_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const denial_t* denial_list_begin(denial_list_t* denial_list) {
    const db_result_t* result;

    if (!denial_list) {
        return NULL;
    }
    if (!denial_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(denial_list->result_list))) {
        return NULL;
    }
    if (!denial_list->denial) {
        if (!(denial_list->denial = denial_new(db_object_connection(denial_list->dbo)))) {
            return NULL;
        }
    }
    if (denial_from_result(denial_list->denial, result)) {
        return NULL;
    }
    return denial_list->denial;
}

const denial_t* denial_list_next(denial_list_t* denial_list) {
    const db_result_t* result;

    if (!denial_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(denial_list->result_list))) {
        return NULL;
    }
    if (!denial_list->denial) {
        if (!(denial_list->denial = denial_new(db_object_connection(denial_list->dbo)))) {
            return NULL;
        }
    }
    if (denial_from_result(denial_list->denial, result)) {
        return NULL;
    }
    return denial_list->denial;
}

