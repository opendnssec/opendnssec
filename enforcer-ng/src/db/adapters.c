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

#include "adapters.h"
#include "db_error.h"

#include "mm.h"

/**
 * Create a new adapters object.
 * \param[in] connection a db_connection_t pointer.
 * \return an adapters_t pointer or NULL on error.
 */
static db_object_t* __adapters_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "Adapters")
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
        || db_object_field_set_name(object_field, "input")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "output")
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

/* ENFORCER ZONE */

static mm_alloc_t __adapters_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(adapters_t));

adapters_t* adapters_new(const db_connection_t* connection) {
    adapters_t* adapters =
        (adapters_t*)mm_alloc_new0(&__adapters_alloc);

    if (adapters) {
        if (!(adapters->dbo = __adapters_new_object(connection))) {
            mm_alloc_delete(&__adapters_alloc, adapters);
            return NULL;
        }
    }

    return adapters;
}

void adapters_free(adapters_t* adapters) {
    if (adapters) {
        if (adapters->dbo) {
            db_object_free(adapters->dbo);
        }
        mm_alloc_delete(&__adapters_alloc, adapters);
    }
}

void adapters_reset(adapters_t* adapters) {
    if (adapters) {
        adapters->id = 0;
        adapters->input = 0;
        adapters->output = 0;
    }
}

int adapters_from_result(adapters_t* adapters, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!adapters) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    adapters_reset(adapters);
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 3
        || db_value_to_int32(db_value_set_at(value_set, 0), &(adapters->id))
        || db_value_to_int32(db_value_set_at(value_set, 1), &(adapters->input))
        || db_value_to_int32(db_value_set_at(value_set, 2), &(adapters->output)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int adapters_id(const adapters_t* adapters) {
    if (!adapters) {
        return 0;
    }

    return adapters->id;
}

int adapters_input(const adapters_t* adapters) {
    if (!adapters) {
        return 0;
    }

    return adapters->input;
}

int adapters_output(const adapters_t* adapters) {
    if (!adapters) {
        return 0;
    }

    return adapters->output;
}

int adapters_set_input(adapters_t* adapters, int input) {
    if (!adapters) {
        return DB_ERROR_UNKNOWN;
    }

    adapters->input = input;

    return DB_OK;
}

int adapters_set_output(adapters_t* adapters, int output) {
    if (!adapters) {
        return DB_ERROR_UNKNOWN;
    }

    adapters->output = output;

    return DB_OK;
}

int adapters_create(adapters_t* adapters) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!adapters) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapters->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (adapters->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "input")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "output")
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

    if (db_value_from_int32(db_value_set_get(value_set, 0), adapters->input)
        || db_value_from_int32(db_value_set_get(value_set, 1), adapters->output))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(adapters->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int adapters_get_by_id(adapters_t* adapters, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!adapters) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapters->dbo) {
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

    result_list = db_object_read(adapters->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (db_result_list_next(result_list)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }

            adapters_from_result(adapters, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int adapters_update(adapters_t* adapters) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!adapters) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapters->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapters->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "input")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "output")
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

    if (db_value_from_int32(db_value_set_get(value_set, 0), adapters->input)
        || db_value_from_int32(db_value_set_get(value_set, 1), adapters->output))
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
        || db_value_from_int32(db_clause_get_value(clause), adapters->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(adapters->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int adapters_delete(adapters_t* adapters) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!adapters) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapters->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapters->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), adapters->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(adapters->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}
