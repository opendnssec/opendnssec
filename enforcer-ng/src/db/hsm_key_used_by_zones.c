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

#include "hsm_key_used_by_zones.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new hsm key used by zones object.
 * \param[in] connection a db_connection_t pointer.
 * \return a hsm_key_used_by_zones_t pointer or NULL on error.
 */
static db_object_t* __hsm_key_used_by_zones_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "HsmKey_used_by_zones")
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
        || db_object_field_set_name(object_field, "value")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parent_id")
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

/* HSM KEY USED BY ZONES */

static mm_alloc_t __hsm_key_used_by_zones_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(hsm_key_used_by_zones_t));

hsm_key_used_by_zones_t* hsm_key_used_by_zones_new(const db_connection_t* connection) {
    hsm_key_used_by_zones_t* hsm_key_used_by_zones =
        (hsm_key_used_by_zones_t*)mm_alloc_new0(&__hsm_key_used_by_zones_alloc);

    if (hsm_key_used_by_zones) {
        if (!(hsm_key_used_by_zones->dbo = __hsm_key_used_by_zones_new_object(connection))) {
            mm_alloc_delete(&__hsm_key_used_by_zones_alloc, hsm_key_used_by_zones);
            return NULL;
        }
    }

    return hsm_key_used_by_zones;
}

void hsm_key_used_by_zones_free(hsm_key_used_by_zones_t* hsm_key_used_by_zones) {
    if (hsm_key_used_by_zones) {
        if (hsm_key_used_by_zones->dbo) {
            db_object_free(hsm_key_used_by_zones->dbo);
        }
        if (hsm_key_used_by_zones->value) {
            free(hsm_key_used_by_zones->value);
        }
        mm_alloc_delete(&__hsm_key_used_by_zones_alloc, hsm_key_used_by_zones);
    }
}

void hsm_key_used_by_zones_reset(hsm_key_used_by_zones_t* hsm_key_used_by_zones) {
    if (hsm_key_used_by_zones) {
        hsm_key_used_by_zones->id = 0;
        if (hsm_key_used_by_zones->value) {
            free(hsm_key_used_by_zones->value);
        }
        hsm_key_used_by_zones->value = NULL;
        hsm_key_used_by_zones->parent_id = 0;
    }
}

int hsm_key_used_by_zones_copy(hsm_key_used_by_zones_t* hsm_key_used_by_zones, const hsm_key_used_by_zones_t* hsm_key_used_by_zones_copy) {
    char* value_text = NULL;
    if (!hsm_key_used_by_zones) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_used_by_zones_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (hsm_key_used_by_zones->value) {
        if (!(value_text = strdup(hsm_key_used_by_zones->value))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    hsm_key_used_by_zones->id = hsm_key_used_by_zones_copy->id;
    if (hsm_key_used_by_zones->value) {
        free(hsm_key_used_by_zones->value);
    }
    hsm_key_used_by_zones->value = value_text;
    hsm_key_used_by_zones->parent_id = hsm_key_used_by_zones_copy->parent_id;
    return DB_OK;
}

int hsm_key_used_by_zones_from_result(hsm_key_used_by_zones_t* hsm_key_used_by_zones, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!hsm_key_used_by_zones) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    if (hsm_key_used_by_zones->value) {
        free(hsm_key_used_by_zones->value);
    }
    hsm_key_used_by_zones->value = NULL;
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 3
        || db_value_to_int32(db_value_set_at(value_set, 0), &(hsm_key_used_by_zones->id))
        || db_value_to_text(db_value_set_at(value_set, 1), &(hsm_key_used_by_zones->value))
        || db_value_to_int32(db_value_set_at(value_set, 2), &(hsm_key_used_by_zones->parent_id)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int hsm_key_used_by_zones_id(const hsm_key_used_by_zones_t* hsm_key_used_by_zones) {
    if (!hsm_key_used_by_zones) {
        return 0;
    }

    return hsm_key_used_by_zones->id;
}

const char* hsm_key_used_by_zones_value(const hsm_key_used_by_zones_t* hsm_key_used_by_zones) {
    if (!hsm_key_used_by_zones) {
        return NULL;
    }

    return hsm_key_used_by_zones->value;
}

int hsm_key_used_by_zones_parent_id(const hsm_key_used_by_zones_t* hsm_key_used_by_zones) {
    if (!hsm_key_used_by_zones) {
        return 0;
    }

    return hsm_key_used_by_zones->parent_id;
}

int hsm_key_used_by_zones_set_value(hsm_key_used_by_zones_t* hsm_key_used_by_zones, const char* value_text) {
    char* new_value;

    if (!hsm_key_used_by_zones) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_value = strdup(value_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (hsm_key_used_by_zones->value) {
        free(hsm_key_used_by_zones->value);
    }
    hsm_key_used_by_zones->value = new_value;

    return DB_OK;
}

int hsm_key_used_by_zones_set_parent_id(hsm_key_used_by_zones_t* hsm_key_used_by_zones, int parent_id) {
    if (!hsm_key_used_by_zones) {
        return DB_ERROR_UNKNOWN;
    }

    hsm_key_used_by_zones->parent_id = parent_id;

    return DB_OK;
}

int hsm_key_used_by_zones_create(hsm_key_used_by_zones_t* hsm_key_used_by_zones) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!hsm_key_used_by_zones) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_used_by_zones->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (hsm_key_used_by_zones->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "value")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parent_id")
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

    if (db_value_from_text(db_value_set_get(value_set, 0), hsm_key_used_by_zones->value)
        || db_value_from_int32(db_value_set_get(value_set, 1), hsm_key_used_by_zones->parent_id))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(hsm_key_used_by_zones->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int hsm_key_used_by_zones_get_by_id(hsm_key_used_by_zones_t* hsm_key_used_by_zones, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!hsm_key_used_by_zones) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_used_by_zones->dbo) {
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

    result_list = db_object_read(hsm_key_used_by_zones->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            hsm_key_used_by_zones_from_result(hsm_key_used_by_zones, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int hsm_key_used_by_zones_update(hsm_key_used_by_zones_t* hsm_key_used_by_zones) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!hsm_key_used_by_zones) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_used_by_zones->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_used_by_zones->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "value")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parent_id")
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

    if (db_value_from_text(db_value_set_get(value_set, 0), hsm_key_used_by_zones->value)
        || db_value_from_int32(db_value_set_get(value_set, 1), hsm_key_used_by_zones->parent_id))
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
        || db_value_from_int32(db_clause_get_value(clause), hsm_key_used_by_zones->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(hsm_key_used_by_zones->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int hsm_key_used_by_zones_delete(hsm_key_used_by_zones_t* hsm_key_used_by_zones) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!hsm_key_used_by_zones) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_used_by_zones->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_used_by_zones->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), hsm_key_used_by_zones->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(hsm_key_used_by_zones->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* HSM KEY USED BY ZONES LIST */

static mm_alloc_t __hsm_key_used_by_zones_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(hsm_key_used_by_zones_list_t));

hsm_key_used_by_zones_list_t* hsm_key_used_by_zones_list_new(const db_connection_t* connection) {
    hsm_key_used_by_zones_list_t* hsm_key_used_by_zones_list =
        (hsm_key_used_by_zones_list_t*)mm_alloc_new0(&__hsm_key_used_by_zones_list_alloc);

    if (hsm_key_used_by_zones_list) {
        if (!(hsm_key_used_by_zones_list->dbo = __hsm_key_used_by_zones_new_object(connection))) {
            mm_alloc_delete(&__hsm_key_used_by_zones_list_alloc, hsm_key_used_by_zones_list);
            return NULL;
        }
    }

    return hsm_key_used_by_zones_list;
}

void hsm_key_used_by_zones_list_free(hsm_key_used_by_zones_list_t* hsm_key_used_by_zones_list) {
    if (hsm_key_used_by_zones_list) {
        if (hsm_key_used_by_zones_list->dbo) {
            db_object_free(hsm_key_used_by_zones_list->dbo);
        }
        if (hsm_key_used_by_zones_list->result_list) {
            db_result_list_free(hsm_key_used_by_zones_list->result_list);
        }
        if (hsm_key_used_by_zones_list->hsm_key_used_by_zones) {
            hsm_key_used_by_zones_free(hsm_key_used_by_zones_list->hsm_key_used_by_zones);
        }
        mm_alloc_delete(&__hsm_key_used_by_zones_list_alloc, hsm_key_used_by_zones_list);
    }
}

int hsm_key_used_by_zones_list_get(hsm_key_used_by_zones_list_t* hsm_key_used_by_zones_list) {
    if (!hsm_key_used_by_zones_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!hsm_key_used_by_zones_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (hsm_key_used_by_zones_list->result_list) {
        db_result_list_free(hsm_key_used_by_zones_list->result_list);
    }
    if (!(hsm_key_used_by_zones_list->result_list = db_object_read(hsm_key_used_by_zones_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const hsm_key_used_by_zones_t* hsm_key_used_by_zones_list_begin(hsm_key_used_by_zones_list_t* hsm_key_used_by_zones_list) {
    const db_result_t* result;

    if (!hsm_key_used_by_zones_list) {
        return NULL;
    }
    if (!hsm_key_used_by_zones_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(hsm_key_used_by_zones_list->result_list))) {
        return NULL;
    }
    if (!hsm_key_used_by_zones_list->hsm_key_used_by_zones) {
        if (!(hsm_key_used_by_zones_list->hsm_key_used_by_zones = hsm_key_used_by_zones_new(db_object_connection(hsm_key_used_by_zones_list->dbo)))) {
            return NULL;
        }
    }
    if (hsm_key_used_by_zones_from_result(hsm_key_used_by_zones_list->hsm_key_used_by_zones, result)) {
        return NULL;
    }
    return hsm_key_used_by_zones_list->hsm_key_used_by_zones;
}

const hsm_key_used_by_zones_t* hsm_key_used_by_zones_list_next(hsm_key_used_by_zones_list_t* hsm_key_used_by_zones_list) {
    const db_result_t* result;

    if (!hsm_key_used_by_zones_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(hsm_key_used_by_zones_list->result_list))) {
        return NULL;
    }
    if (!hsm_key_used_by_zones_list->hsm_key_used_by_zones) {
        if (!(hsm_key_used_by_zones_list->hsm_key_used_by_zones = hsm_key_used_by_zones_new(db_object_connection(hsm_key_used_by_zones_list->dbo)))) {
            return NULL;
        }
    }
    if (hsm_key_used_by_zones_from_result(hsm_key_used_by_zones_list->hsm_key_used_by_zones, result)) {
        return NULL;
    }
    return hsm_key_used_by_zones_list->hsm_key_used_by_zones;
}

