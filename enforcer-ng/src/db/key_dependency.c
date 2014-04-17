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

#include "key_dependency.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new key dependency object.
 * \param[in] connection a db_connection_t pointer.
 * \return a key_dependency_t pointer or NULL on error.
 */
static db_object_t* __key_dependency_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "KeyDependency")
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
        || db_object_field_set_name(object_field, "from_key")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "to_key")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rrtype")
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

/* KEY DEPENDENCY */

static mm_alloc_t __key_dependency_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(key_dependency_t));

key_dependency_t* key_dependency_new(const db_connection_t* connection) {
    key_dependency_t* key_dependency =
        (key_dependency_t*)mm_alloc_new0(&__key_dependency_alloc);

    if (key_dependency) {
        if (!(key_dependency->dbo = __key_dependency_new_object(connection))) {
            mm_alloc_delete(&__key_dependency_alloc, key_dependency);
            return NULL;
        }
    }

    return key_dependency;
}

void key_dependency_free(key_dependency_t* key_dependency) {
    if (key_dependency) {
        if (key_dependency->dbo) {
            db_object_free(key_dependency->dbo);
        }
        if (key_dependency->from_key) {
            free(key_dependency->from_key);
        }
        if (key_dependency->to_key) {
            free(key_dependency->to_key);
        }
        mm_alloc_delete(&__key_dependency_alloc, key_dependency);
    }
}

void key_dependency_reset(key_dependency_t* key_dependency) {
    if (key_dependency) {
        key_dependency->id = 0;
        if (key_dependency->from_key) {
            free(key_dependency->from_key);
        }
        key_dependency->from_key = NULL;
        if (key_dependency->to_key) {
            free(key_dependency->to_key);
        }
        key_dependency->to_key = NULL;
        key_dependency->rrtype = 0;
    }
}

int key_dependency_copy(key_dependency_t* key_dependency, const key_dependency_t* key_dependency_copy) {
    char* from_key_text = NULL;
    char* to_key_text = NULL;
    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (key_dependency->from_key) {
        if (!(from_key_text = strdup(key_dependency->from_key))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    if (key_dependency->to_key) {
        if (!(to_key_text = strdup(key_dependency->to_key))) {
            if (from_key_text) {
                free(from_key_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    key_dependency->id = key_dependency_copy->id;
    if (key_dependency->from_key) {
        free(key_dependency->from_key);
    }
    key_dependency->from_key = from_key_text;
    if (key_dependency->to_key) {
        free(key_dependency->to_key);
    }
    key_dependency->to_key = to_key_text;
    key_dependency->rrtype = key_dependency_copy->rrtype;
    return DB_OK;
}

int key_dependency_from_result(key_dependency_t* key_dependency, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    if (key_dependency->from_key) {
        free(key_dependency->from_key);
    }
    key_dependency->from_key = NULL;
    if (key_dependency->to_key) {
        free(key_dependency->to_key);
    }
    key_dependency->to_key = NULL;
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 4
        || db_value_to_int32(db_value_set_at(value_set, 0), &(key_dependency->id))
        || db_value_to_text(db_value_set_at(value_set, 1), &(key_dependency->from_key))
        || db_value_to_text(db_value_set_at(value_set, 2), &(key_dependency->to_key))
        || db_value_to_uint32(db_value_set_at(value_set, 3), &(key_dependency->rrtype)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int key_dependency_id(const key_dependency_t* key_dependency) {
    if (!key_dependency) {
        return 0;
    }

    return key_dependency->id;
}

const char* key_dependency_from_key(const key_dependency_t* key_dependency) {
    if (!key_dependency) {
        return NULL;
    }

    return key_dependency->from_key;
}

const char* key_dependency_to_key(const key_dependency_t* key_dependency) {
    if (!key_dependency) {
        return NULL;
    }

    return key_dependency->to_key;
}

unsigned int key_dependency_rrtype(const key_dependency_t* key_dependency) {
    if (!key_dependency) {
        return 0;
    }

    return key_dependency->rrtype;
}

int key_dependency_set_from_key(key_dependency_t* key_dependency, const char* from_key_text) {
    char* new_from_key;

    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!from_key_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_from_key = strdup(from_key_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (key_dependency->from_key) {
        free(key_dependency->from_key);
    }
    key_dependency->from_key = new_from_key;

    return DB_OK;
}

int key_dependency_set_to_key(key_dependency_t* key_dependency, const char* to_key_text) {
    char* new_to_key;

    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!to_key_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_to_key = strdup(to_key_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (key_dependency->to_key) {
        free(key_dependency->to_key);
    }
    key_dependency->to_key = new_to_key;

    return DB_OK;
}

int key_dependency_set_rrtype(key_dependency_t* key_dependency, unsigned int rrtype) {
    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }

    key_dependency->rrtype = rrtype;

    return DB_OK;
}

int key_dependency_create(key_dependency_t* key_dependency) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (key_dependency->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "from_key")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "to_key")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rrtype")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(3))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_text(db_value_set_get(value_set, 0), key_dependency->from_key)
        || db_value_from_text(db_value_set_get(value_set, 1), key_dependency->to_key)
        || db_value_from_uint32(db_value_set_get(value_set, 2), key_dependency->rrtype))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(key_dependency->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int key_dependency_get_by_id(key_dependency_t* key_dependency, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency->dbo) {
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

    result_list = db_object_read(key_dependency->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (db_result_list_next(result_list)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }

            key_dependency_from_result(key_dependency, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int key_dependency_update(key_dependency_t* key_dependency) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "from_key")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "to_key")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rrtype")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(3))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_text(db_value_set_get(value_set, 0), key_dependency->from_key)
        || db_value_from_text(db_value_set_get(value_set, 1), key_dependency->to_key)
        || db_value_from_uint32(db_value_set_get(value_set, 2), key_dependency->rrtype))
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
        || db_value_from_int32(db_clause_get_value(clause), key_dependency->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(key_dependency->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int key_dependency_delete(key_dependency_t* key_dependency) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), key_dependency->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(key_dependency->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* KEY DEPENDENCY LIST */

static mm_alloc_t __key_dependency_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(key_dependency_list_t));

key_dependency_list_t* key_dependency_list_new(const db_connection_t* connection) {
    key_dependency_list_t* key_dependency_list =
        (key_dependency_list_t*)mm_alloc_new0(&__key_dependency_list_alloc);

    if (key_dependency_list) {
        if (!(key_dependency_list->dbo = __key_dependency_new_object(connection))) {
            mm_alloc_delete(&__key_dependency_list_alloc, key_dependency_list);
            return NULL;
        }
    }

    return key_dependency_list;
}

void key_dependency_list_free(key_dependency_list_t* key_dependency_list) {
    if (key_dependency_list) {
        if (key_dependency_list->dbo) {
            db_object_free(key_dependency_list->dbo);
        }
        if (key_dependency_list->result_list) {
            db_result_list_free(key_dependency_list->result_list);
        }
        if (key_dependency_list->key_dependency) {
            key_dependency_free(key_dependency_list->key_dependency);
        }
        mm_alloc_delete(&__key_dependency_list_alloc, key_dependency_list);
    }
}

int key_dependency_list_get(key_dependency_list_t* key_dependency_list) {
    if (!key_dependency_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (key_dependency_list->result_list) {
        db_result_list_free(key_dependency_list->result_list);
    }
    if (!(key_dependency_list->result_list = db_object_read(key_dependency_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const key_dependency_t* key_dependency_list_begin(key_dependency_list_t* key_dependency_list) {
    const db_result_t* result;

    if (!key_dependency_list) {
        return NULL;
    }
    if (!key_dependency_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(key_dependency_list->result_list))) {
        return NULL;
    }
    if (!key_dependency_list->key_dependency) {
        if (!(key_dependency_list->key_dependency = key_dependency_new(db_object_connection(key_dependency_list->dbo)))) {
            return NULL;
        }
    }
    if (key_dependency_from_result(key_dependency_list->key_dependency, result)) {
        return NULL;
    }
    return key_dependency_list->key_dependency;
}

const key_dependency_t* key_dependency_list_next(key_dependency_list_t* key_dependency_list) {
    const db_result_t* result;

    if (!key_dependency_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(key_dependency_list->result_list))) {
        return NULL;
    }
    if (!key_dependency_list->key_dependency) {
        if (!(key_dependency_list->key_dependency = key_dependency_new(db_object_connection(key_dependency_list->dbo)))) {
            return NULL;
        }
    }
    if (key_dependency_from_result(key_dependency_list->key_dependency, result)) {
        return NULL;
    }
    return key_dependency_list->key_dependency;
}

