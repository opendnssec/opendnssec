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

#include "adapter.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new adapter object.
 * \param[in] connection a db_connection_t pointer.
 * \return a adapter_t pointer or NULL on error.
 */
static db_object_t* __adapter_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "Adapter")
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
        || db_object_field_set_name(object_field, "adapter")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "type")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "file")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
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

/* ADAPTER */

static mm_alloc_t __adapter_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(adapter_t));

adapter_t* adapter_new(const db_connection_t* connection) {
    adapter_t* adapter =
        (adapter_t*)mm_alloc_new0(&__adapter_alloc);

    if (adapter) {
        if (!(adapter->dbo = __adapter_new_object(connection))) {
            mm_alloc_delete(&__adapter_alloc, adapter);
            return NULL;
        }
        adapter->type = strdup("File");
    }

    return adapter;
}

void adapter_free(adapter_t* adapter) {
    if (adapter) {
        if (adapter->dbo) {
            db_object_free(adapter->dbo);
        }
        if (adapter->adapter) {
            free(adapter->adapter);
        }
        if (adapter->type) {
            free(adapter->type);
        }
        if (adapter->file) {
            free(adapter->file);
        }
        mm_alloc_delete(&__adapter_alloc, adapter);
    }
}

void adapter_reset(adapter_t* adapter) {
    if (adapter) {
        adapter->id = 0;
        if (adapter->adapter) {
            free(adapter->adapter);
        }
        adapter->adapter = NULL;
        if (adapter->type) {
            free(adapter->type);
        }
        adapter->type = strdup("File");
        if (adapter->file) {
            free(adapter->file);
        }
        adapter->file = NULL;
    }
}

int adapter_copy(adapter_t* adapter, const adapter_t* adapter_copy) {
    char* adapter_text = NULL;
    char* type_text = NULL;
    char* file_text = NULL;
    if (!adapter) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapter_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (adapter->adapter) {
        if (!(adapter_text = strdup(adapter->adapter))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    if (adapter->type) {
        if (!(type_text = strdup(adapter->type))) {
            if (adapter_text) {
                free(adapter_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (adapter->file) {
        if (!(file_text = strdup(adapter->file))) {
            if (adapter_text) {
                free(adapter_text);
            }
            if (type_text) {
                free(type_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    adapter->id = adapter_copy->id;
    if (adapter->adapter) {
        free(adapter->adapter);
    }
    adapter->adapter = adapter_text;
    if (adapter->type) {
        free(adapter->type);
    }
    adapter->type = type_text;
    if (adapter->file) {
        free(adapter->file);
    }
    adapter->file = file_text;
    return DB_OK;
}

int adapter_from_result(adapter_t* adapter, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!adapter) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    if (adapter->adapter) {
        free(adapter->adapter);
    }
    adapter->adapter = NULL;
    if (adapter->type) {
        free(adapter->type);
    }
    adapter->type = NULL;
    if (adapter->file) {
        free(adapter->file);
    }
    adapter->file = NULL;
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 4
        || db_value_to_int32(db_value_set_at(value_set, 0), &(adapter->id))
        || db_value_to_text(db_value_set_at(value_set, 1), &(adapter->adapter))
        || db_value_to_text(db_value_set_at(value_set, 2), &(adapter->type))
        || db_value_to_text(db_value_set_at(value_set, 3), &(adapter->file)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int adapter_id(const adapter_t* adapter) {
    if (!adapter) {
        return 0;
    }

    return adapter->id;
}

const char* adapter_adapter(const adapter_t* adapter) {
    if (!adapter) {
        return NULL;
    }

    return adapter->adapter;
}

const char* adapter_type(const adapter_t* adapter) {
    if (!adapter) {
        return NULL;
    }

    return adapter->type;
}

const char* adapter_file(const adapter_t* adapter) {
    if (!adapter) {
        return NULL;
    }

    return adapter->file;
}

int adapter_set_adapter(adapter_t* adapter, const char* adapter_text) {
    char* new_adapter;

    if (!adapter) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapter_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_adapter = strdup(adapter_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (adapter->adapter) {
        free(adapter->adapter);
    }
    adapter->adapter = new_adapter;

    return DB_OK;
}

int adapter_set_type(adapter_t* adapter, const char* type_text) {
    char* new_type;

    if (!adapter) {
        return DB_ERROR_UNKNOWN;
    }
    if (!type_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_type = strdup(type_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (adapter->type) {
        free(adapter->type);
    }
    adapter->type = new_type;

    return DB_OK;
}

int adapter_set_file(adapter_t* adapter, const char* file_text) {
    char* new_file;

    if (!adapter) {
        return DB_ERROR_UNKNOWN;
    }
    if (!file_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_file = strdup(file_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (adapter->file) {
        free(adapter->file);
    }
    adapter->file = new_file;

    return DB_OK;
}

int adapter_create(adapter_t* adapter) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!adapter) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapter->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (adapter->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "adapter")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "type")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "file")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
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

    if (db_value_from_text(db_value_set_get(value_set, 0), adapter->adapter)
        || db_value_from_text(db_value_set_get(value_set, 1), adapter->type)
        || db_value_from_text(db_value_set_get(value_set, 2), adapter->file))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(adapter->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int adapter_get_by_id(adapter_t* adapter, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!adapter) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapter->dbo) {
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

    result_list = db_object_read(adapter->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            adapter_from_result(adapter, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int adapter_update(adapter_t* adapter) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!adapter) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapter->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapter->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "adapter")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "type")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "file")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
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

    if (db_value_from_text(db_value_set_get(value_set, 0), adapter->adapter)
        || db_value_from_text(db_value_set_get(value_set, 1), adapter->type)
        || db_value_from_text(db_value_set_get(value_set, 2), adapter->file))
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
        || db_value_from_int32(db_clause_get_value(clause), adapter->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(adapter->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int adapter_delete(adapter_t* adapter) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!adapter) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapter->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapter->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), adapter->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(adapter->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* ADAPTER LIST */

static mm_alloc_t __adapter_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(adapter_list_t));

adapter_list_t* adapter_list_new(const db_connection_t* connection) {
    adapter_list_t* adapter_list =
        (adapter_list_t*)mm_alloc_new0(&__adapter_list_alloc);

    if (adapter_list) {
        if (!(adapter_list->dbo = __adapter_new_object(connection))) {
            mm_alloc_delete(&__adapter_list_alloc, adapter_list);
            return NULL;
        }
    }

    return adapter_list;
}

void adapter_list_free(adapter_list_t* adapter_list) {
    if (adapter_list) {
        if (adapter_list->dbo) {
            db_object_free(adapter_list->dbo);
        }
        if (adapter_list->result_list) {
            db_result_list_free(adapter_list->result_list);
        }
        if (adapter_list->adapter) {
            adapter_free(adapter_list->adapter);
        }
        mm_alloc_delete(&__adapter_list_alloc, adapter_list);
    }
}

int adapter_list_get(adapter_list_t* adapter_list) {
    if (!adapter_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!adapter_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (adapter_list->result_list) {
        db_result_list_free(adapter_list->result_list);
    }
    if (!(adapter_list->result_list = db_object_read(adapter_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const adapter_t* adapter_list_begin(adapter_list_t* adapter_list) {
    const db_result_t* result;

    if (!adapter_list) {
        return NULL;
    }
    if (!adapter_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(adapter_list->result_list))) {
        return NULL;
    }
    if (!adapter_list->adapter) {
        if (!(adapter_list->adapter = adapter_new(db_object_connection(adapter_list->dbo)))) {
            return NULL;
        }
    }
    if (adapter_from_result(adapter_list->adapter, result)) {
        return NULL;
    }
    return adapter_list->adapter;
}

const adapter_t* adapter_list_next(adapter_list_t* adapter_list) {
    const db_result_t* result;

    if (!adapter_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(adapter_list->result_list))) {
        return NULL;
    }
    if (!adapter_list->adapter) {
        if (!(adapter_list->adapter = adapter_new(db_object_connection(adapter_list->dbo)))) {
            return NULL;
        }
    }
    if (adapter_from_result(adapter_list->adapter, result)) {
        return NULL;
    }
    return adapter_list->adapter;
}

