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

#include "parent.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new parent object.
 * \param[in] connection a db_connection_t pointer.
 * \return a parent_t pointer or NULL on error.
 */
static db_object_t* __parent_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "Parent")
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
        || db_object_field_set_name(object_field, "ttlds")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "registrationdelay")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "propagationdelay")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "min")
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

/* PARENT */

static mm_alloc_t __parent_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(parent_t));

parent_t* parent_new(const db_connection_t* connection) {
    parent_t* parent =
        (parent_t*)mm_alloc_new0(&__parent_alloc);

    if (parent) {
        if (!(parent->dbo = __parent_new_object(connection))) {
            mm_alloc_delete(&__parent_alloc, parent);
            return NULL;
        }
        db_value_reset(&(parent->id));
    }

    return parent;
}

void parent_free(parent_t* parent) {
    if (parent) {
        if (parent->dbo) {
            db_object_free(parent->dbo);
        }
        db_value_reset(&(parent->id));
        mm_alloc_delete(&__parent_alloc, parent);
    }
}

void parent_reset(parent_t* parent) {
    if (parent) {
        db_value_reset(&(parent->id));
        parent->ttlds = 0;
        parent->registrationdelay = 0;
        parent->propagationdelay = 0;
        parent->ttl = 0;
        parent->min = 0;
    }
}

int parent_copy(parent_t* parent, const parent_t* parent_copy) {
    if (!parent) {
        return DB_ERROR_UNKNOWN;
    }
    if (!parent_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_copy(&(parent->id), &(parent_copy->id))) {
        return DB_ERROR_UNKNOWN;
    }
    parent->ttlds = parent_copy->ttlds;
    parent->registrationdelay = parent_copy->registrationdelay;
    parent->propagationdelay = parent_copy->propagationdelay;
    parent->ttl = parent_copy->ttl;
    parent->min = parent_copy->min;
    return DB_OK;
}

int parent_from_result(parent_t* parent, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!parent) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(parent->id));
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 6
        || db_value_copy(&(parent->id), db_value_set_at(value_set, 0))
        || db_value_to_int32(db_value_set_at(value_set, 1), &(parent->ttlds))
        || db_value_to_int32(db_value_set_at(value_set, 2), &(parent->registrationdelay))
        || db_value_to_int32(db_value_set_at(value_set, 3), &(parent->propagationdelay))
        || db_value_to_int32(db_value_set_at(value_set, 4), &(parent->ttl))
        || db_value_to_int32(db_value_set_at(value_set, 5), &(parent->min)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

const db_value_t* parent_id(const parent_t* parent) {
    if (!parent) {
        return NULL;
    }

    return &(parent->id);
}

int parent_ttlds(const parent_t* parent) {
    if (!parent) {
        return 0;
    }

    return parent->ttlds;
}

int parent_registrationdelay(const parent_t* parent) {
    if (!parent) {
        return 0;
    }

    return parent->registrationdelay;
}

int parent_propagationdelay(const parent_t* parent) {
    if (!parent) {
        return 0;
    }

    return parent->propagationdelay;
}

int parent_ttl(const parent_t* parent) {
    if (!parent) {
        return 0;
    }

    return parent->ttl;
}

int parent_min(const parent_t* parent) {
    if (!parent) {
        return 0;
    }

    return parent->min;
}

int parent_set_ttlds(parent_t* parent, int ttlds) {
    if (!parent) {
        return DB_ERROR_UNKNOWN;
    }

    parent->ttlds = ttlds;

    return DB_OK;
}

int parent_set_registrationdelay(parent_t* parent, int registrationdelay) {
    if (!parent) {
        return DB_ERROR_UNKNOWN;
    }

    parent->registrationdelay = registrationdelay;

    return DB_OK;
}

int parent_set_propagationdelay(parent_t* parent, int propagationdelay) {
    if (!parent) {
        return DB_ERROR_UNKNOWN;
    }

    parent->propagationdelay = propagationdelay;

    return DB_OK;
}

int parent_set_ttl(parent_t* parent, int ttl) {
    if (!parent) {
        return DB_ERROR_UNKNOWN;
    }

    parent->ttl = ttl;

    return DB_OK;
}

int parent_set_min(parent_t* parent, int min) {
    if (!parent) {
        return DB_ERROR_UNKNOWN;
    }

    parent->min = min;

    return DB_OK;
}

int parent_create(parent_t* parent) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!parent) {
        return DB_ERROR_UNKNOWN;
    }
    if (!parent->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!db_value_not_empty(&(parent->id))) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttlds")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "registrationdelay")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "propagationdelay")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "min")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(5))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_int32(db_value_set_get(value_set, 0), parent->ttlds)
        || db_value_from_int32(db_value_set_get(value_set, 1), parent->registrationdelay)
        || db_value_from_int32(db_value_set_get(value_set, 2), parent->propagationdelay)
        || db_value_from_int32(db_value_set_get(value_set, 3), parent->ttl)
        || db_value_from_int32(db_value_set_get(value_set, 4), parent->min))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(parent->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int parent_get_by_id(parent_t* parent, const db_value_t* id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!parent) {
        return DB_ERROR_UNKNOWN;
    }
    if (!parent->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!id) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(id)) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    result_list = db_object_read(parent->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (parent_from_result(parent, result)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }
                
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int parent_update(parent_t* parent) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!parent) {
        return DB_ERROR_UNKNOWN;
    }
    if (!parent->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(parent->id))) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttlds")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "registrationdelay")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "propagationdelay")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "min")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(5))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_int32(db_value_set_get(value_set, 0), parent->ttlds)
        || db_value_from_int32(db_value_set_get(value_set, 1), parent->registrationdelay)
        || db_value_from_int32(db_value_set_get(value_set, 2), parent->propagationdelay)
        || db_value_from_int32(db_value_set_get(value_set, 3), parent->ttl)
        || db_value_from_int32(db_value_set_get(value_set, 4), parent->min))
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
        || db_value_copy(db_clause_get_value(clause), &(parent->id))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(parent->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int parent_delete(parent_t* parent) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!parent) {
        return DB_ERROR_UNKNOWN;
    }
    if (!parent->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(parent->id))) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(parent->id))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(parent->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* PARENT LIST */

static mm_alloc_t __parent_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(parent_list_t));

parent_list_t* parent_list_new(const db_connection_t* connection) {
    parent_list_t* parent_list =
        (parent_list_t*)mm_alloc_new0(&__parent_list_alloc);

    if (parent_list) {
        if (!(parent_list->dbo = __parent_new_object(connection))) {
            mm_alloc_delete(&__parent_list_alloc, parent_list);
            return NULL;
        }
    }

    return parent_list;
}

void parent_list_free(parent_list_t* parent_list) {
    if (parent_list) {
        if (parent_list->dbo) {
            db_object_free(parent_list->dbo);
        }
        if (parent_list->result_list) {
            db_result_list_free(parent_list->result_list);
        }
        if (parent_list->parent) {
            parent_free(parent_list->parent);
        }
        mm_alloc_delete(&__parent_list_alloc, parent_list);
    }
}

int parent_list_get(parent_list_t* parent_list) {
    if (!parent_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!parent_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (parent_list->result_list) {
        db_result_list_free(parent_list->result_list);
    }
    if (!(parent_list->result_list = db_object_read(parent_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const parent_t* parent_list_begin(parent_list_t* parent_list) {
    const db_result_t* result;

    if (!parent_list) {
        return NULL;
    }
    if (!parent_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(parent_list->result_list))) {
        return NULL;
    }
    if (!parent_list->parent) {
        if (!(parent_list->parent = parent_new(db_object_connection(parent_list->dbo)))) {
            return NULL;
        }
    }
    if (parent_from_result(parent_list->parent, result)) {
        return NULL;
    }
    return parent_list->parent;
}

const parent_t* parent_list_next(parent_list_t* parent_list) {
    const db_result_t* result;

    if (!parent_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(parent_list->result_list))) {
        return NULL;
    }
    if (!parent_list->parent) {
        if (!(parent_list->parent = parent_new(db_object_connection(parent_list->dbo)))) {
            return NULL;
        }
    }
    if (parent_from_result(parent_list->parent, result)) {
        return NULL;
    }
    return parent_list->parent;
}
