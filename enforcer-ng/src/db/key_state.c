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

#include "key_state.h"
#include "db_error.h"

#include "mm.h"

#include <stdlib.h>
#include <string.h>

const db_enum_t __enum_set_state[] = {
    { "hidden", (key_state_rrstate_t)KEY_STATE_RRSTATE_HIDDEN },
    { "rumoured", (key_state_rrstate_t)KEY_STATE_RRSTATE_RUMOURED },
    { "omnipresent", (key_state_rrstate_t)KEY_STATE_RRSTATE_OMNIPRESENT },
    { "unretentive", (key_state_rrstate_t)KEY_STATE_RRSTATE_UNRETENTIVE },
    { "NA", (key_state_rrstate_t)KEY_STATE_RRSTATE_NA },
    { NULL, 0 }
};

db_object_t* __key_state_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "KeyState")
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
        || db_object_field_set_name(object_field, "state")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_state)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "last_change")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "minimize")
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

    if (db_object_set_object_field_list(object, object_field_list)) {
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    return object;
}

/* ENFORCER ZONE */

mm_alloc_t __key_state_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(key_state_t));

key_state_t* key_state_new(const db_connection_t* connection) {
    key_state_t* key_state =
        (key_state_t*)mm_alloc_new0(&__key_state_alloc);

    if (key_state) {
        if (!(key_state->dbo = __key_state_new_object(connection))) {
            mm_alloc_delete(&__key_state_alloc, key_state);
            return NULL;
        }
        key_state->state = KEY_STATE_RRSTATE_HIDDEN;
    }

    return key_state;
}

void key_state_free(key_state_t* key_state) {
    if (key_state) {
        if (key_state->dbo) {
            db_object_free(key_state->dbo);
        }
        mm_alloc_delete(&__key_state_alloc, key_state);
    }
}

void key_state_reset(key_state_t* key_state) {
    if (key_state) {
        key_state->id = 0;
        key_state->state = KEY_STATE_RRSTATE_HIDDEN;
        key_state->last_change = 0;
        key_state->minimize = 0;
        key_state->ttl = 0;
    }
}

int key_state_copy(key_state_t* key_state, const key_state_t* key_state_copy) {
    if (!key_state) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_state_copy) {
        return DB_ERROR_UNKNOWN;
    }

    key_state->id = key_state_copy->id;
    key_state->state = key_state_copy->state;
    key_state->last_change = key_state_copy->last_change;
    key_state->minimize = key_state_copy->minimize;
    key_state->ttl = key_state_copy->ttl;
    return DB_OK;
}

int key_state_from_result(key_state_t* key_state, const db_result_t* result) {
    const db_value_set_t* value_set;
    int state;

    if (!key_state) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    key_state_reset(key_state);
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 5
        || db_value_to_int32(db_value_set_get(value_set, 0), &(key_state->id))
        || db_value_to_enum_value(db_value_set_get(value_set, 1), &state, __enum_set_state)
        || db_value_to_int32(db_value_set_get(value_set, 2), &(key_state->last_change))
        || db_value_to_int32(db_value_set_get(value_set, 3), &(key_state->minimize))
        || db_value_to_int32(db_value_set_get(value_set, 4), &(key_state->ttl)))
    {
        return DB_ERROR_UNKNOWN;
    }

    if (state == (key_state_rrstate_t)KEY_STATE_RRSTATE_HIDDEN) {
        key_state->state = KEY_STATE_RRSTATE_HIDDEN;
    }
    else if (state == (key_state_rrstate_t)KEY_STATE_RRSTATE_RUMOURED) {
        key_state->state = KEY_STATE_RRSTATE_RUMOURED;
    }
    else if (state == (key_state_rrstate_t)KEY_STATE_RRSTATE_OMNIPRESENT) {
        key_state->state = KEY_STATE_RRSTATE_OMNIPRESENT;
    }
    else if (state == (key_state_rrstate_t)KEY_STATE_RRSTATE_UNRETENTIVE) {
        key_state->state = KEY_STATE_RRSTATE_UNRETENTIVE;
    }
    else if (state == (key_state_rrstate_t)KEY_STATE_RRSTATE_NA) {
        key_state->state = KEY_STATE_RRSTATE_NA;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int key_state_id(const key_state_t* key_state) {
    if (!key_state) {
        return DB_ERROR_UNKNOWN;
    }

    return key_state->id;
}

key_state_rrstate_t key_state_state(const key_state_t* key_state) {
    if (!key_state) {
        return KEY_STATE_RRSTATE_INVALID;
    }

    return key_state->state;
}

const char* key_state_state_text(const key_state_t* key_state) {
    const db_enum_t* enum_set = __enum_set_state;

    if (!key_state) {
        return NULL;
    }

    while (enum_set->text) {
        if (enum_set->value == key_state->state) {
            return enum_set->text;
        }
        enum_set++;
    }
    return NULL;
}

int key_state_last_change(const key_state_t* key_state) {
    if (!key_state) {
        return DB_ERROR_UNKNOWN;
    }

    return key_state->last_change;
}

int key_state_minimize(const key_state_t* key_state) {
    if (!key_state) {
        return DB_ERROR_UNKNOWN;
    }

    return key_state->minimize;
}

int key_state_ttl(const key_state_t* key_state) {
    if (!key_state) {
        return DB_ERROR_UNKNOWN;
    }

    return key_state->ttl;
}

int key_state_get_by_id(key_state_t* key_state, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;
    const db_value_set_t* value_set;

    if (!key_state) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_state->dbo) {
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

    result_list = db_object_read(key_state->dbo, NULL, clause_list);
    if (!result_list
        || !(result = db_result_list_begin(result_list))
        || !(value_set = db_result_value_set(result))
        || key_state_from_result(key_state, result))
    {
        db_result_list_free(result_list);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    if (db_result_list_next(result_list)) {
        key_state_reset(key_state);
        db_result_list_free(result_list);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    db_result_list_free(result_list);
    db_clause_list_free(clause_list);
    return DB_OK;
}

/* ENFORCER ZONE LIST */

mm_alloc_t __key_state_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(key_state_list_t));

key_state_list_t* key_state_list_new(const db_connection_t* connection) {
    key_state_list_t* key_state_list =
        (key_state_list_t*)mm_alloc_new0(&__key_state_list_alloc);

    if (key_state_list) {
        if (!(key_state_list->dbo = __key_state_new_object(connection))) {
            mm_alloc_delete(&__key_state_list_alloc, key_state_list);
            return NULL;
        }
    }

    return key_state_list;
}

void key_state_list_free(key_state_list_t* key_state_list) {
    if (key_state_list) {
        if (key_state_list->dbo) {
            db_object_free(key_state_list->dbo);
        }
        if (key_state_list->result_list) {
            db_result_list_free(key_state_list->result_list);
        }
        if (key_state_list->key_state) {
            key_state_free(key_state_list->key_state);
        }
        mm_alloc_delete(&__key_state_list_alloc, key_state_list);
    }
}

int key_state_list_get_4_by_id(key_state_list_t* key_state_list, int id1, int id2, int id3, int id4) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;

    if (!key_state_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_state_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!id1) {
        return DB_ERROR_UNKNOWN;
    }
    if (!id2) {
        return DB_ERROR_UNKNOWN;
    }
    if (!id3) {
        return DB_ERROR_UNKNOWN;
    }
    if (!id4) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), id1)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_OR)
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), id2)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_OR)
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), id3)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_OR)
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), id4)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    if (key_state_list->result_list) {
        db_result_list_free(key_state_list->result_list);
    }
    if (!(key_state_list->result_list = db_object_read(key_state_list->dbo, NULL, clause_list))) {
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    db_clause_list_free(clause_list);
    return DB_OK;
}

const key_state_t* key_state_list_begin(key_state_list_t* key_state_list) {
    const db_result_t* result;

    if (!key_state_list) {
        return NULL;
    }
    if (!key_state_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(key_state_list->result_list))) {
        return NULL;
    }
    if (!key_state_list->key_state) {
        if (!(key_state_list->key_state = key_state_new(db_object_connection(key_state_list->dbo)))) {
            return NULL;
        }
    }
    if (key_state_from_result(key_state_list->key_state, result)) {
        return NULL;
    }
    return key_state_list->key_state;
}

const key_state_t* key_state_list_next(key_state_list_t* key_state_list) {
    const db_result_t* result;

    if (!key_state_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(key_state_list->result_list))) {
        return NULL;
    }
    if (!key_state_list->key_state) {
        if (!(key_state_list->key_state = key_state_new(db_object_connection(key_state_list->dbo)))) {
            return NULL;
        }
    }
    if (key_state_from_result(key_state_list->key_state, result)) {
        return NULL;
    }
    return key_state_list->key_state;
}
