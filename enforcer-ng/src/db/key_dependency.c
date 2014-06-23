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

const db_enum_t key_dependency_enum_set_type[] = {
    { "DS", (key_dependency_type_t)KEY_DEPENDENCY_TYPE_DS },
    { "RRSIG", (key_dependency_type_t)KEY_DEPENDENCY_TYPE_RRSIG },
    { "DNSKEY", (key_dependency_type_t)KEY_DEPENDENCY_TYPE_DNSKEY },
    { "RRSIGDNSKEY", (key_dependency_type_t)KEY_DEPENDENCY_TYPE_RRSIGDNSKEY },
    { NULL, 0 }
};

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
        || db_object_set_table(object, "keyDependency")
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
        || db_object_field_set_name(object_field, "rev")
        || db_object_field_set_type(object_field, DB_TYPE_REVISION)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "fromKeyDataId")
        || db_object_field_set_type(object_field, DB_TYPE_ANY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "toKeyDataId")
        || db_object_field_set_type(object_field, DB_TYPE_ANY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "type")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, key_dependency_enum_set_type)
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
        db_value_reset(&(key_dependency->id));
        db_value_reset(&(key_dependency->rev));
        db_value_reset(&(key_dependency->from_key_data_id));
        db_value_reset(&(key_dependency->to_key_data_id));
        key_dependency->type = KEY_DEPENDENCY_TYPE_INVALID;
    }

    return key_dependency;
}

key_dependency_t* key_dependency_new_copy(const key_dependency_t* key_dependency) {
    key_dependency_t* new_key_dependency;

    if (!key_dependency) {
        return NULL;
    }
    if (!key_dependency->dbo) {
        return NULL;
    }

    if (!(new_key_dependency = key_dependency_new(db_object_connection(key_dependency->dbo)))
        || key_dependency_copy(new_key_dependency, key_dependency))
    {
        key_dependency_free(new_key_dependency);
        return NULL;
    }
    return new_key_dependency;
}

void key_dependency_free(key_dependency_t* key_dependency) {
    if (key_dependency) {
        if (key_dependency->dbo) {
            db_object_free(key_dependency->dbo);
        }
        db_value_reset(&(key_dependency->id));
        db_value_reset(&(key_dependency->rev));
        db_value_reset(&(key_dependency->from_key_data_id));
        db_value_reset(&(key_dependency->to_key_data_id));
        mm_alloc_delete(&__key_dependency_alloc, key_dependency);
    }
}

void key_dependency_reset(key_dependency_t* key_dependency) {
    if (key_dependency) {
        db_value_reset(&(key_dependency->id));
        db_value_reset(&(key_dependency->rev));
        db_value_reset(&(key_dependency->from_key_data_id));
        db_value_reset(&(key_dependency->to_key_data_id));
        key_dependency->type = KEY_DEPENDENCY_TYPE_INVALID;
    }
}

int key_dependency_copy(key_dependency_t* key_dependency, const key_dependency_t* key_dependency_copy) {
    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_copy(&(key_dependency->id), &(key_dependency_copy->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_copy(&(key_dependency->rev), &(key_dependency_copy->rev))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_copy(&(key_dependency->from_key_data_id), &(key_dependency_copy->from_key_data_id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_copy(&(key_dependency->to_key_data_id), &(key_dependency_copy->to_key_data_id))) {
        return DB_ERROR_UNKNOWN;
    }
    key_dependency->type = key_dependency_copy->type;
    return DB_OK;
}

int key_dependency_cmp(const key_dependency_t* key_dependency_a, const key_dependency_t* key_dependency_b) {
    int ret;

    if (!key_dependency_a && !key_dependency_b) {
        return 0;
    }
    if (!key_dependency_a && key_dependency_b) {
        return -1;
    }
    if (key_dependency_a && !key_dependency_b) {
        return 1;
    }

    ret = 0;
    db_value_cmp(&(key_dependency_a->from_key_data_id), &(key_dependency_b->from_key_data_id), &ret);
    if (ret) {
        return ret;
    }

    ret = 0;
    db_value_cmp(&(key_dependency_a->to_key_data_id), &(key_dependency_b->to_key_data_id), &ret);
    if (ret) {
        return ret;
    }

    if (key_dependency_a->type != key_dependency_b->type) {
        return key_dependency_a->type < key_dependency_b->type ? -1 : 1;
    }
    return 0;
}

int key_dependency_from_result(key_dependency_t* key_dependency, const db_result_t* result) {
    const db_value_set_t* value_set;
    int type;

    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(key_dependency->id));
    db_value_reset(&(key_dependency->rev));
    db_value_reset(&(key_dependency->from_key_data_id));
    db_value_reset(&(key_dependency->to_key_data_id));
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 5
        || db_value_copy(&(key_dependency->id), db_value_set_at(value_set, 0))
        || db_value_copy(&(key_dependency->rev), db_value_set_at(value_set, 1))
        || db_value_copy(&(key_dependency->from_key_data_id), db_value_set_at(value_set, 2))
        || db_value_copy(&(key_dependency->to_key_data_id), db_value_set_at(value_set, 3))
        || db_value_to_enum_value(db_value_set_at(value_set, 4), &type, key_dependency_enum_set_type))
    {
        return DB_ERROR_UNKNOWN;
    }

    if (type == (key_dependency_type_t)KEY_DEPENDENCY_TYPE_DS) {
        key_dependency->type = KEY_DEPENDENCY_TYPE_DS;
    }
    else if (type == (key_dependency_type_t)KEY_DEPENDENCY_TYPE_RRSIG) {
        key_dependency->type = KEY_DEPENDENCY_TYPE_RRSIG;
    }
    else if (type == (key_dependency_type_t)KEY_DEPENDENCY_TYPE_DNSKEY) {
        key_dependency->type = KEY_DEPENDENCY_TYPE_DNSKEY;
    }
    else if (type == (key_dependency_type_t)KEY_DEPENDENCY_TYPE_RRSIGDNSKEY) {
        key_dependency->type = KEY_DEPENDENCY_TYPE_RRSIGDNSKEY;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

const db_value_t* key_dependency_id(const key_dependency_t* key_dependency) {
    if (!key_dependency) {
        return NULL;
    }

    return &(key_dependency->id);
}

const db_value_t* key_dependency_from_key_data_id(const key_dependency_t* key_dependency) {
    if (!key_dependency) {
        return NULL;
    }

    return &(key_dependency->from_key_data_id);
}

key_data_t* key_dependency_get_from_key_data(const key_dependency_t* key_dependency) {
    key_data_t* from_key_data_id = NULL;

    if (!key_dependency) {
        return NULL;
    }
    if (!key_dependency->dbo) {
        return NULL;
    }
    if (db_value_not_empty(&(key_dependency->from_key_data_id))) {
        return NULL;
    }

    if (!(from_key_data_id = key_data_new(db_object_connection(key_dependency->dbo)))) {
        return NULL;
    }
    if (key_data_get_by_id(from_key_data_id, &(key_dependency->from_key_data_id))) {
        key_data_free(from_key_data_id);
        return NULL;
    }

    return from_key_data_id;
}

const db_value_t* key_dependency_to_key_data_id(const key_dependency_t* key_dependency) {
    if (!key_dependency) {
        return NULL;
    }

    return &(key_dependency->to_key_data_id);
}

key_data_t* key_dependency_get_to_key_data(const key_dependency_t* key_dependency) {
    key_data_t* to_key_data_id = NULL;

    if (!key_dependency) {
        return NULL;
    }
    if (!key_dependency->dbo) {
        return NULL;
    }
    if (db_value_not_empty(&(key_dependency->to_key_data_id))) {
        return NULL;
    }

    if (!(to_key_data_id = key_data_new(db_object_connection(key_dependency->dbo)))) {
        return NULL;
    }
    if (key_data_get_by_id(to_key_data_id, &(key_dependency->to_key_data_id))) {
        key_data_free(to_key_data_id);
        return NULL;
    }

    return to_key_data_id;
}

key_dependency_type_t key_dependency_type(const key_dependency_t* key_dependency) {
    if (!key_dependency) {
        return KEY_DEPENDENCY_TYPE_INVALID;
    }

    return key_dependency->type;
}

const char* key_dependency_type_text(const key_dependency_t* key_dependency) {
    const db_enum_t* enum_set = key_dependency_enum_set_type;

    if (!key_dependency) {
        return NULL;
    }

    while (enum_set->text) {
        if (enum_set->value == key_dependency->type) {
            return enum_set->text;
        }
        enum_set++;
    }
    return NULL;
}

int key_dependency_set_from_key_data_id(key_dependency_t* key_dependency, const db_value_t* from_key_data_id) {
    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!from_key_data_id) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(from_key_data_id)) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(key_dependency->from_key_data_id));
    if (db_value_copy(&(key_dependency->from_key_data_id), from_key_data_id)) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int key_dependency_set_to_key_data_id(key_dependency_t* key_dependency, const db_value_t* to_key_data_id) {
    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!to_key_data_id) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(to_key_data_id)) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(key_dependency->to_key_data_id));
    if (db_value_copy(&(key_dependency->to_key_data_id), to_key_data_id)) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int key_dependency_set_type(key_dependency_t* key_dependency, key_dependency_type_t type) {
    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (type == KEY_DEPENDENCY_TYPE_INVALID) {
        return DB_ERROR_UNKNOWN;
    }

    key_dependency->type = type;

    return DB_OK;
}

int key_dependency_set_type_text(key_dependency_t* key_dependency, const char* type) {
    const db_enum_t* enum_set = key_dependency_enum_set_type;

    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }

    while (enum_set->text) {
        if (!strcmp(enum_set->text, type)) {
            key_dependency->type = enum_set->value;
            return DB_OK;
        }
        enum_set++;
    }
    return DB_ERROR_UNKNOWN;
}

db_clause_t* key_dependency_from_key_data_id_clause(db_clause_list_t* clause_list, const db_value_t* from_key_data_id) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!from_key_data_id) {
        return NULL;
    }
    if (db_value_not_empty(from_key_data_id)) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "fromKeyDataId")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_copy(db_clause_get_value(clause), from_key_data_id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* key_dependency_to_key_data_id_clause(db_clause_list_t* clause_list, const db_value_t* to_key_data_id) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!to_key_data_id) {
        return NULL;
    }
    if (db_value_not_empty(to_key_data_id)) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "toKeyDataId")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_copy(db_clause_get_value(clause), to_key_data_id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* key_dependency_type_clause(db_clause_list_t* clause_list, key_dependency_type_t type) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "type")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_enum_value(db_clause_get_value(clause), type, key_dependency_enum_set_type)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
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
    if (!db_value_not_empty(&(key_dependency->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (!db_value_not_empty(&(key_dependency->rev))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(key_dependency->from_key_data_id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(key_dependency->to_key_data_id))) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "fromKeyDataId")
        || db_object_field_set_type(object_field, DB_TYPE_ANY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "toKeyDataId")
        || db_object_field_set_type(object_field, DB_TYPE_ANY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "type")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, key_dependency_enum_set_type)
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

    if (db_value_copy(db_value_set_get(value_set, 0), &(key_dependency->from_key_data_id))
        || db_value_copy(db_value_set_get(value_set, 1), &(key_dependency->to_key_data_id))
        || db_value_from_enum_value(db_value_set_get(value_set, 2), key_dependency->type, key_dependency_enum_set_type))
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

int key_dependency_get_by_id(key_dependency_t* key_dependency, const db_value_t* id) {
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

    result_list = db_object_read(key_dependency->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_next(result_list);
        if (result) {
            if (key_dependency_from_result(key_dependency, result)) {
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

key_dependency_t* key_dependency_new_get_by_id(const db_connection_t* connection, const db_value_t* id) {
    key_dependency_t* key_dependency;

    if (!connection) {
        return NULL;
    }
    if (!id) {
        return NULL;
    }
    if (db_value_not_empty(id)) {
        return NULL;
    }

    if (!(key_dependency = key_dependency_new(connection))
        || key_dependency_get_by_id(key_dependency, id))
    {
        key_dependency_free(key_dependency);
        return NULL;
    }

    return key_dependency;
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
    if (db_value_not_empty(&(key_dependency->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(key_dependency->rev))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(key_dependency->from_key_data_id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(key_dependency->to_key_data_id))) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "fromKeyDataId")
        || db_object_field_set_type(object_field, DB_TYPE_ANY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "toKeyDataId")
        || db_object_field_set_type(object_field, DB_TYPE_ANY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "type")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, key_dependency_enum_set_type)
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

    if (db_value_copy(db_value_set_get(value_set, 0), &(key_dependency->from_key_data_id))
        || db_value_copy(db_value_set_get(value_set, 1), &(key_dependency->to_key_data_id))
        || db_value_from_enum_value(db_value_set_get(value_set, 2), key_dependency->type, key_dependency_enum_set_type))
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
        || db_value_copy(db_clause_get_value(clause), &(key_dependency->id))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "rev")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(key_dependency->rev))
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
    if (db_value_not_empty(&(key_dependency->id))) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(key_dependency->id))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "rev")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(key_dependency->rev))
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

int key_dependency_count(key_dependency_t* key_dependency, db_clause_list_t* clause_list, size_t* count) {
    if (!key_dependency) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!count) {
        return DB_ERROR_UNKNOWN;
    }

    return db_object_count(key_dependency->dbo, NULL, clause_list, count);
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

key_dependency_list_t* key_dependency_list_new_get(const db_connection_t* connection) {
    key_dependency_list_t* key_dependency_list;

    if (!connection) {
        return NULL;
    }

    if (!(key_dependency_list = key_dependency_list_new(connection))
        || key_dependency_list_get(key_dependency_list))
    {
        key_dependency_list_free(key_dependency_list);
        return NULL;
    }

    return key_dependency_list;
}

int key_dependency_list_get_by_clauses(key_dependency_list_t* key_dependency_list, const db_clause_list_t* clause_list) {
    if (!key_dependency_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!clause_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (key_dependency_list->result_list) {
        db_result_list_free(key_dependency_list->result_list);
    }
    if (!(key_dependency_list->result_list = db_object_read(key_dependency_list->dbo, NULL, clause_list))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

key_dependency_list_t* key_dependency_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list) {
    key_dependency_list_t* key_dependency_list;

    if (!connection) {
        return NULL;
    }
    if (!clause_list) {
        return NULL;
    }

    if (!(key_dependency_list = key_dependency_list_new(connection))
        || key_dependency_list_get_by_clauses(key_dependency_list, clause_list))
    {
        key_dependency_list_free(key_dependency_list);
        return NULL;
    }

    return key_dependency_list;
}

int key_dependency_list_get_by_from_key_data_id(key_dependency_list_t* key_dependency_list, const db_value_t* from_key_data_id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;

    if (!key_dependency_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!from_key_data_id) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(from_key_data_id)) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "fromKeyDataId")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), from_key_data_id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    if (key_dependency_list->result_list) {
        db_result_list_free(key_dependency_list->result_list);
    }
    if (!(key_dependency_list->result_list = db_object_read(key_dependency_list->dbo, NULL, clause_list))) {
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    db_clause_list_free(clause_list);
    return DB_OK;
}

key_dependency_list_t* key_dependency_list_new_get_by_from_key_data_id(const db_connection_t* connection, const db_value_t* from_key_data_id) {
    key_dependency_list_t* key_dependency_list;

    if (!connection) {
        return NULL;
    }
    if (!from_key_data_id) {
        return NULL;
    }
    if (db_value_not_empty(from_key_data_id)) {
        return NULL;
    }

    if (!(key_dependency_list = key_dependency_list_new(connection))
        || key_dependency_list_get_by_from_key_data_id(key_dependency_list, from_key_data_id))
    {
        key_dependency_list_free(key_dependency_list);
        return NULL;
    }

    return key_dependency_list;
}

int key_dependency_list_get_by_to_key_data_id(key_dependency_list_t* key_dependency_list, const db_value_t* to_key_data_id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;

    if (!key_dependency_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!to_key_data_id) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(to_key_data_id)) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "toKeyDataId")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), to_key_data_id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    if (key_dependency_list->result_list) {
        db_result_list_free(key_dependency_list->result_list);
    }
    if (!(key_dependency_list->result_list = db_object_read(key_dependency_list->dbo, NULL, clause_list))) {
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    db_clause_list_free(clause_list);
    return DB_OK;
}

key_dependency_list_t* key_dependency_list_new_get_by_to_key_data_id(const db_connection_t* connection, const db_value_t* to_key_data_id) {
    key_dependency_list_t* key_dependency_list;

    if (!connection) {
        return NULL;
    }
    if (!to_key_data_id) {
        return NULL;
    }
    if (db_value_not_empty(to_key_data_id)) {
        return NULL;
    }

    if (!(key_dependency_list = key_dependency_list_new(connection))
        || key_dependency_list_get_by_to_key_data_id(key_dependency_list, to_key_data_id))
    {
        key_dependency_list_free(key_dependency_list);
        return NULL;
    }

    return key_dependency_list;
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

key_dependency_t* key_dependency_list_get_begin(key_dependency_list_t* key_dependency_list) {
    const db_result_t* result;
    key_dependency_t* key_dependency;

    if (!key_dependency_list) {
        return NULL;
    }
    if (!key_dependency_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(key_dependency_list->result_list))) {
        return NULL;
    }
    if (!(key_dependency = key_dependency_new(db_object_connection(key_dependency_list->dbo)))) {
        return NULL;
    }
    if (key_dependency_from_result(key_dependency, result)) {
        key_dependency_free(key_dependency);
        return NULL;
    }
    return key_dependency;
}

const key_dependency_t* key_dependency_list_next(key_dependency_list_t* key_dependency_list) {
    const db_result_t* result;

    if (!key_dependency_list) {
        return NULL;
    }
    if (!key_dependency_list->result_list) {
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

key_dependency_t* key_dependency_list_get_next(key_dependency_list_t* key_dependency_list) {
    const db_result_t* result;
    key_dependency_t* key_dependency;

    if (!key_dependency_list) {
        return NULL;
    }
    if (!key_dependency_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(key_dependency_list->result_list))) {
        return NULL;
    }
    if (!(key_dependency = key_dependency_new(db_object_connection(key_dependency_list->dbo)))) {
        return NULL;
    }
    if (key_dependency_from_result(key_dependency, result)) {
        key_dependency_free(key_dependency);
        return NULL;
    }
    return key_dependency;
}

int key_dependency_list_fetch_all(key_dependency_list_t* key_dependency_list) {
    if (!key_dependency_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency_list->result_list) {
        return DB_ERROR_UNKNOWN;
    }

    return db_result_list_fetch_all(key_dependency_list->result_list);
}

size_t key_dependency_list_size(key_dependency_list_t* key_dependency_list) {
    if (!key_dependency_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_dependency_list->result_list) {
        return DB_ERROR_UNKNOWN;
    }

    return db_result_list_size(key_dependency_list->result_list);
}
