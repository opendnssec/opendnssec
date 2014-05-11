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

#include "database_version.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new database version object.
 * \param[in] connection a db_connection_t pointer.
 * \return a database_version_t pointer or NULL on error.
 */
static db_object_t* __database_version_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "databaseVersion")
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
        || db_object_field_set_name(object_field, "version")
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

/* DATABASE VERSION */

static mm_alloc_t __database_version_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(database_version_t));

database_version_t* database_version_new(const db_connection_t* connection) {
    database_version_t* database_version =
        (database_version_t*)mm_alloc_new0(&__database_version_alloc);

    if (database_version) {
        if (!(database_version->dbo = __database_version_new_object(connection))) {
            mm_alloc_delete(&__database_version_alloc, database_version);
            return NULL;
        }
        db_value_reset(&(database_version->id));
        db_value_reset(&(database_version->rev));
    }

    return database_version;
}

void database_version_free(database_version_t* database_version) {
    if (database_version) {
        if (database_version->dbo) {
            db_object_free(database_version->dbo);
        }
        db_value_reset(&(database_version->id));
        db_value_reset(&(database_version->rev));
        mm_alloc_delete(&__database_version_alloc, database_version);
    }
}

void database_version_reset(database_version_t* database_version) {
    if (database_version) {
        db_value_reset(&(database_version->id));
        db_value_reset(&(database_version->rev));
        database_version->version = 0;
    }
}

int database_version_copy(database_version_t* database_version, const database_version_t* database_version_copy) {
    if (!database_version) {
        return DB_ERROR_UNKNOWN;
    }
    if (!database_version_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_copy(&(database_version->id), &(database_version_copy->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_copy(&(database_version->rev), &(database_version_copy->rev))) {
        return DB_ERROR_UNKNOWN;
    }
    database_version->version = database_version_copy->version;
    return DB_OK;
}

int database_version_cmp(const database_version_t* database_version_a, const database_version_t* database_version_b) {
    if (!database_version_a && !database_version_b) {
        return 0;
    }
    if (!database_version_a && database_version_b) {
        return -1;
    }
    if (database_version_a && !database_version_b) {
        return 1;
    }

    if (database_version_a->version != database_version_b->version) {
        return database_version_a->version < database_version_b->version ? -1 : 1;
    }
    return 0;
}

int database_version_from_result(database_version_t* database_version, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!database_version) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(database_version->id));
    db_value_reset(&(database_version->rev));
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 3
        || db_value_copy(&(database_version->id), db_value_set_at(value_set, 0))
        || db_value_copy(&(database_version->rev), db_value_set_at(value_set, 1))
        || db_value_to_uint32(db_value_set_at(value_set, 2), &(database_version->version)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

const db_value_t* database_version_id(const database_version_t* database_version) {
    if (!database_version) {
        return NULL;
    }

    return &(database_version->id);
}

unsigned int database_version_version(const database_version_t* database_version) {
    if (!database_version) {
        return 0;
    }

    return database_version->version;
}

int database_version_set_version(database_version_t* database_version, unsigned int version) {
    if (!database_version) {
        return DB_ERROR_UNKNOWN;
    }

    database_version->version = version;

    return DB_OK;
}

db_clause_t* database_version_version_clause(db_clause_list_t* clause_list, unsigned int version) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "version")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), version)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

int database_version_create(database_version_t* database_version) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!database_version) {
        return DB_ERROR_UNKNOWN;
    }
    if (!database_version->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!db_value_not_empty(&(database_version->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (!db_value_not_empty(&(database_version->rev))) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "version")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(1))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_uint32(db_value_set_get(value_set, 0), database_version->version))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(database_version->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int database_version_get_by_id(database_version_t* database_version, const db_value_t* id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!database_version) {
        return DB_ERROR_UNKNOWN;
    }
    if (!database_version->dbo) {
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

    result_list = db_object_read(database_version->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_next(result_list);
        if (result) {
            if (database_version_from_result(database_version, result)) {
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

database_version_t* database_version_new_get_by_id(const db_connection_t* connection, const db_value_t* id) {
    database_version_t* database_version;

    if (!connection) {
        return NULL;
    }
    if (!id) {
        return NULL;
    }
    if (db_value_not_empty(id)) {
        return NULL;
    }

    if (!(database_version = database_version_new(connection))
        || database_version_get_by_id(database_version, id))
    {
        database_version_free(database_version);
        return NULL;
    }

    return database_version;
}

int database_version_update(database_version_t* database_version) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!database_version) {
        return DB_ERROR_UNKNOWN;
    }
    if (!database_version->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(database_version->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(database_version->rev))) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "version")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(1))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_uint32(db_value_set_get(value_set, 0), database_version->version))
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
        || db_value_copy(db_clause_get_value(clause), &(database_version->id))
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
        || db_value_copy(db_clause_get_value(clause), &(database_version->rev))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(database_version->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int database_version_delete(database_version_t* database_version) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!database_version) {
        return DB_ERROR_UNKNOWN;
    }
    if (!database_version->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(database_version->id))) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(database_version->id))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "rev")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(database_version->rev))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(database_version->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* DATABASE VERSION LIST */

static mm_alloc_t __database_version_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(database_version_list_t));

database_version_list_t* database_version_list_new(const db_connection_t* connection) {
    database_version_list_t* database_version_list =
        (database_version_list_t*)mm_alloc_new0(&__database_version_list_alloc);

    if (database_version_list) {
        if (!(database_version_list->dbo = __database_version_new_object(connection))) {
            mm_alloc_delete(&__database_version_list_alloc, database_version_list);
            return NULL;
        }
    }

    return database_version_list;
}

void database_version_list_free(database_version_list_t* database_version_list) {
    if (database_version_list) {
        if (database_version_list->dbo) {
            db_object_free(database_version_list->dbo);
        }
        if (database_version_list->result_list) {
            db_result_list_free(database_version_list->result_list);
        }
        if (database_version_list->database_version) {
            database_version_free(database_version_list->database_version);
        }
        mm_alloc_delete(&__database_version_list_alloc, database_version_list);
    }
}

int database_version_list_get(database_version_list_t* database_version_list) {
    if (!database_version_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!database_version_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (database_version_list->result_list) {
        db_result_list_free(database_version_list->result_list);
    }
    if (!(database_version_list->result_list = db_object_read(database_version_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

database_version_list_t* database_version_list_new_get(const db_connection_t* connection) {
    database_version_list_t* database_version_list;

    if (!connection) {
        return NULL;
    }

    if (!(database_version_list = database_version_list_new(connection))
        || database_version_list_get(database_version_list))
    {
        database_version_list_free(database_version_list);
        return NULL;
    }

    return database_version_list;
}

int database_version_list_get_by_clauses(database_version_list_t* database_version_list, const db_clause_list_t* clause_list) {
    if (!database_version_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!clause_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!database_version_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (database_version_list->result_list) {
        db_result_list_free(database_version_list->result_list);
    }
    if (!(database_version_list->result_list = db_object_read(database_version_list->dbo, NULL, clause_list))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

database_version_list_t* database_version_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list) {
    database_version_list_t* database_version_list;

    if (!connection) {
        return NULL;
    }
    if (!clause_list) {
        return NULL;
    }

    if (!(database_version_list = database_version_list_new(connection))
        || database_version_list_get_by_clauses(database_version_list, clause_list))
    {
        database_version_list_free(database_version_list);
        return NULL;
    }

    return database_version_list;
}

const database_version_t* database_version_list_next(database_version_list_t* database_version_list) {
    const db_result_t* result;

    if (!database_version_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(database_version_list->result_list))) {
        return NULL;
    }
    if (!database_version_list->database_version) {
        if (!(database_version_list->database_version = database_version_new(db_object_connection(database_version_list->dbo)))) {
            return NULL;
        }
    }
    if (database_version_from_result(database_version_list->database_version, result)) {
        return NULL;
    }
    return database_version_list->database_version;
}

database_version_t* database_version_list_get_next(database_version_list_t* database_version_list) {
    const db_result_t* result;
    database_version_t* database_version;

    if (!database_version_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(database_version_list->result_list))) {
        return NULL;
    }
    if (!(database_version = database_version_new(db_object_connection(database_version_list->dbo)))) {
        return NULL;
    }
    if (database_version_from_result(database_version_list->database_version, result)) {
        database_version_free(database_version);
        return NULL;
    }
    return database_version;
}
