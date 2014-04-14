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

#include "db_backend_sqlite.h"
#include "db_error.h"

#include "mm.h"
#include "shared/log.h"

#include <stdlib.h>
#include <sqlite3.h>
#include <stdio.h>
#include <unistd.h>

static int db_backend_sqlite_transaction_rollback(void*);

/**
 * Keep track of if we have initialized the SQLite backend.
 */
static int __sqlite3_initialized = 0;

/**
 * The SQLite database backend specific data.
 */
typedef struct db_backend_sqlite {
    sqlite3* db;
    int transaction;
} db_backend_sqlite_t;

static mm_alloc_t __sqlite_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_backend_sqlite_t));

/**
 * The SQLite database backend specific data for walking a result.
 */
typedef struct db_backend_sqlite_statement {
    db_backend_sqlite_t* backend_sqlite;
    sqlite3_stmt* statement;
    int fields;
    const db_object_t* object;
} db_backend_sqlite_statement_t;

static mm_alloc_t __sqlite_statement_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_backend_sqlite_statement_t));

static int db_backend_sqlite_initialize(void* data) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

    if (!backend_sqlite) {
        return DB_ERROR_UNKNOWN;
    }

    if (!__sqlite3_initialized) {
        int ret = sqlite3_initialize();
        if (ret != SQLITE_OK) {
            return DB_ERROR_UNKNOWN;
        }
        __sqlite3_initialized = 1;
    }
    return DB_OK;
}

static int db_backend_sqlite_shutdown(void* data) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

    if (!backend_sqlite) {
        return DB_ERROR_UNKNOWN;
    }

    if (__sqlite3_initialized) {
        int ret = sqlite3_shutdown();
        if (ret != SQLITE_OK) {
            return DB_ERROR_UNKNOWN;
        }
        __sqlite3_initialized = 0;
    }
    return DB_OK;
}

static int db_backend_sqlite_connect(void* data, const db_configuration_list_t* configuration_list) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;
    const db_configuration_t* file;
    int ret;

    if (!__sqlite3_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_sqlite) {
        return DB_ERROR_UNKNOWN;
    }
    if (backend_sqlite->db) {
        return DB_ERROR_UNKNOWN;
    }
    if (!configuration_list) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(file = db_configuration_list_find(configuration_list, "file"))) {
        return DB_ERROR_UNKNOWN;
    }

    ret = sqlite3_open_v2(
        db_configuration_value(file),
        &(backend_sqlite->db),
        SQLITE_OPEN_READWRITE
        | SQLITE_OPEN_CREATE
        | SQLITE_OPEN_FULLMUTEX,
        NULL);
    if (ret != SQLITE_OK) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

static int db_backend_sqlite_disconnect(void* data) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;
    int ret;

    if (!__sqlite3_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_sqlite) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_sqlite->db) {
        return DB_ERROR_UNKNOWN;
    }

    if (backend_sqlite->transaction) {
        db_backend_sqlite_transaction_rollback(backend_sqlite);
    }
    ret = sqlite3_close(backend_sqlite->db);
    if (ret != SQLITE_OK) {
        return DB_ERROR_UNKNOWN;
    }
    backend_sqlite->db = NULL;
    return DB_OK;
}

/**
 * Build the clause/WHERE SQL and append it to `sqlp`, how much that is left in
 * the buffer pointed by `sqlp` is specified by `left`.
 * \param[in] object a db_object_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \param[in] sqlp a character pointer pointer.
 * \param[in] left an integer pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
static int __db_backend_sqlite_build_clause(const db_object_t* object, const db_clause_list_t* clause_list, char** sqlp, int* left) {
    const db_clause_t* clause;
    int first, ret;

    if (!clause_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!sqlp) {
        return DB_ERROR_UNKNOWN;
    }
    if (!*sqlp) {
        return DB_ERROR_UNKNOWN;
    }
    if (!left) {
        return DB_ERROR_UNKNOWN;
    }
    if (*left < 1) {
        return DB_ERROR_UNKNOWN;
    }

    clause = db_clause_list_begin(clause_list);
    first = 1;
    while (clause) {
        if (first) {
            first = 0;
        }
        else {
            switch (db_clause_operator(clause)) {
            case DB_CLAUSE_OPERATOR_AND:
                if ((ret = snprintf(*sqlp, *left, " AND")) >= *left) {
                    return DB_ERROR_UNKNOWN;
                }
                break;

            case DB_CLAUSE_OPERATOR_OR:
                if ((ret = snprintf(*sqlp, *left, " OR")) >= *left) {
                    return DB_ERROR_UNKNOWN;
                }
                break;

            default:
                return DB_ERROR_UNKNOWN;
            }
            *sqlp += ret;
            *left -= ret;
        }

        switch (db_clause_type(clause)) {
        case DB_CLAUSE_EQUAL:
            if ((ret = snprintf(*sqlp, *left, " %s.%s = ?",
                (db_clause_table(clause) ? db_clause_table(clause) : db_object_table(object)),
                db_clause_field(clause))) >= *left)
            {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_NOT_EQUAL:
            if ((ret = snprintf(*sqlp, *left, " %s.%s != ?",
                (db_clause_table(clause) ? db_clause_table(clause) : db_object_table(object)),
                db_clause_field(clause))) >= *left)
            {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_LESS_THEN:
            if ((ret = snprintf(*sqlp, *left, " %s.%s < ?",
                (db_clause_table(clause) ? db_clause_table(clause) : db_object_table(object)),
                db_clause_field(clause))) >= *left)
            {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_LESS_OR_EQUAL:
            if ((ret = snprintf(*sqlp, *left, " %s.%s <= ?",
                (db_clause_table(clause) ? db_clause_table(clause) : db_object_table(object)),
                db_clause_field(clause))) >= *left)
            {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_GREATER_OR_EQUAL:
            if ((ret = snprintf(*sqlp, *left, " %s.%s >= ?",
                (db_clause_table(clause) ? db_clause_table(clause) : db_object_table(object)),
                db_clause_field(clause))) >= *left)
            {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_GREATER_THEN:
            if ((ret = snprintf(*sqlp, *left, " %s.%s > ?",
                (db_clause_table(clause) ? db_clause_table(clause) : db_object_table(object)),
                db_clause_field(clause))) >= *left)
            {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_IS_NULL:
            if ((ret = snprintf(*sqlp, *left, " %s.%s IS NULL",
                (db_clause_table(clause) ? db_clause_table(clause) : db_object_table(object)),
                db_clause_field(clause))) >= *left)
            {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_IS_NOT_NULL:
            if ((ret = snprintf(*sqlp, *left, " %s.%s IS NOT NULL",
                (db_clause_table(clause) ? db_clause_table(clause) : db_object_table(object)),
                db_clause_field(clause))) >= *left)
            {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_NESTED:
            if ((ret = snprintf(*sqlp, *left, " (")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            *sqlp += ret;
            *left -= ret;
            if (__db_backend_sqlite_build_clause(object, db_clause_list(clause), sqlp, left)) {
                return DB_ERROR_UNKNOWN;
            }
            if ((ret = snprintf(*sqlp, *left, " )")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        default:
            return DB_ERROR_UNKNOWN;
        }
        *sqlp += ret;
        *left -= ret;

        clause = db_clause_next(clause);
    }
    return DB_OK;
}

/**
 * Bind values from the clause list to the SQLite statement, `bind` contains the
 * position of the bind value.
 * \param[in] statement a sqlite3_stmt pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \param[in] bind an integer pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
static int __db_backend_sqlite_bind_clause(sqlite3_stmt* statement, const db_clause_list_t* clause_list, int* bind) {
    const db_clause_t* clause;
    int ret;
    int to_int;
    sqlite3_int64 to_int64;
    db_type_int32_t int32;
    db_type_uint32_t uint32;
    db_type_int64_t int64;
    db_type_uint64_t uint64;

    if (!statement) {
        return DB_ERROR_UNKNOWN;
    }
    if (!clause_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!bind) {
        return DB_ERROR_UNKNOWN;
    }
    if (!*bind) {
        return DB_ERROR_UNKNOWN;
    }

    clause = db_clause_list_begin(clause_list);
    while (clause) {
        switch (db_clause_type(clause)) {
        case DB_CLAUSE_EQUAL:
        case DB_CLAUSE_NOT_EQUAL:
        case DB_CLAUSE_LESS_THEN:
        case DB_CLAUSE_LESS_OR_EQUAL:
        case DB_CLAUSE_GREATER_OR_EQUAL:
        case DB_CLAUSE_GREATER_THEN:
            switch (db_value_type(db_clause_value(clause))) {
            case DB_TYPE_PRIMARY_KEY:
            case DB_TYPE_INT32:
                if (db_value_to_int32(db_clause_value(clause), &int32)) {
                    return DB_ERROR_UNKNOWN;
                }
                to_int = int32;
                ret = sqlite3_bind_int(statement, *bind++, to_int);
                if (ret != SQLITE_OK) {
                    return DB_ERROR_UNKNOWN;
                }
                break;

            case DB_TYPE_UINT32:
                if (db_value_to_uint32(db_clause_value(clause), &uint32)) {
                    return DB_ERROR_UNKNOWN;
                }
                to_int = uint32;
                ret = sqlite3_bind_int(statement, *bind++, to_int);
                if (ret != SQLITE_OK) {
                    return DB_ERROR_UNKNOWN;
                }
                break;

            case DB_TYPE_INT64:
                if (db_value_to_int64(db_clause_value(clause), &int64)) {
                    return DB_ERROR_UNKNOWN;
                }
                to_int64 = int64;
                ret = sqlite3_bind_int64(statement, *bind++, to_int64);
                if (ret != SQLITE_OK) {
                    return DB_ERROR_UNKNOWN;
                }
                break;

            case DB_TYPE_UINT64:
                if (db_value_to_uint64(db_clause_value(clause), &uint64)) {
                    return DB_ERROR_UNKNOWN;
                }
                to_int64 = uint64;
                ret = sqlite3_bind_int64(statement, *bind++, to_int64);
                if (ret != SQLITE_OK) {
                    return DB_ERROR_UNKNOWN;
                }
                break;

            case DB_TYPE_TEXT:
                ret = sqlite3_bind_text(statement, *bind++, db_value_text(db_clause_value(clause)), -1, SQLITE_STATIC);
                if (ret != SQLITE_OK) {
                    return DB_ERROR_UNKNOWN;
                }
                break;

            case DB_TYPE_ENUM:
                if (db_value_enum_value(db_clause_value(clause), &to_int)) {
                    return DB_ERROR_UNKNOWN;
                }
                ret = sqlite3_bind_int(statement, *bind++, to_int);
                if (ret != SQLITE_OK) {
                    return DB_ERROR_UNKNOWN;
                }
                break;

            default:
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_IS_NULL:
        case DB_CLAUSE_IS_NOT_NULL:
            break;

        case DB_CLAUSE_NESTED:
            if (__db_backend_sqlite_bind_clause(statement, db_clause_list(clause), bind)) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        default:
            return DB_ERROR_UNKNOWN;
        }
        clause = db_clause_next(clause);
    }
    return DB_OK;
}

static db_result_t* db_backend_sqlite_next(void* data, int finish) {
    db_backend_sqlite_statement_t* statement = (db_backend_sqlite_statement_t*)data;
    int ret;
    int bind;
    db_result_t* result = NULL;
    db_value_set_t* value_set = NULL;
    const db_object_field_t* object_field;
    int from_int;
    sqlite3_int64 from_int64;
    db_type_int32_t int32;
    db_type_uint32_t uint32;
    db_type_int64_t int64;
    db_type_uint64_t uint64;
    const char* text;

    if (!statement) {
        return NULL;
    }
    if (!statement->object) {
        return NULL;
    }
    if (!statement->statement) {
        return NULL;
    }

    if (finish) {
        sqlite3_finalize(statement->statement);
        mm_alloc_delete(&__sqlite_statement_alloc, statement);
        return NULL;
    }

    ret = sqlite3_step(statement->statement);
    while (ret == SQLITE_BUSY) {
        usleep(100);
        ret = sqlite3_step(statement->statement);
    }
    if (ret != SQLITE_ROW) {
        return NULL;
    }

    if (!(result = db_result_new())
        || !(value_set = db_value_set_new(statement->fields))
        || db_result_set_value_set(result, value_set))
    {
        db_result_free(result);
        db_value_set_free(value_set);
        return NULL;
    }
    object_field = db_object_field_list_begin(db_object_object_field_list(statement->object));
    bind = 0;
    while (object_field) {
        switch (db_object_field_type(object_field)) {
        case DB_TYPE_PRIMARY_KEY:
            from_int = sqlite3_column_int(statement->statement, bind);
            int32 = from_int;
            ret = sqlite3_errcode(statement->backend_sqlite->db);
            if ((ret != SQLITE_OK && ret != SQLITE_ROW && ret != SQLITE_DONE)
                || db_value_from_int32(db_value_set_get(value_set, bind), int32)
                || db_value_set_primary_key(db_value_set_get(value_set, bind)))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        case DB_TYPE_ENUM:
            /*
             * Enum needs to be handled elsewhere since we don't know the
             * enum_set_t here.
             */
        case DB_TYPE_INT32:
            from_int = sqlite3_column_int(statement->statement, bind);
            int32 = from_int;
            ret = sqlite3_errcode(statement->backend_sqlite->db);
            if ((ret != SQLITE_OK && ret != SQLITE_ROW && ret != SQLITE_DONE)
                || db_value_from_int32(db_value_set_get(value_set, bind), int32))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        case DB_TYPE_UINT32:
            from_int = sqlite3_column_int(statement->statement, bind);
            uint32 = from_int;
            ret = sqlite3_errcode(statement->backend_sqlite->db);
            if ((ret != SQLITE_OK && ret != SQLITE_ROW && ret != SQLITE_DONE)
                || db_value_from_uint32(db_value_set_get(value_set, bind), uint32))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        case DB_TYPE_INT64:
            from_int64 = sqlite3_column_int64(statement->statement, bind);
            int64 = from_int64;
            ret = sqlite3_errcode(statement->backend_sqlite->db);
            if ((ret != SQLITE_OK && ret != SQLITE_ROW && ret != SQLITE_DONE)
                || db_value_from_int64(db_value_set_get(value_set, bind), int64))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        case DB_TYPE_UINT64:
            from_int64 = sqlite3_column_int64(statement->statement, bind);
            uint64 = from_int64;
            ret = sqlite3_errcode(statement->backend_sqlite->db);
            if ((ret != SQLITE_OK && ret != SQLITE_ROW && ret != SQLITE_DONE)
                || db_value_from_uint64(db_value_set_get(value_set, bind), uint64))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        case DB_TYPE_TEXT:
            text = (const char*)sqlite3_column_text(statement->statement, bind);
            ret = sqlite3_errcode(statement->backend_sqlite->db);
            if (!text
                || (ret != SQLITE_OK && ret != SQLITE_ROW && ret != SQLITE_DONE)
                || db_value_from_text(db_value_set_get(value_set, bind), text))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        default:
            db_result_free(result);
            return NULL;
        }
        object_field = db_object_field_next(object_field);
        bind++;
    }
    return result;
}

static int db_backend_sqlite_create(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;
    const db_object_field_t* object_field;
    const db_value_t* value;
    char sql[4*1024];
    char* sqlp;
    int ret, left, bind, first;
    sqlite3_stmt* statement = NULL;
    size_t value_pos;
    int to_int;
    sqlite3_int64 to_int64;
    db_type_int32_t int32;
    db_type_uint32_t uint32;
    db_type_int64_t int64;
    db_type_uint64_t uint64;

    if (!__sqlite3_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_sqlite) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object_field_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value_set) {
        return DB_ERROR_UNKNOWN;
    }

    left = sizeof(sql);
    sqlp = sql;

    if ((ret = snprintf(sqlp, left, "INSERT INTO %s (", db_object_table(object))) >= left) {
        return DB_ERROR_UNKNOWN;
    }
    sqlp += ret;
    left -= ret;

    object_field = db_object_field_list_begin(object_field_list);
    first = 1;
    while (object_field) {
        if (first) {
            if ((ret = snprintf(sqlp, left, " %s", db_object_field_name(object_field))) >= left) {
                return DB_ERROR_UNKNOWN;
            }
            first = 0;
        }
        else {
            if ((ret = snprintf(sqlp, left, ", %s", db_object_field_name(object_field))) >= left) {
                return DB_ERROR_UNKNOWN;
            }
        }
        sqlp += ret;
        left -= ret;

        object_field = db_object_field_next(object_field);
    }

    if ((ret = snprintf(sqlp, left, " ) VALUES (")) >= left) {
        return DB_ERROR_UNKNOWN;
    }
    sqlp += ret;
    left -= ret;

    object_field = db_object_field_list_begin(object_field_list);
    first = 1;
    while (object_field) {
        if (first) {
            if ((ret = snprintf(sqlp, left, " ?")) >= left) {
                return DB_ERROR_UNKNOWN;
            }
            first = 0;
        }
        else {
            if ((ret = snprintf(sqlp, left, ", ?")) >= left) {
                return DB_ERROR_UNKNOWN;
            }
        }
        sqlp += ret;
        left -= ret;

        object_field = db_object_field_next(object_field);
    }

    if ((ret = snprintf(sqlp, left, " )")) >= left) {
        return DB_ERROR_UNKNOWN;
    }
    sqlp += ret;
    left -= ret;

    ret = sqlite3_prepare_v2(backend_sqlite->db,
        sql,
        sizeof(sql),
        &statement,
        NULL);
    if (ret != SQLITE_OK) {
        ods_log_info("DB SQL %s", sql);
        ods_log_info("DB Err %d\n", ret);
        if (statement) {
            sqlite3_finalize(statement);
        }
        return DB_ERROR_UNKNOWN;
    }

    bind = 1;
    for (value_pos = 0; value_pos < db_value_set_size(value_set); value_pos++) {
        if (!(value = db_value_set_at(value_set, value_pos))) {
            sqlite3_finalize(statement);
            return DB_ERROR_UNKNOWN;
        }

        switch (db_value_type(value)) {
        case DB_TYPE_PRIMARY_KEY:
        case DB_TYPE_INT32:
            if (db_value_to_int32(value, &int32)) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int = int32;
            ret = sqlite3_bind_int(statement, bind++, to_int);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_UINT32:
            if (db_value_to_uint32(value, &uint32)) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int = uint32;
            ret = sqlite3_bind_int(statement, bind++, to_int);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_INT64:
            if (db_value_to_int64(value, &int64)) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int64 = int64;
            ret = sqlite3_bind_int64(statement, bind++, to_int64);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_UINT64:
            if (db_value_to_uint64(value, &uint64)) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int64 = uint64;
            ret = sqlite3_bind_int64(statement, bind++, to_int64);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_TEXT:
            ret = sqlite3_bind_text(statement, bind++, db_value_text(value), -1, SQLITE_STATIC);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_ENUM:
            if (db_value_enum_value(value, &to_int)) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            ret = sqlite3_bind_int(statement, bind++, to_int);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        default:
            sqlite3_finalize(statement);
            return DB_ERROR_UNKNOWN;
        }
    }

    ret = sqlite3_step(statement);
    while (ret == SQLITE_BUSY) {
        usleep(100);
        ret = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

static db_result_list_t* db_backend_sqlite_read(void* data, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;
    const db_object_field_t* object_field;
    const db_join_t* join;
    char sql[4*1024];
    char* sqlp;
    int ret, left, first, fields, bind;
    db_result_list_t* result_list;
    db_backend_sqlite_statement_t* statement;

    if (!__sqlite3_initialized) {
        return NULL;
    }
    if (!backend_sqlite) {
        return NULL;
    }
    if (!object) {
        return NULL;
    }

    left = sizeof(sql);
    sqlp = sql;

    if ((ret = snprintf(sqlp, left, "SELECT")) >= left) {
        return NULL;
    }
    sqlp += ret;
    left -= ret;

    object_field = db_object_field_list_begin(db_object_object_field_list(object));
    first = 1;
    fields = 0;
    while (object_field) {
        if (first) {
            if ((ret = snprintf(sqlp, left, " %s.%s", db_object_table(object), db_object_field_name(object_field))) >= left) {
                return NULL;
            }
            first = 0;
        }
        else {
            if ((ret = snprintf(sqlp, left, ", %s.%s", db_object_table(object), db_object_field_name(object_field))) >= left) {
                return NULL;
            }
        }
        sqlp += ret;
        left -= ret;

        object_field = db_object_field_next(object_field);
        fields++;
    }

    if ((ret = snprintf(sqlp, left, " FROM %s", db_object_table(object))) >= left) {
        return NULL;
    }
    sqlp += ret;
    left -= ret;

    if (join_list) {
        join = db_join_list_begin(join_list);
        while (join) {
            if ((ret = snprintf(sqlp, left, " INNER JOIN %s ON %s.%s = %s.%s",
                db_join_to_table(join),
                db_join_to_table(join),
                db_join_to_field(join),
                db_join_from_table(join),
                db_join_from_field(join))) >= left)
            {
                return NULL;
            }
            sqlp += ret;
            left -= ret;
            join = db_join_next(join);
        }
    }

    if (clause_list) {
        if (db_clause_list_begin(clause_list)) {
            if ((ret = snprintf(sqlp, left, " WHERE")) >= left) {
                return NULL;
            }
            sqlp += ret;
            left -= ret;
        }
        if (__db_backend_sqlite_build_clause(object, clause_list, &sqlp, &left)) {
            return NULL;
        }
    }

    statement = mm_alloc_new0(&__sqlite_statement_alloc);
    if (!statement) {
        return NULL;
    }
    statement->backend_sqlite = backend_sqlite;
    statement->object = object;
    statement->fields = fields;
    statement->statement = NULL;

    ret = sqlite3_prepare_v2(backend_sqlite->db,
        sql,
        sizeof(sql),
        &(statement->statement),
        NULL);
    if (ret != SQLITE_OK) {
        ods_log_info("DB SQL %s", sql);
        ods_log_info("DB Err %d\n", ret);
        if (statement->statement) {
            sqlite3_finalize(statement->statement);
        }
        mm_alloc_delete(&__sqlite_statement_alloc, statement);
        return NULL;
    }

    if (clause_list) {
        bind = 1;
        if (__db_backend_sqlite_bind_clause(statement->statement, clause_list, &bind)) {
            sqlite3_finalize(statement->statement);
            mm_alloc_delete(&__sqlite_statement_alloc, statement);
            return NULL;
        }
    }

    if (!(result_list = db_result_list_new())
        || db_result_list_set_next(result_list, db_backend_sqlite_next, statement))
    {
        sqlite3_finalize(statement->statement);
        mm_alloc_delete(&__sqlite_statement_alloc, statement);
        return NULL;
    }
    return result_list;
}

static int db_backend_sqlite_update(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;
    const db_object_field_t* object_field;
    const db_value_t* value;
    char sql[4*1024];
    char* sqlp;
    int ret, left, bind, first;
    sqlite3_stmt* statement = NULL;
    size_t value_pos;
    int to_int;
    sqlite3_int64 to_int64;
    db_type_int32_t int32;
    db_type_uint32_t uint32;
    db_type_int64_t int64;
    db_type_uint64_t uint64;

    if (!__sqlite3_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_sqlite) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object_field_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value_set) {
        return DB_ERROR_UNKNOWN;
    }

    left = sizeof(sql);
    sqlp = sql;

    if ((ret = snprintf(sqlp, left, "UPDATE %s SET", db_object_table(object))) >= left) {
        return DB_ERROR_UNKNOWN;
    }
    sqlp += ret;
    left -= ret;

    object_field = db_object_field_list_begin(object_field_list);
    first = 1;
    while (object_field) {
        if (first) {
            if ((ret = snprintf(sqlp, left, " %s = ?", db_object_field_name(object_field))) >= left) {
                return DB_ERROR_UNKNOWN;
            }
            first = 0;
        }
        else {
            if ((ret = snprintf(sqlp, left, ", %s = ?", db_object_field_name(object_field))) >= left) {
                return DB_ERROR_UNKNOWN;
            }
        }
        sqlp += ret;
        left -= ret;

        object_field = db_object_field_next(object_field);
    }

    if (clause_list) {
        if (db_clause_list_begin(clause_list)) {
            if ((ret = snprintf(sqlp, left, " WHERE")) >= left) {
                return DB_ERROR_UNKNOWN;
            }
            sqlp += ret;
            left -= ret;
        }
        if (__db_backend_sqlite_build_clause(object, clause_list, &sqlp, &left)) {
            return DB_ERROR_UNKNOWN;
        }
    }

    ret = sqlite3_prepare_v2(backend_sqlite->db,
        sql,
        sizeof(sql),
        &statement,
        NULL);
    if (ret != SQLITE_OK) {
        ods_log_info("DB SQL %s", sql);
        ods_log_info("DB Err %d\n", ret);
        if (statement) {
            sqlite3_finalize(statement);
        }
        return DB_ERROR_UNKNOWN;
    }

    bind = 1;
    for (value_pos = 0; value_pos < db_value_set_size(value_set); value_pos++) {
        if (!(value = db_value_set_at(value_set, value_pos))) {
            sqlite3_finalize(statement);
            return DB_ERROR_UNKNOWN;
        }

        switch (db_value_type(value)) {
        case DB_TYPE_PRIMARY_KEY:
        case DB_TYPE_INT32:
            if (db_value_to_int32(value, &int32)) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int = int32;
            ret = sqlite3_bind_int(statement, bind++, to_int);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_UINT32:
            if (db_value_to_uint32(value, &uint32)) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int = uint32;
            ret = sqlite3_bind_int(statement, bind++, to_int);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_INT64:
            if (db_value_to_int64(value, &int64)) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int64 = int64;
            ret = sqlite3_bind_int64(statement, bind++, to_int64);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_UINT64:
            if (db_value_to_uint64(value, &uint64)) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int64 = uint64;
            ret = sqlite3_bind_int64(statement, bind++, to_int64);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_TEXT:
            ret = sqlite3_bind_text(statement, bind++, db_value_text(value), -1, SQLITE_STATIC);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_ENUM:
            if (db_value_enum_value(value, &to_int)) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            ret = sqlite3_bind_int(statement, bind++, to_int);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        default:
            sqlite3_finalize(statement);
            return DB_ERROR_UNKNOWN;
        }
    }

    if (clause_list) {
        if (__db_backend_sqlite_bind_clause(statement, clause_list, &bind)) {
            sqlite3_finalize(statement);
            return DB_ERROR_UNKNOWN;
        }
    }

    ret = sqlite3_step(statement);
    while (ret == SQLITE_BUSY) {
        usleep(100);
        ret = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

static int db_backend_sqlite_delete(void* data, const db_object_t* object, const db_clause_list_t* clause_list) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;
    char sql[4*1024];
    char* sqlp;
    int ret, left, bind;
    sqlite3_stmt* statement = NULL;

    if (!__sqlite3_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_sqlite) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }

    left = sizeof(sql);
    sqlp = sql;

    if ((ret = snprintf(sqlp, left, "DELETE FROM %s", db_object_table(object))) >= left) {
        return DB_ERROR_UNKNOWN;
    }
    sqlp += ret;
    left -= ret;

    if (clause_list) {
        if (db_clause_list_begin(clause_list)) {
            if ((ret = snprintf(sqlp, left, " WHERE")) >= left) {
                return DB_ERROR_UNKNOWN;
            }
            sqlp += ret;
            left -= ret;
        }
        if (__db_backend_sqlite_build_clause(object, clause_list, &sqlp, &left)) {
            return DB_ERROR_UNKNOWN;
        }
    }

    ret = sqlite3_prepare_v2(backend_sqlite->db,
        sql,
        sizeof(sql),
        &statement,
        NULL);
    if (ret != SQLITE_OK) {
        ods_log_info("DB SQL %s", sql);
        ods_log_info("DB Err %d\n", ret);
        if (statement) {
            sqlite3_finalize(statement);
        }
        return DB_ERROR_UNKNOWN;
    }

    if (clause_list) {
        bind = 1;
        if (__db_backend_sqlite_bind_clause(statement, clause_list, &bind)) {
            sqlite3_finalize(statement);
            return DB_ERROR_UNKNOWN;
        }
    }

    ret = sqlite3_step(statement);
    while (ret == SQLITE_BUSY) {
        usleep(100);
        ret = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

static void db_backend_sqlite_free(void* data) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

    if (backend_sqlite) {
        if (backend_sqlite->db) {
            (void)db_backend_sqlite_disconnect(backend_sqlite);
        }
        mm_alloc_delete(&__sqlite_alloc, backend_sqlite);
    }
}

static int db_backend_sqlite_transaction_begin(void* data) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;
    static const char* sql = "BEGIN TRANSACTION";
    int ret;
    sqlite3_stmt* statement = NULL;

    if (!__sqlite3_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_sqlite) {
        return DB_ERROR_UNKNOWN;
    }
    if (backend_sqlite->transaction) {
        return DB_ERROR_UNKNOWN;
    }

    ret = sqlite3_prepare_v2(backend_sqlite->db,
        sql,
        sizeof(sql),
        &statement,
        NULL);
    if (ret != SQLITE_OK) {
        ods_log_info("DB SQL %s", sql);
        ods_log_info("DB Err %d\n", ret);
        if (statement) {
            sqlite3_finalize(statement);
        }
        return DB_ERROR_UNKNOWN;
    }

    ret = sqlite3_step(statement);
    while (ret == SQLITE_BUSY) {
        usleep(100);
        ret = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        return DB_ERROR_UNKNOWN;
    }

    backend_sqlite->transaction = 1;
    return DB_OK;
}

static int db_backend_sqlite_transaction_commit(void* data) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;
    static const char* sql = "COMMIT TRANSACTION";
    int ret;
    sqlite3_stmt* statement = NULL;

    if (!__sqlite3_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_sqlite) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_sqlite->transaction) {
        return DB_ERROR_UNKNOWN;
    }

    ret = sqlite3_prepare_v2(backend_sqlite->db,
        sql,
        sizeof(sql),
        &statement,
        NULL);
    if (ret != SQLITE_OK) {
        ods_log_info("DB SQL %s", sql);
        ods_log_info("DB Err %d\n", ret);
        if (statement) {
            sqlite3_finalize(statement);
        }
        return DB_ERROR_UNKNOWN;
    }

    ret = sqlite3_step(statement);
    while (ret == SQLITE_BUSY) {
        usleep(100);
        ret = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        return DB_ERROR_UNKNOWN;
    }

    backend_sqlite->transaction = 0;
    return DB_OK;
}

static int db_backend_sqlite_transaction_rollback(void* data) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;
    static const char* sql = "ROLLBACK TRANSACTION";
    int ret;
    sqlite3_stmt* statement = NULL;

    if (!__sqlite3_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_sqlite) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_sqlite->transaction) {
        return DB_ERROR_UNKNOWN;
    }

    ret = sqlite3_prepare_v2(backend_sqlite->db,
        sql,
        sizeof(sql),
        &statement,
        NULL);
    if (ret != SQLITE_OK) {
        ods_log_info("DB SQL %s", sql);
        ods_log_info("DB Err %d\n", ret);
        if (statement) {
            sqlite3_finalize(statement);
        }
        return DB_ERROR_UNKNOWN;
    }

    ret = sqlite3_step(statement);
    while (ret == SQLITE_BUSY) {
        usleep(100);
        ret = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        return DB_ERROR_UNKNOWN;
    }

    backend_sqlite->transaction = 0;
    return DB_OK;
}

db_backend_handle_t* db_backend_sqlite_new_handle(void) {
    db_backend_handle_t* backend_handle = NULL;
    db_backend_sqlite_t* backend_sqlite =
        (db_backend_sqlite_t*)mm_alloc_new0(&__sqlite_alloc);

    if (backend_sqlite && (backend_handle = db_backend_handle_new())) {
        if (db_backend_handle_set_data(backend_handle, (void*)backend_sqlite)
            || db_backend_handle_set_initialize(backend_handle, db_backend_sqlite_initialize)
            || db_backend_handle_set_shutdown(backend_handle, db_backend_sqlite_shutdown)
            || db_backend_handle_set_connect(backend_handle, db_backend_sqlite_connect)
            || db_backend_handle_set_disconnect(backend_handle, db_backend_sqlite_disconnect)
            || db_backend_handle_set_create(backend_handle, db_backend_sqlite_create)
            || db_backend_handle_set_read(backend_handle, db_backend_sqlite_read)
            || db_backend_handle_set_update(backend_handle, db_backend_sqlite_update)
            || db_backend_handle_set_delete(backend_handle, db_backend_sqlite_delete)
            || db_backend_handle_set_free(backend_handle, db_backend_sqlite_free)
            || db_backend_handle_set_transaction_begin(backend_handle, db_backend_sqlite_transaction_begin)
            || db_backend_handle_set_transaction_commit(backend_handle, db_backend_sqlite_transaction_commit)
            || db_backend_handle_set_transaction_rollback(backend_handle, db_backend_sqlite_transaction_rollback))
        {
            db_backend_handle_free(backend_handle);
            mm_alloc_delete(&__sqlite_alloc, backend_sqlite);
            return NULL;
        }
    }
    return backend_handle;
}
