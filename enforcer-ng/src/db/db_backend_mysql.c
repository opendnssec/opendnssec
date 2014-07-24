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

#include "db_backend_mysql.h"
#include "db_error.h"

#include "mm.h"
#include "shared/log.h"

#include <mysql/mysql.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>

static int db_backend_mysql_transaction_rollback(void*);

/**
 * Keep track of if we have initialized the MySQL backend.
 */
static int __mysql_initialized = 0;

/**
 * The MySQL database backend specific data.
 */
typedef struct db_backend_mysql {
    MYSQL* db;
    int transaction;
    unsigned int timeout;
} db_backend_mysql_t;

static mm_alloc_t __mysql_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_backend_mysql_t));

/**
 * The MySQL database backend specific data for a statement bind.
 */
typedef struct db_backend_mysql_bind db_backend_mysql_bind_t;
struct db_backend_mysql_bind {
    db_backend_mysql_bind_t* next;
    MYSQL_BIND* bind;
    unsigned long length;
    my_bool error;
    int value_enum;
};

static mm_alloc_t __mysql_bind_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_backend_mysql_bind_t));

/**
 * The MySQL database backend specific data for statements.
 */
typedef struct db_backend_mysql_statement {
    db_backend_mysql_t* backend_mysql;
    MYSQL_STMT* statement;
    MYSQL_BIND* mysql_bind_input;
    db_backend_mysql_bind_t* bind_input;
    MYSQL_BIND* mysql_bind_output;
    db_backend_mysql_bind_t* bind_output;
} db_backend_mysql_statement_t;

static mm_alloc_t __mysql_statement_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_backend_mysql_statement_t));

static inline void __db_backend_mysql_finish(db_backend_mysql_statement_t* statement) {
    db_backend_mysql_bind_t* bind;

    if (!statement) {
        return;
    }

    if (statement->statement) {
        mysql_stmt_close(statement->statement);
    }
    if (statement->mysql_bind_input) {
        free(statement->mysql_bind_input);
    }
    while (statement->bind_input) {
        bind = statement->bind_input;
        statement->bind_input = bind->next;
        mm_alloc_delete(__mysql_bind_alloc, bind);
    }
    while (statement->bind_output) {
        bind = statement->bind_output;
        statement->bind_output = bind->next;
        if (bind->bind && bind->bind->buffer) {
            free(bind->bind->buffer);
        }
        mm_alloc_delete(__mysql_bind_alloc, bind);
    }
    if (statement->mysql_bind_output) {
        free(statement->mysql_bind_output);
    }

    mm_alloc_delete(__mysql_statement_alloc, statement);
}

/**
 * MySQL prepare function.
 */
static inline int __db_backend_mysql_prepare(db_backend_mysql_t* backend_mysql, db_backend_mysql_statement_t** statement, const char* sql, size_t size, const db_object_t* object) {
    unsigned long i, size;
    db_backend_mysql_bind_t* bind;
    const db_object_field_list_t* object_field_list;
    const db_object_field_t* object_field;
    MYSQL_BIND* mysql_bind;
    MYSQL_RES* result_metadata;
    MYSQL_FIELD* field;

    if (!backend_mysql) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql->db) {
        return DB_ERROR_UNKNOWN;
    }
    if (!statement) {
        return DB_ERROR_UNKNOWN;
    }
    if (*statement) {
        return DB_ERROR_UNKNOWN;
    }
    if (!sql) {
        return DB_ERROR_UNKNOWN;
    }

    ods_log_debug("%s", sql);
    if (!(*statement = mm_alloc_new0(__mysql_statement_alloc))
        || !((*statement)->statement = mysql_stmt_init(backend_mysql->db))
        || mysql_stmt_prepare((*statement)->statement, sql, size))
    {
        if ((*statement)->statement) {
            ods_log_info("DB prepare SQL %s", sql);
            ods_log_info("DB prepare Err %d: %s\n", mysql_stmt_errno((*statement)->statement), mysql_stmt_error((*statement)->statement));
        }
        __db_backend_mysql_finish(*statement);
        *statement = NULL;
        return DB_ERROR_UNKNOWN;
    }

    (*statement)->backend_mysql = backend_mysql;

    if ((size = mysql_stmt_param_count((*statement)->statement)) > 0) {
        if (!((*statement)->mysql_bind_input = calloc(size, sizeof(MYSQL_BIND)))) {
            __db_backend_mysql_finish(*statement);
            *statement = NULL;
            return DB_ERROR_UNKNOWN;
        }

        for (i = 0; i < size; i++) {
            if (!(bind = mm_alloc_new0(__mysql_bind_alloc))) {
                __db_backend_mysql_finish(*statement);
                *statement = NULL;
                return DB_ERROR_UNKNOWN;
            }

            bind->bind = (*statement)->mysql_bind_input[i];
            bind->next = (*statement)->bind_input;
            (*statement)->bind_input = bind;
        }
    }

    if (object
        && (result_metadata = mysql_stmt_result_metadata((*statement)->statement))
        && (size = db_object_field_list_size((object_field_list = db_object_object_field_list(object)))) > 0)
    {
        if (!((*statement)->mysql_bind_output = calloc(size, sizeof(MYSQL_BIND)))) {
            mysql_free_result(result_metadata);
            __db_backend_mysql_finish(*statement);
            *statement = NULL;
            return DB_ERROR_UNKNOWN;
        }

        field = mysql_fetch_field(result_metadata);
        object_field = db_object_field_list_begin(object_field_list);
        for (i = 0; i < size; i++) {
            if (!field
                || !object_field
                || !(bind = mm_alloc_new0(__mysql_bind_alloc)))
            {
                mysql_free_result(result_metadata);
                __db_backend_mysql_finish(*statement);
                *statement = NULL;
                return DB_ERROR_UNKNOWN;
            }

            bind->bind = (mysql_bind = (*statement)->mysql_bind_output[i]);

            switch (db_object_field_type(object_field)) {
            case DB_TYPE_PRIMARY_KEY:
                switch (field->type) {
                case MYSQL_TYPE_TINY:
                case MYSQL_TYPE_SHORT:
                case MYSQL_TYPE_LONG:
                case MYSQL_TYPE_INT24:
                    mysql_bind->buffer_type = MYSQL_TYPE_LONG;
                    if (!(mysql_bind->buffer = calloc(sizeof(db_type_uint32_t)))) {
                        mysql_free_result(result_metadata);
                        __db_backend_mysql_finish(*statement);
                        *statement = NULL;
                        return DB_ERROR_UNKNOWN;
                    }
                    mysql_bind->buffer_length = sizeof(db_type_uint32_t);
                    bind->length = mysql_bind->buffer_length;
                    mysql_bind->length = &bind->length;
                    mysql_bind->is_null = (my_bool*)0;
                    mysql_bind->is_unsigned = 1;
                    mysql_bind->error = &bind->error;
                    break;

                case MYSQL_TYPE_LONGLONG:
                    mysql_bind->buffer_type = MYSQL_TYPE_LONGLONG;
                    if (!(mysql_bind->buffer = calloc(sizeof(db_type_uint64_t)))) {
                        mysql_free_result(result_metadata);
                        __db_backend_mysql_finish(*statement);
                        *statement = NULL;
                        return DB_ERROR_UNKNOWN;
                    }
                    mysql_bind->buffer_length = sizeof(db_type_uint64_t);
                    bind->length = mysql_bind->buffer_length;
                    mysql_bind->length = &bind->length;
                    mysql_bind->is_null = (my_bool*)0;
                    mysql_bind->is_unsigned = 1;
                    mysql_bind->error = &bind->error;
                    break;

                case MYSQL_TYPE_STRING:
                case MYSQL_TYPE_VAR_STRING:
                    mysql_bind->buffer_type = MYSQL_TYPE_STRING;
                    if (field->length < 1
                        || !(mysql_bind->buffer = calloc(field->length)))
                    {
                        mysql_free_result(result_metadata);
                        __db_backend_mysql_finish(*statement);
                        *statement = NULL;
                        return DB_ERROR_UNKNOWN;
                    }
                    mysql_bind->buffer_length = field->length;
                    bind->length = mysql_bind->buffer_length;
                    mysql_bind->length = &bind->length;
                    mysql_bind->is_null = (my_bool*)0;
                    mysql_bind->is_unsigned = 0;
                    mysql_bind->error = &bind->error;
                    break;

                default:
                    mysql_free_result(result_metadata);
                    __db_backend_mysql_finish(*statement);
                    *statement = NULL;
                    return DB_ERROR_UNKNOWN;
                }
                break;

            case DB_TYPE_ENUM:
                /*
                 * Enum needs to be handled elsewhere since we don't know the
                 * enum_set_t here.
                 */
            case DB_TYPE_INT32:
                mysql_bind->buffer_type = MYSQL_TYPE_LONG;
                if (!(mysql_bind->buffer = calloc(sizeof(db_type_int32_t)))) {
                    mysql_free_result(result_metadata);
                    __db_backend_mysql_finish(*statement);
                    *statement = NULL;
                    return DB_ERROR_UNKNOWN;
                }
                mysql_bind->buffer_length = sizeof(db_type_int32_t);
                bind->length = mysql_bind->buffer_length;
                mysql_bind->length = &bind->length;
                mysql_bind->is_null = (my_bool*)0;
                mysql_bind->is_unsigned = 0;
                mysql_bind->error = &bind->error;
                break;

            case DB_TYPE_UINT32:
                mysql_bind->buffer_type = MYSQL_TYPE_LONG;
                if (!(mysql_bind->buffer = calloc(sizeof(db_type_uint32_t)))) {
                    mysql_free_result(result_metadata);
                    __db_backend_mysql_finish(*statement);
                    *statement = NULL;
                    return DB_ERROR_UNKNOWN;
                }
                mysql_bind->buffer_length = sizeof(db_type_uint32_t);
                bind->length = mysql_bind->buffer_length;
                mysql_bind->length = &bind->length;
                mysql_bind->is_null = (my_bool*)0;
                mysql_bind->is_unsigned = 1;
                mysql_bind->error = &bind->error;
                break;

            case DB_TYPE_INT64:
                mysql_bind->buffer_type = MYSQL_TYPE_LONGLONG;
                if (!(mysql_bind->buffer = calloc(sizeof(db_type_int64_t)))) {
                    mysql_free_result(result_metadata);
                    __db_backend_mysql_finish(*statement);
                    *statement = NULL;
                    return DB_ERROR_UNKNOWN;
                }
                mysql_bind->buffer_length = sizeof(db_type_int64_t);
                bind->length = mysql_bind->buffer_length;
                mysql_bind->length = &bind->length;
                mysql_bind->is_null = (my_bool*)0;
                mysql_bind->is_unsigned = 0;
                mysql_bind->error = &bind->error;
                break;

            case DB_TYPE_UINT64:
                mysql_bind->buffer_type = MYSQL_TYPE_LONGLONG;
                if (!(mysql_bind->buffer = calloc(sizeof(db_type_uint64_t)))) {
                    mysql_free_result(result_metadata);
                    __db_backend_mysql_finish(*statement);
                    *statement = NULL;
                    return DB_ERROR_UNKNOWN;
                }
                mysql_bind->buffer_length = sizeof(db_type_uint64_t);
                bind->length = mysql_bind->buffer_length;
                mysql_bind->length = &bind->length;
                mysql_bind->is_null = (my_bool*)0;
                mysql_bind->is_unsigned = 1;
                mysql_bind->error = &bind->error;
                break;

            case DB_TYPE_TEXT:
                mysql_bind->buffer_type = MYSQL_TYPE_STRING;
                if (field->length < 1
                    || !(mysql_bind->buffer = calloc(field->length)))
                {
                    mysql_free_result(result_metadata);
                    __db_backend_mysql_finish(*statement);
                    *statement = NULL;
                    return DB_ERROR_UNKNOWN;
                }
                mysql_bind->buffer_length = field->length;
                bind->length = mysql_bind->buffer_length;
                mysql_bind->length = &bind->length;
                mysql_bind->is_null = (my_bool*)0;
                mysql_bind->is_unsigned = 0;
                mysql_bind->error = &bind->error;
                break;

            case DB_TYPE_ANY:
            case DB_TYPE_REVISION:
                switch (field->type) {
                case MYSQL_TYPE_TINY:
                case MYSQL_TYPE_SHORT:
                case MYSQL_TYPE_LONG:
                case MYSQL_TYPE_INT24:
                    mysql_bind->buffer_type = MYSQL_TYPE_LONG;
                    if (field->flags & UNSIGNED_FLAG) {
                        if (!(mysql_bind->buffer = calloc(sizeof(db_type_uint32_t)))) {
                            mysql_free_result(result_metadata);
                            __db_backend_mysql_finish(*statement);
                            *statement = NULL;
                            return DB_ERROR_UNKNOWN;
                        }
                        mysql_bind->buffer_length = sizeof(db_type_uint32_t);
                        mysql_bind->is_unsigned = 1;
                    }
                    else {
                        if (!(mysql_bind->buffer = calloc(sizeof(db_type_int32_t)))) {
                            mysql_free_result(result_metadata);
                            __db_backend_mysql_finish(*statement);
                            *statement = NULL;
                            return DB_ERROR_UNKNOWN;
                        }
                        mysql_bind->buffer_length = sizeof(db_type_int32_t);
                        mysql_bind->is_unsigned = 0;
                    }
                    bind->length = mysql_bind->buffer_length;
                    mysql_bind->length = &bind->length;
                    mysql_bind->is_null = (my_bool*)0;
                    mysql_bind->error = &bind->error;
                    break;

                case MYSQL_TYPE_LONGLONG:
                    mysql_bind->buffer_type = MYSQL_TYPE_LONGLONG;
                    if (field->flags & UNSIGNED_FLAG) {
                        if (!(mysql_bind->buffer = calloc(sizeof(db_type_uint64_t)))) {
                            mysql_free_result(result_metadata);
                            __db_backend_mysql_finish(*statement);
                            *statement = NULL;
                            return DB_ERROR_UNKNOWN;
                        }
                        mysql_bind->buffer_length = sizeof(db_type_uint64_t);
                        mysql_bind->is_unsigned = 1;
                    }
                    else {
                        if (!(mysql_bind->buffer = calloc(sizeof(db_type_int64_t)))) {
                            mysql_free_result(result_metadata);
                            __db_backend_mysql_finish(*statement);
                            *statement = NULL;
                            return DB_ERROR_UNKNOWN;
                        }
                        mysql_bind->buffer_length = sizeof(db_type_int64_t);
                        mysql_bind->is_unsigned = 0;
                    }
                    bind->length = mysql_bind->buffer_length;
                    mysql_bind->length = &bind->length;
                    mysql_bind->is_null = (my_bool*)0;
                    mysql_bind->error = &bind->error;
                    break;

                case MYSQL_TYPE_STRING:
                case MYSQL_TYPE_VAR_STRING:
                    mysql_bind->buffer_type = MYSQL_TYPE_STRING;
                    if (field->length < 1
                        || !(mysql_bind->buffer = calloc(field->length)))
                    {
                        mysql_free_result(result_metadata);
                        __db_backend_mysql_finish(*statement);
                        *statement = NULL;
                        return DB_ERROR_UNKNOWN;
                    }
                    mysql_bind->buffer_length = field->length;
                    bind->length = mysql_bind->buffer_length;
                    mysql_bind->length = &bind->length;
                    mysql_bind->is_null = (my_bool*)0;
                    mysql_bind->is_unsigned = 0;
                    mysql_bind->error = &bind->error;
                    break;

                default:
                    mysql_free_result(result_metadata);
                    __db_backend_mysql_finish(*statement);
                    *statement = NULL;
                    return DB_ERROR_UNKNOWN;
                }
                break;

            default:
                return NULL;
            }

            bind->next = (*statement)->bind_output;
            (*statement)->bind_output = bind;
            object_field = db_object_field_next(object_field);
        }
        if (object_field) {
            mysql_free_result(result_metadata);
            __db_backend_mysql_finish(*statement);
            *statement = NULL;
            return DB_ERROR_UNKNOWN;
        }
    }
    if (result_metadata) {
        mysql_free_result(result_metadata);
    }

    return DB_OK;
}

static int db_backend_mysql_initialize(void* data) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;

    if (!backend_mysql) {
        return DB_ERROR_UNKNOWN;
    }

    if (!__mysql_initialized) {
        if (mysql_library_init()) {
            return DB_ERROR_UNKNOWN;
        }
        __mysql_initialized = 1;
    }
    return DB_OK;
}

static int db_backend_mysql_shutdown(void* data) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;

    if (!backend_mysql) {
        return DB_ERROR_UNKNOWN;
    }

    if (__mysql_initialized) {
        mysql_library_end();
        __mysql_initialized = 0;
    }
    return DB_OK;
}

static int db_backend_mysql_connect(void* data, const db_configuration_list_t* configuration_list) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;
    const db_configuration_t* host;
    const db_configuration_t* user;
    const db_configuration_t* pass;
    const db_configuration_t* db;
    const db_configuration_t* port_configuration;
    const db_configuration_t* timeout;
    int ret, timeout;
    unsigned int port = 0;

    if (!__mysql_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql) {
        return DB_ERROR_UNKNOWN;
    }
    if (backend_mysql->db) {
        return DB_ERROR_UNKNOWN;
    }
    if (!configuration_list) {
        return DB_ERROR_UNKNOWN;
    }

    host = db_configuration_list_find(configuration_list, "host");
    user = db_configuration_list_find(configuration_list, "user");
    pass = db_configuration_list_find(configuration_list, "pass");
    db = db_configuration_list_find(configuration_list, "db");
    port_configuration = db_configuration_list_find(configuration_list, "port");
    if (port_configuration) {
        port = atoi(db_configuration_value(port_configuration));
    }

    backend_mysql->timeout = DB_BACKEND_MYSQL_DEFAULT_TIMEOUT;
    if ((timeout = db_configuration_list_find(configuration_list, "timeout"))) {
        timeout = atoi(db_configuration_value(timeout));
        if (timeout < 1) {
            backend_mysql->timeout = DB_BACKEND_MYSQL_DEFAULT_TIMEOUT;
        }
        else {
            backend_mysql->timeout = (unsigned int)timeout;
        }
    }

    if (!(backend_mysql->db = mysql_init(NULL))
        || mysql_options(backend_mysql->db, MYSQL_OPT_CONNECT_TIMEOUT, &backend_mysql->timeout)
        || mysql_real_connect(backend_mysql->db,
            (host ? db_configuration_value(host) : NULL),
            (user ? db_configuration_value(user) : NULL),
            (pass ? db_configuration_value(pass) : NULL),
            (db ? db_configuration_value(db) : NULL),
            port,
            NULL,
            0))
    {
        if (backend_mysql->db) {
            ods_log_error("db_backend_mysql: connect failed %d: %s", mysql_errno(backend_mysql->db), mysql_error(backend_mysql->db));
            mysql_close(backend_mysql->db);
            backend_mysql->db = NULL;
        }
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

static int db_backend_mysql_disconnect(void* data) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;
    int ret;

    if (!__mysql_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql->db) {
        return DB_ERROR_UNKNOWN;
    }

    if (backend_mysql->transaction) {
        db_backend_mysql_transaction_rollback(backend_mysql);
    }

    mysql_close(backend_mysql->db);
    backend_mysql->db = NULL;

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
static int __db_backend_mysql_build_clause(const db_object_t* object, const db_clause_list_t* clause_list, char** sqlp, int* left) {
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
            if (__db_backend_mysql_build_clause(object, db_clause_list(clause), sqlp, left)) {
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
 * Bind values from the clause list to a MySQL bind structure.
 * TODO
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
static int __db_backend_mysql_bind_clause(db_backend_mysql_bind_t** bind, const db_clause_list_t* clause_list) {
    const db_clause_t* clause;
    int ret;
    const db_type_int32_t* int32;
    const db_type_uint32_t* uint32;
    const db_type_int64_t* int64;
    const db_type_uint64_t* uint64;
    const char* text;

    if (!bind) {
        return DB_ERROR_UNKNOWN;
    }
    if (!*bind) {
        return DB_ERROR_UNKNOWN;
    }
    if (!clause_list) {
        return DB_ERROR_UNKNOWN;
    }

    clause = db_clause_list_begin(clause_list);
    while (clause) {
        if (!*bind) {
            return DB_ERROR_UNKNOWN;
        }

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
                if (!(int32 = db_value_int32(db_clause_value(clause)))) {
                    return DB_ERROR_UNKNOWN;
                }
                *bind->bind->buffer_type = MYSQL_TYPE_LONG;
                *bind->bind->buffer = (void*)int32;
                *bind->bind->buffer_length = sizeof(db_type_int32_t);
                *bind->bind->length = &(*bind->bind->buffer_length);
                *bind->bind->is_null = (my_bool*)0;
                *bind->bind->is_unsigned = 0;
                *bind_pos++;
                break;

            case DB_TYPE_UINT32:
                if (!(uint32 = db_value_uint32(db_clause_value(clause)))) {
                    return DB_ERROR_UNKNOWN;
                }
                *bind->bind->buffer_type = MYSQL_TYPE_LONG;
                *bind->bind->buffer = (void*)uint32;
                *bind->bind->buffer_length = sizeof(db_type_uint32_t);
                *bind->bind->length = &(*bind->bind->buffer_length);
                *bind->bind->is_null = (my_bool*)0;
                *bind->bind->is_unsigned = 1;
                break;

            case DB_TYPE_INT64:
                if (!(int64 = db_value_int64(db_clause_value(clause)))) {
                    return DB_ERROR_UNKNOWN;
                }
                *bind->bind->buffer_type = MYSQL_TYPE_LONGLONG;
                *bind->bind->buffer = (void*)int64;
                *bind->bind->buffer_length = sizeof(db_type_int64_t);
                *bind->bind->length = &(*bind->bind->buffer_length);
                *bind->bind->is_null = (my_bool*)0;
                *bind->bind->is_unsigned = 0;
                break;

            case DB_TYPE_UINT64:
                if (!(uint64 = db_value_uint64(db_clause_value(clause)))) {
                    return DB_ERROR_UNKNOWN;
                }
                *bind->bind->buffer_type = MYSQL_TYPE_LONGLONG;
                *bind->bind->buffer = (void*)uint64;
                *bind->bind->buffer_length = sizeof(db_type_uint64_t);
                *bind->bind->length = &(*bind->bind->buffer_length);
                *bind->bind->is_null = (my_bool*)0;
                *bind->bind->is_unsigned = 1;
                break;

            case DB_TYPE_TEXT:
                if (!(text = db_value_text(db_clause_value(clause)))) {
                    return DB_ERROR_UNKNOWN;
                }
                *bind->bind->buffer_type = MYSQL_TYPE_STRING;
                *bind->bind->buffer = (void*)text;
                *bind->bind->buffer_length = strlen(text);
                *bind->bind->length = &(*bind->bind->buffer_length);
                *bind->bind->is_null = (my_bool*)0;
                *bind->bind->is_unsigned = 0;
                break;

            case DB_TYPE_ENUM:
                if (db_value_enum_value(db_clause_value(clause), &(*bind->value_enum))) {
                    return DB_ERROR_UNKNOWN;
                }
                *bind->bind->buffer_type = MYSQL_TYPE_LONG;
                *bind->bind->buffer = (void*)&(*bind->value_enum);
                *bind->bind->buffer_length = sizeof(int);
                *bind->bind->length = &(*bind->bind->buffer_length);
                *bind->bind->is_null = (my_bool*)0;
                *bind->bind->is_unsigned = 0;
                break;

            default:
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_IS_NULL:
            /* TODO: is null */
            break;

        case DB_CLAUSE_IS_NOT_NULL:
            /* TODO: is not null */
            break;

        case DB_CLAUSE_NESTED:
            *bind = *bind->next;
            if (__db_backend_mysql_bind_clause(bind, db_clause_list(clause))) {
                return DB_ERROR_UNKNOWN;
            }
            clause = db_clause_next(clause);
            continue;

        default:
            return DB_ERROR_UNKNOWN;
        }

        *bind = *bind->next;
        clause = db_clause_next(clause);
    }
    return DB_OK;
}

static db_result_t* db_backend_mysql_next(void* data, int finish) {
    db_backend_mysql_statement_t* statement = (db_backend_mysql_statement_t*)data;
    int ret;
    int bind;
    db_result_t* result = NULL;
    db_value_set_t* value_set = NULL;
    const db_object_field_t* object_field;
    int from_int;
    mysql_int64 from_int64;
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
        __db_backend_mysql_finish(statement->statement);
        mm_alloc_delete(&__mysql_statement_alloc, statement);
        return NULL;
    }

    if (__db_backend_mysql_step(statement->backend_mysql, statement->statement) != MYSQL_ROW) {
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
            from_int = mysql_column_int(statement->statement, bind);
            int32 = from_int;
            ret = mysql_errcode(statement->backend_mysql->db);
            if ((ret != MYSQL_OK && ret != MYSQL_ROW && ret != MYSQL_DONE)
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
            from_int = mysql_column_int(statement->statement, bind);
            int32 = from_int;
            ret = mysql_errcode(statement->backend_mysql->db);
            if ((ret != MYSQL_OK && ret != MYSQL_ROW && ret != MYSQL_DONE)
                || db_value_from_int32(db_value_set_get(value_set, bind), int32))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        case DB_TYPE_UINT32:
            from_int = mysql_column_int(statement->statement, bind);
            uint32 = from_int;
            ret = mysql_errcode(statement->backend_mysql->db);
            if ((ret != MYSQL_OK && ret != MYSQL_ROW && ret != MYSQL_DONE)
                || db_value_from_uint32(db_value_set_get(value_set, bind), uint32))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        case DB_TYPE_INT64:
            from_int64 = mysql_column_int64(statement->statement, bind);
            int64 = from_int64;
            ret = mysql_errcode(statement->backend_mysql->db);
            if ((ret != MYSQL_OK && ret != MYSQL_ROW && ret != MYSQL_DONE)
                || db_value_from_int64(db_value_set_get(value_set, bind), int64))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        case DB_TYPE_UINT64:
            from_int64 = mysql_column_int64(statement->statement, bind);
            uint64 = from_int64;
            ret = mysql_errcode(statement->backend_mysql->db);
            if ((ret != MYSQL_OK && ret != MYSQL_ROW && ret != MYSQL_DONE)
                || db_value_from_uint64(db_value_set_get(value_set, bind), uint64))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        case DB_TYPE_TEXT:
            text = (const char*)mysql_column_text(statement->statement, bind);
            ret = mysql_errcode(statement->backend_mysql->db);
            if (!text
                || (ret != MYSQL_OK && ret != MYSQL_ROW && ret != MYSQL_DONE)
                || db_value_from_text(db_value_set_get(value_set, bind), text))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        case DB_TYPE_ANY:
        case DB_TYPE_REVISION:
            switch (mysql_column_type(statement->statement, bind)) {
            case MYSQL_INTEGER:
                from_int64 = mysql_column_int64(statement->statement, bind);
                int64 = from_int64;
                ret = mysql_errcode(statement->backend_mysql->db);
                if ((ret != MYSQL_OK && ret != MYSQL_ROW && ret != MYSQL_DONE)
                    || db_value_from_int64(db_value_set_get(value_set, bind), int64))
                {
                    db_result_free(result);
                    return NULL;
                }
                break;

            case MYSQL_TEXT:
                text = (const char*)mysql_column_text(statement->statement, bind);
                ret = mysql_errcode(statement->backend_mysql->db);
                if (!text
                    || (ret != MYSQL_OK && ret != MYSQL_ROW && ret != MYSQL_DONE)
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

static int db_backend_mysql_create(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;
    const db_object_field_t* object_field;
    const db_object_field_t* revision_field = NULL;
    const db_value_t* value;
    char sql[4*1024];
    char* sqlp;
    int ret, left, bind, first;
    MYSQL_STMT* statement = NULL;
    size_t value_pos;
    int to_int;
    mysql_int64 to_int64;
    db_type_int32_t int32;
    db_type_uint32_t uint32;
    db_type_int64_t int64;
    db_type_uint64_t uint64;

    if (!__mysql_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql) {
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

    /*
     * Check if the object has a revision field and keep it for later use.
     */
    object_field = db_object_field_list_begin(db_object_object_field_list(object));
    while (object_field) {
        if (db_object_field_type(object_field) == DB_TYPE_REVISION) {
            if (revision_field) {
                /*
                 * We do not support multiple revision fields.
                 */
                return DB_ERROR_UNKNOWN;
            }

            revision_field = object_field;
        }
        object_field = db_object_field_next(object_field);
    }

    left = sizeof(sql);
    sqlp = sql;

    if (!db_object_field_list_begin(object_field_list) && !revision_field) {
        /*
         * Special case when tables has no fields except maybe a primary key.
         */
        if ((ret = snprintf(sqlp, left, "INSERT INTO %s DEFAULT VALUES", db_object_table(object))) >= left) {
            return DB_ERROR_UNKNOWN;
        }
        sqlp += ret;
        left -= ret;
    }
    else {
        if ((ret = snprintf(sqlp, left, "INSERT INTO %s (", db_object_table(object))) >= left) {
            return DB_ERROR_UNKNOWN;
        }
        sqlp += ret;
        left -= ret;

        /*
         * Add the fields from the given object_field_list.
         */
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

        /*
         * Add the revision field if we have one.
         */
        if (revision_field) {
            if (first) {
                if ((ret = snprintf(sqlp, left, " %s", db_object_field_name(revision_field))) >= left) {
                    return DB_ERROR_UNKNOWN;
                }
                first = 0;
            }
            else {
                if ((ret = snprintf(sqlp, left, ", %s", db_object_field_name(revision_field))) >= left) {
                    return DB_ERROR_UNKNOWN;
                }
            }
            sqlp += ret;
            left -= ret;
        }

        if ((ret = snprintf(sqlp, left, " ) VALUES (")) >= left) {
            return DB_ERROR_UNKNOWN;
        }
        sqlp += ret;
        left -= ret;

        /*
         * Mark all the fields for binding from the object_field_list.
         */
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

        /*
         * Mark revision field for binding if we have one.
         */
        if (revision_field) {
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
        }

        if ((ret = snprintf(sqlp, left, " )")) >= left) {
            return DB_ERROR_UNKNOWN;
        }
        sqlp += ret;
        left -= ret;
    }

    /*
     * Prepare the SQL, create a MySQL statement.
     */
    if (__db_backend_mysql_prepare(backend_mysql, &statement, sql, sizeof(sql))) {
        return DB_ERROR_UNKNOWN;
    }

    /*
     * Bind all the values from value_set.
     */
    bind = 1;
    for (value_pos = 0; value_pos < db_value_set_size(value_set); value_pos++) {
        if (!(value = db_value_set_at(value_set, value_pos))) {
            __db_backend_mysql_finish(statement);
            return DB_ERROR_UNKNOWN;
        }

        switch (db_value_type(value)) {
        case DB_TYPE_INT32:
            if (db_value_to_int32(value, &int32)) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int = int32;
            ret = mysql_bind_int(statement, bind++, to_int);
            if (ret != MYSQL_OK) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_UINT32:
            if (db_value_to_uint32(value, &uint32)) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int = uint32;
            ret = mysql_bind_int(statement, bind++, to_int);
            if (ret != MYSQL_OK) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_INT64:
            if (db_value_to_int64(value, &int64)) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int64 = int64;
            ret = mysql_bind_int64(statement, bind++, to_int64);
            if (ret != MYSQL_OK) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_UINT64:
            if (db_value_to_uint64(value, &uint64)) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int64 = uint64;
            ret = mysql_bind_int64(statement, bind++, to_int64);
            if (ret != MYSQL_OK) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_TEXT:
            ret = mysql_bind_text(statement, bind++, db_value_text(value), -1, MYSQL_TRANSIENT);
            if (ret != MYSQL_OK) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_ENUM:
            if (db_value_enum_value(value, &to_int)) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            ret = mysql_bind_int(statement, bind++, to_int);
            if (ret != MYSQL_OK) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        default:
            __db_backend_mysql_finish(statement);
            return DB_ERROR_UNKNOWN;
        }
    }

    /*
     * Bind the revision field value if we have one.
     */
    if (revision_field) {
        ret = mysql_bind_int(statement, bind++, 1);
        if (ret != MYSQL_OK) {
            __db_backend_mysql_finish(statement);
            return DB_ERROR_UNKNOWN;
        }
    }

    /*
     * Execute the SQL.
     */
    if (__db_backend_mysql_step(backend_mysql, statement) != MYSQL_DONE) {
        __db_backend_mysql_finish(statement);
        return DB_ERROR_UNKNOWN;
    }
    __db_backend_mysql_finish(statement);

    return DB_OK;
}

static db_result_list_t* db_backend_mysql_read(void* data, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;
    const db_object_field_t* object_field;
    const db_join_t* join;
    char sql[4*1024];
    char* sqlp;
    int ret, left, first, fields, bind;
    db_result_list_t* result_list;
    db_backend_mysql_statement_t* statement;

    if (!__mysql_initialized) {
        return NULL;
    }
    if (!backend_mysql) {
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
        if (__db_backend_mysql_build_clause(object, clause_list, &sqlp, &left)) {
            return NULL;
        }
    }

    statement = mm_alloc_new0(&__mysql_statement_alloc);
    if (!statement) {
        return NULL;
    }
    statement->backend_mysql = backend_mysql;
    statement->object = object;
    statement->fields = fields;
    statement->statement = NULL;

    if (__db_backend_mysql_prepare(backend_mysql, &(statement->statement), sql, sizeof(sql))) {
        mm_alloc_delete(&__mysql_statement_alloc, statement);
        return NULL;
    }

    if (clause_list) {
        bind = 1;
        if (__db_backend_mysql_bind_clause(statement->statement, clause_list, &bind)) {
            __db_backend_mysql_finish(statement->statement);
            mm_alloc_delete(&__mysql_statement_alloc, statement);
            return NULL;
        }
    }

    if (!(result_list = db_result_list_new())
        || db_result_list_set_next(result_list, db_backend_mysql_next, statement, 0))
    {
        __db_backend_mysql_finish(statement->statement);
        mm_alloc_delete(&__mysql_statement_alloc, statement);
        return NULL;
    }
    return result_list;
}

static int db_backend_mysql_update(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;
    const db_object_field_t* object_field;
    const db_object_field_t* revision_field = NULL;
    const db_clause_t* clause;
    const db_clause_t* revision_clause = NULL;
    mysql_int64 revision_number = -1;
    const db_value_t* value;
    char sql[4*1024];
    char* sqlp;
    int ret, left, bind, first;
    MYSQL_STMT* statement = NULL;
    size_t value_pos;
    int to_int;
    mysql_int64 to_int64;
    db_type_int32_t int32;
    db_type_uint32_t uint32;
    db_type_int64_t int64;
    db_type_uint64_t uint64;

    if (!__mysql_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql) {
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

    /*
     * Check if the object has a revision field and keep it for later use.
     */
    object_field = db_object_field_list_begin(db_object_object_field_list(object));
    while (object_field) {
        if (db_object_field_type(object_field) == DB_TYPE_REVISION) {
            if (revision_field) {
                /*
                 * We do not support multiple revision fields.
                 */
                return DB_ERROR_UNKNOWN;
            }

            revision_field = object_field;
        }
        object_field = db_object_field_next(object_field);
    }
    if (revision_field) {
        /*
         * If we have a revision field we should also have it in the clause,
         * find it and get the value for later use or return error if not found.
         */
        clause = db_clause_list_begin(clause_list);
        while (clause) {
            if (!strcmp(db_clause_field(clause), db_object_field_name(revision_field))) {
                revision_clause = clause;
                break;
            }
            clause = db_clause_next(clause);
        }
        if (!revision_clause) {
            return DB_ERROR_UNKNOWN;
        }
        switch (db_value_type(db_clause_value(revision_clause))) {
        case DB_TYPE_INT32:
            if (db_value_to_int32(db_clause_value(revision_clause), &int32)) {
                return DB_ERROR_UNKNOWN;
            }
            revision_number = int32;
            break;

        case DB_TYPE_UINT32:
            if (db_value_to_uint32(db_clause_value(revision_clause), &uint32)) {
                return DB_ERROR_UNKNOWN;
            }
            revision_number = uint32;
            break;

        case DB_TYPE_INT64:
            if (db_value_to_int64(db_clause_value(revision_clause), &int64)) {
                return DB_ERROR_UNKNOWN;
            }
            revision_number = int64;
            break;

        case DB_TYPE_UINT64:
            if (db_value_to_uint64(db_clause_value(revision_clause), &uint64)) {
                return DB_ERROR_UNKNOWN;
            }
            revision_number = uint64;
            break;

        default:
            return DB_ERROR_UNKNOWN;
        }
    }

    left = sizeof(sql);
    sqlp = sql;

    if ((ret = snprintf(sqlp, left, "UPDATE %s SET", db_object_table(object))) >= left) {
        return DB_ERROR_UNKNOWN;
    }
    sqlp += ret;
    left -= ret;

    /*
     * Build the update SQL from the object_field_list.
     */
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

    /*
     * Add a new revision if we have any.
     */
    if (revision_field) {
        if (first) {
            if ((ret = snprintf(sqlp, left, " %s = ?", db_object_field_name(revision_field))) >= left) {
                return DB_ERROR_UNKNOWN;
            }
            first = 0;
        }
        else {
            if ((ret = snprintf(sqlp, left, ", %s = ?", db_object_field_name(revision_field))) >= left) {
                return DB_ERROR_UNKNOWN;
            }
        }
        sqlp += ret;
        left -= ret;
    }

    /*
     * Build the clauses.
     */
    if (clause_list) {
        if (db_clause_list_begin(clause_list)) {
            if ((ret = snprintf(sqlp, left, " WHERE")) >= left) {
                return DB_ERROR_UNKNOWN;
            }
            sqlp += ret;
            left -= ret;
        }
        if (__db_backend_mysql_build_clause(object, clause_list, &sqlp, &left)) {
            return DB_ERROR_UNKNOWN;
        }
    }

    /*
     * Prepare the SQL.
     */
    if (__db_backend_mysql_prepare(backend_mysql, &statement, sql, sizeof(sql))) {
        return DB_ERROR_UNKNOWN;
    }

    /*
     * Bind all the values from value_set.
     */
    bind = 1;
    for (value_pos = 0; value_pos < db_value_set_size(value_set); value_pos++) {
        if (!(value = db_value_set_at(value_set, value_pos))) {
            __db_backend_mysql_finish(statement);
            return DB_ERROR_UNKNOWN;
        }

        switch (db_value_type(value)) {
        case DB_TYPE_INT32:
            if (db_value_to_int32(value, &int32)) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int = int32;
            ret = mysql_bind_int(statement, bind++, to_int);
            if (ret != MYSQL_OK) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_UINT32:
            if (db_value_to_uint32(value, &uint32)) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int = uint32;
            ret = mysql_bind_int(statement, bind++, to_int);
            if (ret != MYSQL_OK) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_INT64:
            if (db_value_to_int64(value, &int64)) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int64 = int64;
            ret = mysql_bind_int64(statement, bind++, to_int64);
            if (ret != MYSQL_OK) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_UINT64:
            if (db_value_to_uint64(value, &uint64)) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            to_int64 = uint64;
            ret = mysql_bind_int64(statement, bind++, to_int64);
            if (ret != MYSQL_OK) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_TEXT:
            ret = mysql_bind_text(statement, bind++, db_value_text(value), -1, MYSQL_TRANSIENT);
            if (ret != MYSQL_OK) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_ENUM:
            if (db_value_enum_value(value, &to_int)) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            ret = mysql_bind_int(statement, bind++, to_int);
            if (ret != MYSQL_OK) {
                __db_backend_mysql_finish(statement);
                return DB_ERROR_UNKNOWN;
            }
            break;

        default:
            __db_backend_mysql_finish(statement);
            return DB_ERROR_UNKNOWN;
        }
    }

    /*
     * Bind the new revision if we have any.
     */
    if (revision_field) {
        ret = mysql_bind_int64(statement, bind++, revision_number + 1);
        if (ret != MYSQL_OK) {
            __db_backend_mysql_finish(statement);
            return DB_ERROR_UNKNOWN;
        }
    }

    /*
     * Bind the clauses values.
     */
    if (clause_list) {
        if (__db_backend_mysql_bind_clause(statement, clause_list, &bind)) {
            __db_backend_mysql_finish(statement);
            return DB_ERROR_UNKNOWN;
        }
    }

    /*
     * Execute the SQL.
     */
    if (__db_backend_mysql_step(backend_mysql, statement) != MYSQL_DONE) {
        __db_backend_mysql_finish(statement);
        return DB_ERROR_UNKNOWN;
    }
    __db_backend_mysql_finish(statement);

    /*
     * If we are using revision we have to have a positive number of changes
     * otherwise its a failure.
     */
    if (revision_field) {
        if (mysql_changes(backend_mysql->db) < 1) {
            return DB_ERROR_UNKNOWN;
        }
    }

    return DB_OK;
}

static int db_backend_mysql_delete(void* data, const db_object_t* object, const db_clause_list_t* clause_list) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;
    char sql[4*1024];
    char* sqlp;
    int ret, left, bind;
    MYSQL_STMT* statement = NULL;
    const db_object_field_t* revision_field = NULL;
    const db_object_field_t* object_field;
    const db_clause_t* clause;

    if (!__mysql_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }

    /*
     * Check if the object has a revision field and keep it for later use.
     */
    object_field = db_object_field_list_begin(db_object_object_field_list(object));
    while (object_field) {
        if (db_object_field_type(object_field) == DB_TYPE_REVISION) {
            if (revision_field) {
                /*
                 * We do not support multiple revision fields.
                 */
                return DB_ERROR_UNKNOWN;
            }

            revision_field = object_field;
        }
        object_field = db_object_field_next(object_field);
    }
    if (revision_field) {
        /*
         * If we have a revision field we should also have it in the clause,
         * find it or return error if not found.
         */
        clause = db_clause_list_begin(clause_list);
        while (clause) {
            if (!strcmp(db_clause_field(clause), db_object_field_name(revision_field))) {
                break;
            }
            clause = db_clause_next(clause);
        }
        if (!clause) {
            return DB_ERROR_UNKNOWN;
        }
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
        if (__db_backend_mysql_build_clause(object, clause_list, &sqlp, &left)) {
            return DB_ERROR_UNKNOWN;
        }
    }

    if (__db_backend_mysql_prepare(backend_mysql, &statement, sql, sizeof(sql))) {
        return DB_ERROR_UNKNOWN;
    }

    if (clause_list) {
        bind = 1;
        if (__db_backend_mysql_bind_clause(statement, clause_list, &bind)) {
            __db_backend_mysql_finish(statement);
            return DB_ERROR_UNKNOWN;
        }
    }

    if (__db_backend_mysql_step(backend_mysql, statement) != MYSQL_DONE) {
        __db_backend_mysql_finish(statement);
        return DB_ERROR_UNKNOWN;
    }
    __db_backend_mysql_finish(statement);

    /*
     * If we are using revision we have to have a positive number of changes
     * otherwise its a failure.
     */
    if (revision_field) {
        if (mysql_changes(backend_mysql->db) < 1) {
            return DB_ERROR_UNKNOWN;
        }
    }

    return DB_OK;
}

static int db_backend_mysql_count(void* data, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list, size_t* count) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;
    const db_join_t* join;
    char sql[4*1024];
    char* sqlp;
    int ret, left, bind;
    MYSQL_STMT* statement = NULL;
    int mysql_count;

    if (!__mysql_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!count) {
        return DB_ERROR_UNKNOWN;
    }

    left = sizeof(sql);
    sqlp = sql;

    if ((ret = snprintf(sqlp, left, "SELECT COUNT(*)")) >= left) {
        return DB_ERROR_UNKNOWN;
    }
    sqlp += ret;
    left -= ret;

    if ((ret = snprintf(sqlp, left, " FROM %s", db_object_table(object))) >= left) {
        return DB_ERROR_UNKNOWN;
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
                return DB_ERROR_UNKNOWN;
            }
            sqlp += ret;
            left -= ret;
            join = db_join_next(join);
        }
    }

    if (clause_list) {
        if (db_clause_list_begin(clause_list)) {
            if ((ret = snprintf(sqlp, left, " WHERE")) >= left) {
                return DB_ERROR_UNKNOWN;
            }
            sqlp += ret;
            left -= ret;
        }
        if (__db_backend_mysql_build_clause(object, clause_list, &sqlp, &left)) {
            return DB_ERROR_UNKNOWN;
        }
    }

    if (__db_backend_mysql_prepare(backend_mysql, &statement, sql, sizeof(sql))) {
        return DB_ERROR_UNKNOWN;
    }

    if (clause_list) {
        bind = 1;
        if (__db_backend_mysql_bind_clause(statement, clause_list, &bind)) {
            __db_backend_mysql_finish(statement);
            return DB_ERROR_UNKNOWN;
        }
    }

    ret = __db_backend_mysql_step(backend_mysql, statement);
    if (ret != MYSQL_DONE && ret != MYSQL_ROW) {
        __db_backend_mysql_finish(statement);
        return DB_ERROR_UNKNOWN;
    }

    mysql_count = mysql_column_int(statement, 0);
    ret = mysql_errcode(backend_mysql->db);
    if ((ret != MYSQL_OK && ret != MYSQL_ROW && ret != MYSQL_DONE)) {
        __db_backend_mysql_finish(statement);
        return DB_ERROR_UNKNOWN;
    }

    *count = mysql_count;
    __db_backend_mysql_finish(statement);
    return DB_OK;
}

static void db_backend_mysql_free(void* data) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;

    if (backend_mysql) {
        if (backend_mysql->db) {
            (void)db_backend_mysql_disconnect(backend_mysql);
        }
        mm_alloc_delete(&__mysql_alloc, backend_mysql);
    }
}

static int db_backend_mysql_transaction_begin(void* data) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;
    static const char* sql = "BEGIN TRANSACTION";
    MYSQL_STMT* statement = NULL;

    if (!__mysql_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql) {
        return DB_ERROR_UNKNOWN;
    }
    if (backend_mysql->transaction) {
        return DB_ERROR_UNKNOWN;
    }

    if (__db_backend_mysql_prepare(backend_mysql, &statement, sql, sizeof(sql))) {
        return DB_ERROR_UNKNOWN;
    }

    if (__db_backend_mysql_step(backend_mysql, statement) != MYSQL_DONE) {
        __db_backend_mysql_finish(statement);
        return DB_ERROR_UNKNOWN;
    }
    __db_backend_mysql_finish(statement);

    backend_mysql->transaction = 1;
    return DB_OK;
}

static int db_backend_mysql_transaction_commit(void* data) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;
    static const char* sql = "COMMIT TRANSACTION";
    MYSQL_STMT* statement = NULL;

    if (!__mysql_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql->transaction) {
        return DB_ERROR_UNKNOWN;
    }

    if (__db_backend_mysql_prepare(backend_mysql, &statement, sql, sizeof(sql))) {
        return DB_ERROR_UNKNOWN;
    }

    if (__db_backend_mysql_step(backend_mysql, statement) != MYSQL_DONE) {
        __db_backend_mysql_finish(statement);
        return DB_ERROR_UNKNOWN;
    }
    __db_backend_mysql_finish(statement);

    backend_mysql->transaction = 0;
    return DB_OK;
}

static int db_backend_mysql_transaction_rollback(void* data) {
    db_backend_mysql_t* backend_mysql = (db_backend_mysql_t*)data;
    static const char* sql = "ROLLBACK TRANSACTION";
    MYSQL_STMT* statement = NULL;

    if (!__mysql_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_mysql->transaction) {
        return DB_ERROR_UNKNOWN;
    }

    if (__db_backend_mysql_prepare(backend_mysql, &statement, sql, sizeof(sql))) {
        return DB_ERROR_UNKNOWN;
    }

    if (__db_backend_mysql_step(backend_mysql, statement) != MYSQL_DONE) {
        __db_backend_mysql_finish(statement);
        return DB_ERROR_UNKNOWN;
    }
    __db_backend_mysql_finish(statement);

    backend_mysql->transaction = 0;
    return DB_OK;
}

db_backend_handle_t* db_backend_mysql_new_handle(void) {
    db_backend_handle_t* backend_handle = NULL;
    db_backend_mysql_t* backend_mysql =
        (db_backend_mysql_t*)mm_alloc_new0(&__mysql_alloc);

    if (backend_mysql && (backend_handle = db_backend_handle_new())) {
        if (db_backend_handle_set_data(backend_handle, (void*)backend_mysql)
            || db_backend_handle_set_initialize(backend_handle, db_backend_mysql_initialize)
            || db_backend_handle_set_shutdown(backend_handle, db_backend_mysql_shutdown)
            || db_backend_handle_set_connect(backend_handle, db_backend_mysql_connect)
            || db_backend_handle_set_disconnect(backend_handle, db_backend_mysql_disconnect)
            || db_backend_handle_set_create(backend_handle, db_backend_mysql_create)
            || db_backend_handle_set_read(backend_handle, db_backend_mysql_read)
            || db_backend_handle_set_update(backend_handle, db_backend_mysql_update)
            || db_backend_handle_set_delete(backend_handle, db_backend_mysql_delete)
            || db_backend_handle_set_count(backend_handle, db_backend_mysql_count)
            || db_backend_handle_set_free(backend_handle, db_backend_mysql_free)
            || db_backend_handle_set_transaction_begin(backend_handle, db_backend_mysql_transaction_begin)
            || db_backend_handle_set_transaction_commit(backend_handle, db_backend_mysql_transaction_commit)
            || db_backend_handle_set_transaction_rollback(backend_handle, db_backend_mysql_transaction_rollback))
        {
            db_backend_handle_free(backend_handle);
            mm_alloc_delete(&__mysql_alloc, backend_mysql);
            return NULL;
        }
    }
    return backend_handle;
}
