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

#include "../db_configuration.h"
#include "../db_connection.h"
#include "../db_object.h"
#include "../db_backend.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include "CUnit/Basic.h"

#include <sqlite3.h>

void ods_log_deeebug(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void ods_log_debug(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void ods_log_verbose(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void ods_log_info(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void ods_log_warning(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void ods_log_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void ods_log_verror(const char *format, va_list args) {
    vprintf(format, args);
}

void ods_log_crit(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void ods_log_alert(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void ods_fatal_exit(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    exit(1);
}

db_backend_handle_t* backend_handle = NULL;
db_backend_t* backend = NULL;
db_configuration_list_t* configuration_list = NULL;
db_configuration_t* configuration = NULL;
db_connection_t* connection = NULL;

int init_suite_classes(void) {
    if (backend_handle) {
        return 1;
    }
    if (backend) {
        return 1;
    }
    return 0;
}

int clean_suite_classes(void) {
    db_backend_handle_free(backend_handle);
    backend_handle = NULL;
    db_backend_free(backend);
    backend = NULL;
    return 0;
}

void test_class_db_backend_handle(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((backend_handle = db_backend_handle_new()));
    /*
    int db_backend_handle_initialize(const db_backend_handle_t*);
    int db_backend_handle_shutdown(const db_backend_handle_t*);
    int db_backend_handle_connect(const db_backend_handle_t*, const db_configuration_list_t*);
    int db_backend_handle_disconnect(const db_backend_handle_t*);
    int db_backend_handle_create(const db_backend_handle_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*);
    db_result_list_t* db_backend_handle_read(const db_backend_handle_t*, const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
    int db_backend_handle_update(const db_backend_handle_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*, const db_clause_list_t*);
    int db_backend_handle_delete(const db_backend_handle_t*, const db_object_t*, const db_clause_list_t*);
    int db_backend_handle_transaction_begin(const db_backend_handle_t*);
    int db_backend_handle_transaction_commit(const db_backend_handle_t*);
    int db_backend_handle_transaction_rollback(const db_backend_handle_t*);
    const void* db_backend_handle_data(const db_backend_handle_t*);
    int db_backend_handle_set_initialize(db_backend_handle_t*, db_backend_handle_initialize_t);
    int db_backend_handle_set_shutdown(db_backend_handle_t*, db_backend_handle_shutdown_t);
    int db_backend_handle_set_connect(db_backend_handle_t*, db_backend_handle_connect_t);
    int db_backend_handle_set_disconnect(db_backend_handle_t*, db_backend_handle_disconnect_t);
    int db_backend_handle_set_create(db_backend_handle_t*, db_backend_handle_create_t);
    int db_backend_handle_set_read(db_backend_handle_t*, db_backend_handle_read_t);
    int db_backend_handle_set_update(db_backend_handle_t*, db_backend_handle_update_t);
    int db_backend_handle_set_delete(db_backend_handle_t*, db_backend_handle_delete_t);
    int db_backend_handle_set_free(db_backend_handle_t*, db_backend_handle_free_t);
    int db_backend_handle_set_transaction_begin(db_backend_handle_t*, db_backend_handle_transaction_begin_t);
    int db_backend_handle_set_transaction_commit(db_backend_handle_t*, db_backend_handle_transaction_commit_t);
    int db_backend_handle_set_transaction_rollback(db_backend_handle_t*, db_backend_handle_transaction_rollback_t);
    int db_backend_handle_set_data(db_backend_handle_t*, void*);
    int db_backend_handle_not_empty(const db_backend_handle_t*);
    */
}

void test_class_db_backend(void) {
    db_backend_handle_t* local_backend_handle;

    CU_ASSERT_PTR_NOT_NULL_FATAL((backend = db_backend_new()));
    CU_ASSERT_FATAL(!db_backend_set_name(backend, "test"));
    CU_ASSERT_FATAL(!strcmp(db_backend_name(backend), "test"));
    CU_ASSERT_FATAL(!db_backend_set_handle(backend, backend_handle));
    local_backend_handle = backend_handle;
    backend_handle = NULL;
    CU_ASSERT_FATAL(db_backend_handle(backend) == local_backend_handle);
    CU_ASSERT_FATAL(!db_backend_not_empty(backend));
    /*
    int db_backend_initialize(const db_backend_t*);
    int db_backend_shutdown(const db_backend_t*);
    int db_backend_connect(const db_backend_t*, const db_configuration_list_t*);
    int db_backend_disconnect(const db_backend_t*);
    int db_backend_create(const db_backend_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*);
    db_result_list_t* db_backend_read(const db_backend_t*, const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
    int db_backend_update(const db_backend_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*, const db_clause_list_t*);
    int db_backend_delete(const db_backend_t*, const db_object_t*, const db_clause_list_t*);
    int db_backend_transaction_begin(const db_backend_t*);
    int db_backend_transaction_commit(const db_backend_t*);
    int db_backend_transaction_rollback(const db_backend_t*);
    */
    db_backend_free(backend);
    backend = NULL;
    CU_PASS("db_backend_handle_free");
    CU_PASS("db_backend_free");
}

typedef struct {
    db_object_t* dbo;
    int id;
    char* name;
} test_t;

test_t* test = NULL;

test_t* test_new(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    test_t* test =
        (test_t*)calloc(1, sizeof(test_t));

    if (test) {
        CU_ASSERT_PTR_NOT_NULL_FATAL((test->dbo = db_object_new()));

        CU_ASSERT_FATAL(!db_object_set_connection(test->dbo, connection));
        CU_ASSERT_FATAL(!db_object_set_table(test->dbo, "test"));
        CU_ASSERT_FATAL(!db_object_set_primary_key_name(test->dbo, "id"));

        CU_ASSERT_PTR_NOT_NULL_FATAL((object_field_list = db_object_field_list_new()));

        CU_ASSERT_PTR_NOT_NULL_FATAL((object_field = db_object_field_new()));
        CU_ASSERT_FATAL(!db_object_field_set_name(object_field, "id"));
        CU_ASSERT_FATAL(!db_object_field_set_type(object_field, DB_TYPE_PRIMARY_KEY));
        CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field));

        CU_ASSERT_PTR_NOT_NULL_FATAL((object_field = db_object_field_new()));
        CU_ASSERT_FATAL(!db_object_field_set_name(object_field, "name"));
        CU_ASSERT_FATAL(!db_object_field_set_type(object_field, DB_TYPE_TEXT));
        CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field));

        CU_ASSERT_FATAL(!db_object_set_object_field_list(test->dbo, object_field_list));
    }

    return test;
}

void test_free(test_t* test) {
    if (test) {
        if (test->dbo) {
            db_object_free(test->dbo);
        }
        if (test->name) {
            free(test->name);
        }
        free(test);
    }
}

int test_id(const test_t* test) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(test);

    return test->id;
}

const char* test_name(const test_t* test) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(test);

    return test->name;
}

int test_get_by_id(test_t* test, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;
    int ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test);
    CU_ASSERT_FATAL(id);

    test->id = 0;
    if (test->name) {
        free(test->name);
    }
    test->name = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "id"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_from_int32(db_clause_get_value(clause), id));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));

    ret = 1;
    result_list = db_object_read(test->dbo, NULL, clause_list);
    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            const db_value_set_t* value_set = db_result_value_set(result);

            CU_ASSERT_PTR_NOT_NULL_FATAL(value_set);
            CU_ASSERT_FATAL(db_value_set_size(value_set) == 2);
            CU_ASSERT_FATAL(!db_value_to_int32(db_value_set_at(value_set, 0), &(test->id)));
            CU_ASSERT_FATAL(!db_value_to_text(db_value_set_at(value_set, 1), &(test->name)));
            ret = 0;
        }
        result = db_result_list_next(result_list);
        if (result) {
            db_result_list_free(result_list);
            db_clause_list_free(clause_list);
            return 1;
        }
    }

    db_result_list_free(result_list);
    db_clause_list_free(clause_list);
    return ret;
}

int init_suite_initialization(void) {
    if (configuration_list) {
        return 1;
    }
    if (configuration) {
        return 1;
    }
    if (connection) {
        return 1;
    }
    return 0;
}

int clean_suite_initialization(void) {
    db_connection_free(connection);
    connection = NULL;
    db_configuration_free(configuration);
    configuration = NULL;
    db_configuration_list_free(configuration_list);
    configuration_list = NULL;
    return 0;
}

void test_initialization_configuration(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((configuration_list = db_configuration_list_new()));

    CU_ASSERT_PTR_NOT_NULL_FATAL((configuration = db_configuration_new()));
    CU_ASSERT_FATAL(!db_configuration_set_name(configuration, "backend"));
    CU_ASSERT_FATAL(!db_configuration_set_value(configuration, "sqlite"));
    CU_ASSERT_FATAL(!db_configuration_list_add(configuration_list, configuration));
    configuration = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((configuration = db_configuration_new()));
    CU_ASSERT_FATAL(!db_configuration_set_name(configuration, "file"));
    CU_ASSERT_FATAL(!db_configuration_set_value(configuration, "test.db"));
    CU_ASSERT_FATAL(!db_configuration_list_add(configuration_list, configuration));
    configuration = NULL;
}

void test_initialization_connection(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((connection = db_connection_new()));
    CU_ASSERT_FATAL(!db_connection_set_configuration_list(connection, configuration_list));
    CU_ASSERT_FATAL(!db_connection_setup(connection));
    CU_ASSERT_FATAL(!db_connection_connect(connection));

    CU_ASSERT_FATAL(!db_connection_disconnect(connection));
}

int init_suite_database_operations(void) {
    if (configuration_list) {
        return 1;
    }
    if (configuration) {
        return 1;
    }
    if (connection) {
        return 1;
    }
    if (test) {
        return 1;
    }

    /*
     * Setup the configuration for the connection
     */
    if (!(configuration_list = db_configuration_list_new())) {
        return 1;
    }
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "backend")
        || db_configuration_set_value(configuration, "sqlite")
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        db_configuration_list_free(configuration_list);
        return 1;
    }
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "file")
        || db_configuration_set_value(configuration, "test.db")
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        db_configuration_list_free(configuration_list);
        return 1;
    }

    /*
     * Connect to the database
     */
    if (!(connection = db_connection_new())
        || db_connection_set_configuration_list(connection, configuration_list)
        || db_connection_setup(connection)
        || db_connection_connect(connection))
    {
        db_connection_free(connection);
        db_configuration_list_free(configuration_list);
        return 1;
    }

    return 0;
}

int clean_suite_database_operations(void) {
    test_free(test);
    test = NULL;
    db_connection_free(connection);
    connection = NULL;
    db_configuration_free(configuration);
    configuration = NULL;
    db_configuration_list_free(configuration_list);
    configuration_list = NULL;
    return 0;
}

void test_database_operations_read_object(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(!test_get_by_id(test, 1));
    CU_ASSERT_FATAL(test_id(test) == 1);
}

int main(void) {
    CU_pSuite pSuite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    pSuite = CU_add_suite("Classes", init_suite_classes, clean_suite_classes);
    if (!pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (!CU_add_test(pSuite, "test of db_backend_handle", test_class_db_backend_handle)
        || !CU_add_test(pSuite, "test of db_backend", test_class_db_backend))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    pSuite = CU_add_suite("Initialization", init_suite_initialization, clean_suite_initialization);
    if (!pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (!CU_add_test(pSuite, "test of configuration", test_initialization_configuration)
        || !CU_add_test(pSuite, "test of connection", test_initialization_connection))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    pSuite = CU_add_suite("Database operations", init_suite_database_operations, clean_suite_database_operations);
    if (!pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (!CU_add_test(pSuite, "test of read object", test_database_operations_read_object))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}
