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

#include "CUnit/Basic.h"

typedef struct {
    db_object_t* dbo;
    int id;
    char* name;
} test_t;

static db_configuration_list_t* configuration_list = NULL;
static db_configuration_t* configuration = NULL;
static db_connection_t* connection = NULL;
static test_t* test = NULL;

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
