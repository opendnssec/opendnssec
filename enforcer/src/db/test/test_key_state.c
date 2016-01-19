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

#include "CUnit/Basic.h"

#include "../db_configuration.h"
#include "../db_connection.h"
#include "../key_state.h"

#include <string.h>

static db_configuration_list_t* configuration_list = NULL;
static db_configuration_t* configuration = NULL;
static db_connection_t* connection = NULL;

static key_state_t* object = NULL;
static key_state_list_t* object_list = NULL;
static db_value_t id = DB_VALUE_EMPTY;
static db_clause_list_t* clause_list = NULL;

static int db_sqlite = 0;
static int db_mysql = 0;

#if defined(ENFORCER_DATABASE_SQLITE3)
int test_key_state_init_suite_sqlite(void) {
    if (configuration_list) {
        return 1;
    }
    if (configuration) {
        return 1;
    }
    if (connection) {
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
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "file")
        || db_configuration_set_value(configuration, "test.db")
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;

    /*
     * Connect to the database
     */
    if (!(connection = db_connection_new())
        || db_connection_set_configuration_list(connection, configuration_list))
    {
        db_connection_free(connection);
        connection = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration_list = NULL;

    if (db_connection_setup(connection)
        || db_connection_connect(connection))
    {
        db_connection_free(connection);
        connection = NULL;
        return 1;
    }

    db_sqlite = 1;
    db_mysql = 0;

    return 0;
}
#endif

#if defined(ENFORCER_DATABASE_MYSQL)
int test_key_state_init_suite_mysql(void) {
    if (configuration_list) {
        return 1;
    }
    if (configuration) {
        return 1;
    }
    if (connection) {
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
        || db_configuration_set_value(configuration, "mysql")
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "host")
        || db_configuration_set_value(configuration, ENFORCER_DB_HOST)
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "port")
        || db_configuration_set_value(configuration, ENFORCER_DB_PORT_TEXT)
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "user")
        || db_configuration_set_value(configuration, ENFORCER_DB_USERNAME)
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "pass")
        || db_configuration_set_value(configuration, ENFORCER_DB_PASSWORD)
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "db")
        || db_configuration_set_value(configuration, ENFORCER_DB_DATABASE)
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;

    /*
     * Connect to the database
     */
    if (!(connection = db_connection_new())
        || db_connection_set_configuration_list(connection, configuration_list))
    {
        db_connection_free(connection);
        connection = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration_list = NULL;

    if (db_connection_setup(connection)
        || db_connection_connect(connection))
    {
        db_connection_free(connection);
        connection = NULL;
        return 1;
    }

    db_sqlite = 0;
    db_mysql = 1;

    return 0;
}
#endif

static int test_key_state_clean_suite(void) {
    db_connection_free(connection);
    connection = NULL;
    db_configuration_free(configuration);
    configuration = NULL;
    db_configuration_list_free(configuration_list);
    configuration_list = NULL;
    db_value_reset(&id);
    db_clause_list_free(clause_list);
    clause_list = NULL;
    return 0;
}

static void test_key_state_new(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((object = key_state_new(connection)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_list = key_state_list_new(connection)));
}

static void test_key_state_set(void) {
    db_value_t key_data_id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&key_data_id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&key_data_id, 1));
    }
    CU_ASSERT(!key_state_set_key_data_id(object, &key_data_id));
    CU_ASSERT(!key_state_set_type(object, KEY_STATE_TYPE_DS));
    CU_ASSERT(!key_state_set_type(object, KEY_STATE_TYPE_RRSIG));
    CU_ASSERT(!key_state_set_type(object, KEY_STATE_TYPE_DNSKEY));
    CU_ASSERT(!key_state_set_type(object, KEY_STATE_TYPE_RRSIGDNSKEY));
    CU_ASSERT(!key_state_set_state(object, KEY_STATE_STATE_HIDDEN));
    CU_ASSERT(!key_state_set_state(object, KEY_STATE_STATE_RUMOURED));
    CU_ASSERT(!key_state_set_state(object, KEY_STATE_STATE_OMNIPRESENT));
    CU_ASSERT(!key_state_set_state(object, KEY_STATE_STATE_UNRETENTIVE));
    CU_ASSERT(!key_state_set_state(object, KEY_STATE_STATE_NA));
    CU_ASSERT(!key_state_set_last_change(object, 1));
    CU_ASSERT(!key_state_set_minimize(object, 1));
    CU_ASSERT(!key_state_set_ttl(object, 1));
    db_value_reset(&key_data_id);
}

static void test_key_state_get(void) {
    int ret;
    db_value_t key_data_id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&key_data_id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&key_data_id, 1));
    }
    CU_ASSERT(!db_value_cmp(key_state_key_data_id(object), &key_data_id, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(key_state_type(object) == KEY_STATE_TYPE_RRSIGDNSKEY);
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_state_type_text(object));
    CU_ASSERT(!strcmp(key_state_type_text(object), "RRSIGDNSKEY"));
    CU_ASSERT(key_state_state(object) == KEY_STATE_STATE_NA);
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_state_state_text(object));
    CU_ASSERT(!strcmp(key_state_state_text(object), "NA"));
    CU_ASSERT(key_state_last_change(object) == 1);
    CU_ASSERT(key_state_minimize(object) == 1);
    CU_ASSERT(key_state_ttl(object) == 1);
    db_value_reset(&key_data_id);
}

static void test_key_state_create(void) {
    CU_ASSERT_FATAL(!key_state_create(object));
}

static void test_key_state_clauses(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL(key_state_key_data_id_clause(clause_list, key_state_key_data_id(object)));
    CU_ASSERT(!key_state_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(key_state_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;
}

static void test_key_state_verify(void) {
    int ret;
    db_value_t key_data_id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&key_data_id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&key_data_id, 1));
    }
    CU_ASSERT(!db_value_cmp(key_state_key_data_id(object), &key_data_id, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(key_state_type(object) == KEY_STATE_TYPE_RRSIGDNSKEY);
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_state_type_text(object));
    CU_ASSERT(!strcmp(key_state_type_text(object), "RRSIGDNSKEY"));
    CU_ASSERT(key_state_state(object) == KEY_STATE_STATE_NA);
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_state_state_text(object));
    CU_ASSERT(!strcmp(key_state_state_text(object), "NA"));
    CU_ASSERT(key_state_last_change(object) == 1);
    CU_ASSERT(key_state_minimize(object) == 1);
    CU_ASSERT(key_state_ttl(object) == 1);
    db_value_reset(&key_data_id);
}

static void test_key_state_change(void) {
    db_value_t key_data_id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&key_data_id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&key_data_id, 1));
    }
    CU_ASSERT(!key_state_set_key_data_id(object, &key_data_id));
    CU_ASSERT(!key_state_set_type(object, KEY_STATE_TYPE_DS));
    CU_ASSERT(!key_state_set_state(object, KEY_STATE_STATE_HIDDEN));
    CU_ASSERT(!key_state_set_last_change(object, 2));
    CU_ASSERT(!key_state_set_minimize(object, 2));
    CU_ASSERT(!key_state_set_ttl(object, 2));
    db_value_reset(&key_data_id);
}

static void test_key_state_update(void) {
    CU_ASSERT_FATAL(!key_state_update(object));
}

static void test_key_state_read(void) {
    db_value_t id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&id, 1));
    }
    CU_ASSERT_FATAL(!key_state_get_by_id(object, &id));
}

static void test_key_state_read2(void) {
    db_value_t id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&id, 1));
    }
    CU_ASSERT_FATAL(!key_state_get_by_id(object, &id));
}

static void test_key_state_verify2(void) {
    int ret;
    db_value_t key_data_id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&key_data_id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&key_data_id, 1));
    }
    CU_ASSERT(!db_value_cmp(key_state_key_data_id(object), &key_data_id, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(key_state_type(object) == KEY_STATE_TYPE_DS);
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_state_type_text(object));
    CU_ASSERT(!strcmp(key_state_type_text(object), "DS"));
    CU_ASSERT(key_state_state(object) == KEY_STATE_STATE_HIDDEN);
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_state_state_text(object));
    CU_ASSERT(!strcmp(key_state_state_text(object), "hidden"));
    CU_ASSERT(key_state_last_change(object) == 2);
    CU_ASSERT(key_state_minimize(object) == 2);
    CU_ASSERT(key_state_ttl(object) == 2);
    db_value_reset(&key_data_id);
}

static void test_key_state_delete(void) {
    CU_ASSERT_FATAL(!key_state_delete(object));
}

static void test_key_state_end(void) {
    if (object) {
        key_state_free(object);
        CU_PASS("key_state_free");
    }
    if (object_list) {
        key_state_list_free(object_list);
        CU_PASS("key_state_list_free");
    }
}

static int test_key_state_add_tests(CU_pSuite pSuite) {
    if (!CU_add_test(pSuite, "new object", test_key_state_new)
        || !CU_add_test(pSuite, "set fields", test_key_state_set)
        || !CU_add_test(pSuite, "get fields", test_key_state_get)
        || !CU_add_test(pSuite, "create object", test_key_state_create)
        || !CU_add_test(pSuite, "object clauses", test_key_state_clauses)
        || !CU_add_test(pSuite, "read object by id", test_key_state_read)
        || !CU_add_test(pSuite, "verify fields", test_key_state_verify)
        || !CU_add_test(pSuite, "change object", test_key_state_change)
        || !CU_add_test(pSuite, "update object", test_key_state_update)
        || !CU_add_test(pSuite, "reread object by id", test_key_state_read2)
        || !CU_add_test(pSuite, "verify fields after update", test_key_state_verify2)
        || !CU_add_test(pSuite, "delete object", test_key_state_delete)
        || !CU_add_test(pSuite, "end test", test_key_state_end))
    {
        return CU_get_error();
    }
    return 0;
}

int test_key_state_add_suite(void) {
    CU_pSuite pSuite = NULL;
    int ret;

#if defined(ENFORCER_DATABASE_SQLITE3)
    pSuite = CU_add_suite("Test of key state (SQLite)", test_key_state_init_suite_sqlite, test_key_state_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_key_state_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
#if defined(ENFORCER_DATABASE_MYSQL)
    pSuite = CU_add_suite("Test of key state (MySQL)", test_key_state_init_suite_mysql, test_key_state_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_key_state_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
    return 0;
}
