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
#include "../csk.h"

#include <string.h>

static db_configuration_list_t* configuration_list = NULL;
static db_configuration_t* configuration = NULL;
static db_connection_t* connection = NULL;

static csk_t* object = NULL;
static csk_list_t* object_list = NULL;
static int id = 0;

#if defined(ENFORCER_DATABASE_SQLITE3)
int test_csk_init_suite_sqlite(void) {
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

    return 0;
}
#endif

#if defined(ENFORCER_DATABASE_COUCHDB)
int test_csk_init_suite_couchdb(void) {
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
        || db_configuration_set_value(configuration, "couchdb")
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
        || db_configuration_set_name(configuration, "url")
        || db_configuration_set_value(configuration, "http://127.0.0.1:5984/opendnssec")
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

    return 0;
}
#endif

static int test_csk_clean_suite(void) {
    db_connection_free(connection);
    connection = NULL;
    db_configuration_free(configuration);
    configuration = NULL;
    db_configuration_list_free(configuration_list);
    configuration_list = NULL;
    return 0;
}

static void test_csk_new(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((object = csk_new(connection)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_list = csk_list_new(connection)));
}

static void test_csk_set(void) {
    CU_ASSERT(!csk_set_algorithm(object, 1));
    CU_ASSERT(!csk_set_bits(object, 1));
    CU_ASSERT(!csk_set_lifetime(object, 1));
    CU_ASSERT(!csk_set_repository(object, "repository 1"));
    CU_ASSERT(!csk_set_standby(object, 1));
    CU_ASSERT(!csk_set_manual_rollover(object, 1));
    CU_ASSERT(!csk_set_rfc5011(object, 1));
    CU_ASSERT(!csk_set_rollover_type(object, CSK_ROLLOVER_TYPE_DOUBLE_RRSET));
    CU_ASSERT(!csk_set_rollover_type_text(object, "CskDoubleRRset"));
    CU_ASSERT(!csk_set_rollover_type(object, CSK_ROLLOVER_TYPE_SINGLE_SIGNATURE));
    CU_ASSERT(!csk_set_rollover_type_text(object, "CskSingleSignature"));
    CU_ASSERT(!csk_set_rollover_type(object, CSK_ROLLOVER_TYPE_DOUBLE_DS));
    CU_ASSERT(!csk_set_rollover_type_text(object, "CskDoubleDS"));
    CU_ASSERT(!csk_set_rollover_type(object, CSK_ROLLOVER_TYPE_DOUBLE_SIGNATURE));
    CU_ASSERT(!csk_set_rollover_type_text(object, "CskDoubleSignature"));
    CU_ASSERT(!csk_set_rollover_type(object, CSK_ROLLOVER_TYPE_PREPUBLICATION));
    CU_ASSERT(!csk_set_rollover_type_text(object, "CskPrePublication"));
}

static void test_csk_get(void) {
    CU_ASSERT(csk_algorithm(object) == 1);
    CU_ASSERT(csk_bits(object) == 1);
    CU_ASSERT(csk_lifetime(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(csk_repository(object));
    CU_ASSERT(!strcmp(csk_repository(object), "repository 1"));
    CU_ASSERT(csk_standby(object) == 1);
    CU_ASSERT(csk_manual_rollover(object) == 1);
    CU_ASSERT(csk_rfc5011(object) == 1);
    CU_ASSERT(csk_rollover_type(object) == CSK_ROLLOVER_TYPE_PREPUBLICATION);
    CU_ASSERT_PTR_NOT_NULL_FATAL(csk_rollover_type_text(object));
    CU_ASSERT(!strcmp(csk_rollover_type_text(object), "CskPrePublication"));
}

static void test_csk_create(void) {
    CU_ASSERT_FATAL(!csk_create(object));
}

static void test_csk_list(void) {
    const csk_t* item;
    CU_ASSERT_FATAL(!csk_list_get(object_list));
    CU_ASSERT_PTR_NOT_NULL_FATAL((item = csk_list_begin(object_list)));
    CU_ASSERT_FATAL((id = csk_id(item)));
}

static void test_csk_read(void) {
    CU_ASSERT_FATAL(!csk_get_by_id(object, id));
}

static void test_csk_verify(void) {
    CU_ASSERT(csk_algorithm(object) == 1);
    CU_ASSERT(csk_bits(object) == 1);
    CU_ASSERT(csk_lifetime(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(csk_repository(object));
    CU_ASSERT(!strcmp(csk_repository(object), "repository 1"));
    CU_ASSERT(csk_standby(object) == 1);
    CU_ASSERT(csk_manual_rollover(object) == 1);
    CU_ASSERT(csk_rfc5011(object) == 1);
    CU_ASSERT(csk_rollover_type(object) == CSK_ROLLOVER_TYPE_PREPUBLICATION);
    CU_ASSERT_PTR_NOT_NULL_FATAL(csk_rollover_type_text(object));
    CU_ASSERT(!strcmp(csk_rollover_type_text(object), "CskPrePublication"));
}

static void test_csk_change(void) {
    CU_ASSERT(!csk_set_algorithm(object, 2));
    CU_ASSERT(!csk_set_bits(object, 2));
    CU_ASSERT(!csk_set_lifetime(object, 2));
    CU_ASSERT(!csk_set_repository(object, "repository 2"));
    CU_ASSERT(!csk_set_standby(object, 2));
    CU_ASSERT(!csk_set_manual_rollover(object, 2));
    CU_ASSERT(!csk_set_rfc5011(object, 2));
    CU_ASSERT(!csk_set_rollover_type(object, CSK_ROLLOVER_TYPE_DOUBLE_RRSET));
    CU_ASSERT(!csk_set_rollover_type_text(object, "CskDoubleRRset"));
}

static void test_csk_update(void) {
    CU_ASSERT_FATAL(!csk_update(object));
}

static void test_csk_read2(void) {
    CU_ASSERT_FATAL(!csk_get_by_id(object, id));
}

static void test_csk_verify2(void) {
    CU_ASSERT(csk_algorithm(object) == 2);
    CU_ASSERT(csk_bits(object) == 2);
    CU_ASSERT(csk_lifetime(object) == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(csk_repository(object));
    CU_ASSERT(!strcmp(csk_repository(object), "repository 2"));
    CU_ASSERT(csk_standby(object) == 2);
    CU_ASSERT(csk_manual_rollover(object) == 2);
    CU_ASSERT(csk_rfc5011(object) == 2);
    CU_ASSERT(csk_rollover_type(object) == CSK_ROLLOVER_TYPE_DOUBLE_RRSET);
    CU_ASSERT_PTR_NOT_NULL_FATAL(csk_rollover_type_text(object));
    CU_ASSERT(!strcmp(csk_rollover_type_text(object), "CskDoubleRRset"));
}

static void test_csk_delete(void) {
    CU_ASSERT_FATAL(!csk_delete(object));
}

static void test_csk_list2(void) {
    CU_ASSERT_FATAL(!csk_list_get(object_list));
    CU_ASSERT_PTR_NULL(csk_list_begin(object_list));
}

static void test_csk_end(void) {
    if (object) {
        csk_free(object);
        CU_PASS("csk_free");
    }
    if (object_list) {
        csk_list_free(object_list);
        CU_PASS("csk_list_free");
    }
}

static int test_csk_add_tests(CU_pSuite pSuite) {
    if (!CU_add_test(pSuite, "new object", test_csk_new)
        || !CU_add_test(pSuite, "set fields", test_csk_set)
        || !CU_add_test(pSuite, "get fields", test_csk_get)
        || !CU_add_test(pSuite, "create object", test_csk_create)
        || !CU_add_test(pSuite, "list objects", test_csk_list)
        || !CU_add_test(pSuite, "read object by id", test_csk_read)
        || !CU_add_test(pSuite, "verify fields", test_csk_verify)
        || !CU_add_test(pSuite, "change object", test_csk_change)
        || !CU_add_test(pSuite, "update object", test_csk_update)
        || !CU_add_test(pSuite, "reread object by id", test_csk_read2)
        || !CU_add_test(pSuite, "verify fields after update", test_csk_verify2)
        || !CU_add_test(pSuite, "delete object", test_csk_delete)
        || !CU_add_test(pSuite, "list objects to verify delete", test_csk_list2)
        || !CU_add_test(pSuite, "end test", test_csk_end))
    {
        return CU_get_error();
    }
    return 0;
}

int test_csk_add_suite(void) {
    CU_pSuite pSuite = NULL;
    int ret;

#if defined(ENFORCER_DATABASE_SQLITE3)
    pSuite = CU_add_suite("Test of csk (SQLite)", test_csk_init_suite_sqlite, test_csk_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_csk_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
#if defined(ENFORCER_DATABASE_COUCHDB)
    pSuite = CU_add_suite("Test of csk (CouchDB)", test_csk_init_suite_couchdb, test_csk_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_csk_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
    return 0;
}
