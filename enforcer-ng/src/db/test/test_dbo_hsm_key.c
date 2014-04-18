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
#include "../dbo_hsm_key.h"

#include <string.h>

static db_configuration_list_t* configuration_list = NULL;
static db_configuration_t* configuration = NULL;
static db_connection_t* connection = NULL;

static dbo_hsm_key_t* object = NULL;
static dbo_hsm_key_list_t* object_list = NULL;
static db_value_t id = DB_VALUE_EMPTY;

#if defined(ENFORCER_DATABASE_SQLITE3)
int test_dbo_hsm_key_init_suite_sqlite(void) {
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
int test_dbo_hsm_key_init_suite_couchdb(void) {
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

static int test_dbo_hsm_key_clean_suite(void) {
    db_connection_free(connection);
    connection = NULL;
    db_configuration_free(configuration);
    configuration = NULL;
    db_configuration_list_free(configuration_list);
    configuration_list = NULL;
    db_value_reset(&id);
    return 0;
}

static void test_dbo_hsm_key_new(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((object = dbo_hsm_key_new(connection)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_list = dbo_hsm_key_list_new(connection)));
}

static void test_dbo_hsm_key_set(void) {
    CU_ASSERT(!dbo_hsm_key_set_locator(object, "locator 1"));
    CU_ASSERT(!dbo_hsm_key_set_candidate_for_sharing(object, 1));
    CU_ASSERT(!dbo_hsm_key_set_bits(object, 1));
    CU_ASSERT(!dbo_hsm_key_set_policy(object, "policy 1"));
    CU_ASSERT(!dbo_hsm_key_set_algorithm(object, 1));
    CU_ASSERT(!dbo_hsm_key_set_role(object, DBO_HSM_KEY_ROLE_KSK));
    CU_ASSERT(!dbo_hsm_key_set_role_text(object, "KSK"));
    CU_ASSERT(!dbo_hsm_key_set_role(object, DBO_HSM_KEY_ROLE_ZSK));
    CU_ASSERT(!dbo_hsm_key_set_role_text(object, "ZSK"));
    CU_ASSERT(!dbo_hsm_key_set_role(object, DBO_HSM_KEY_ROLE_CSK));
    CU_ASSERT(!dbo_hsm_key_set_role_text(object, "CSK"));
    CU_ASSERT(!dbo_hsm_key_set_inception(object, 1));
    CU_ASSERT(!dbo_hsm_key_set_isrevoked(object, 1));
    CU_ASSERT(!dbo_hsm_key_set_key_type(object, "key_type 1"));
    CU_ASSERT(!dbo_hsm_key_set_repository(object, "repository 1"));
    CU_ASSERT(!dbo_hsm_key_set_backmeup(object, 1));
    CU_ASSERT(!dbo_hsm_key_set_backedup(object, 1));
    CU_ASSERT(!dbo_hsm_key_set_requirebackup(object, 1));
}

static void test_dbo_hsm_key_get(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_locator(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_locator(object), "locator 1"));
    CU_ASSERT(dbo_hsm_key_candidate_for_sharing(object) == 1);
    CU_ASSERT(dbo_hsm_key_bits(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_policy(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_policy(object), "policy 1"));
    CU_ASSERT(dbo_hsm_key_algorithm(object) == 1);
    CU_ASSERT(dbo_hsm_key_role(object) == DBO_HSM_KEY_ROLE_CSK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_role_text(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_role_text(object), "CSK"));
    CU_ASSERT(dbo_hsm_key_inception(object) == 1);
    CU_ASSERT(dbo_hsm_key_isrevoked(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_key_type(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_key_type(object), "key_type 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_repository(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_repository(object), "repository 1"));
    CU_ASSERT(dbo_hsm_key_backmeup(object) == 1);
    CU_ASSERT(dbo_hsm_key_backedup(object) == 1);
    CU_ASSERT(dbo_hsm_key_requirebackup(object) == 1);
}

static void test_dbo_hsm_key_create(void) {
    CU_ASSERT_FATAL(!dbo_hsm_key_create(object));
}

static void test_dbo_hsm_key_list(void) {
    const dbo_hsm_key_t* item;
    CU_ASSERT_FATAL(!dbo_hsm_key_list_get(object_list));
    CU_ASSERT_PTR_NOT_NULL_FATAL((item = dbo_hsm_key_list_begin(object_list)));
    CU_ASSERT_FATAL(!db_value_copy(&id, dbo_hsm_key_id(item)));
}

static void test_dbo_hsm_key_read(void) {
    CU_ASSERT_FATAL(!dbo_hsm_key_get_by_id(object, &id));
}

static void test_dbo_hsm_key_verify(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_locator(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_locator(object), "locator 1"));
    CU_ASSERT(dbo_hsm_key_candidate_for_sharing(object) == 1);
    CU_ASSERT(dbo_hsm_key_bits(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_policy(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_policy(object), "policy 1"));
    CU_ASSERT(dbo_hsm_key_algorithm(object) == 1);
    CU_ASSERT(dbo_hsm_key_role(object) == DBO_HSM_KEY_ROLE_CSK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_role_text(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_role_text(object), "CSK"));
    CU_ASSERT(dbo_hsm_key_inception(object) == 1);
    CU_ASSERT(dbo_hsm_key_isrevoked(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_key_type(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_key_type(object), "key_type 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_repository(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_repository(object), "repository 1"));
    CU_ASSERT(dbo_hsm_key_backmeup(object) == 1);
    CU_ASSERT(dbo_hsm_key_backedup(object) == 1);
    CU_ASSERT(dbo_hsm_key_requirebackup(object) == 1);
}

static void test_dbo_hsm_key_change(void) {
    CU_ASSERT(!dbo_hsm_key_set_locator(object, "locator 2"));
    CU_ASSERT(!dbo_hsm_key_set_candidate_for_sharing(object, 2));
    CU_ASSERT(!dbo_hsm_key_set_bits(object, 2));
    CU_ASSERT(!dbo_hsm_key_set_policy(object, "policy 2"));
    CU_ASSERT(!dbo_hsm_key_set_algorithm(object, 2));
    CU_ASSERT(!dbo_hsm_key_set_role(object, DBO_HSM_KEY_ROLE_KSK));
    CU_ASSERT(!dbo_hsm_key_set_role_text(object, "KSK"));
    CU_ASSERT(!dbo_hsm_key_set_inception(object, 2));
    CU_ASSERT(!dbo_hsm_key_set_isrevoked(object, 2));
    CU_ASSERT(!dbo_hsm_key_set_key_type(object, "key_type 2"));
    CU_ASSERT(!dbo_hsm_key_set_repository(object, "repository 2"));
    CU_ASSERT(!dbo_hsm_key_set_backmeup(object, 2));
    CU_ASSERT(!dbo_hsm_key_set_backedup(object, 2));
    CU_ASSERT(!dbo_hsm_key_set_requirebackup(object, 2));
}

static void test_dbo_hsm_key_update(void) {
    CU_ASSERT_FATAL(!dbo_hsm_key_update(object));
}

static void test_dbo_hsm_key_read2(void) {
    CU_ASSERT_FATAL(!dbo_hsm_key_get_by_id(object, &id));
}

static void test_dbo_hsm_key_verify2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_locator(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_locator(object), "locator 2"));
    CU_ASSERT(dbo_hsm_key_candidate_for_sharing(object) == 2);
    CU_ASSERT(dbo_hsm_key_bits(object) == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_policy(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_policy(object), "policy 2"));
    CU_ASSERT(dbo_hsm_key_algorithm(object) == 2);
    CU_ASSERT(dbo_hsm_key_role(object) == DBO_HSM_KEY_ROLE_KSK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_role_text(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_role_text(object), "KSK"));
    CU_ASSERT(dbo_hsm_key_inception(object) == 2);
    CU_ASSERT(dbo_hsm_key_isrevoked(object) == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_key_type(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_key_type(object), "key_type 2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(dbo_hsm_key_repository(object));
    CU_ASSERT(!strcmp(dbo_hsm_key_repository(object), "repository 2"));
    CU_ASSERT(dbo_hsm_key_backmeup(object) == 2);
    CU_ASSERT(dbo_hsm_key_backedup(object) == 2);
    CU_ASSERT(dbo_hsm_key_requirebackup(object) == 2);
}

static void test_dbo_hsm_key_delete(void) {
    CU_ASSERT_FATAL(!dbo_hsm_key_delete(object));
}

static void test_dbo_hsm_key_list2(void) {
    CU_ASSERT_FATAL(!dbo_hsm_key_list_get(object_list));
    CU_ASSERT_PTR_NULL(dbo_hsm_key_list_begin(object_list));
}

static void test_dbo_hsm_key_end(void) {
    if (object) {
        dbo_hsm_key_free(object);
        CU_PASS("dbo_hsm_key_free");
    }
    if (object_list) {
        dbo_hsm_key_list_free(object_list);
        CU_PASS("dbo_hsm_key_list_free");
    }
}

static int test_dbo_hsm_key_add_tests(CU_pSuite pSuite) {
    if (!CU_add_test(pSuite, "new object", test_dbo_hsm_key_new)
        || !CU_add_test(pSuite, "set fields", test_dbo_hsm_key_set)
        || !CU_add_test(pSuite, "get fields", test_dbo_hsm_key_get)
        || !CU_add_test(pSuite, "create object", test_dbo_hsm_key_create)
        || !CU_add_test(pSuite, "list objects", test_dbo_hsm_key_list)
        || !CU_add_test(pSuite, "read object by id", test_dbo_hsm_key_read)
        || !CU_add_test(pSuite, "verify fields", test_dbo_hsm_key_verify)
        || !CU_add_test(pSuite, "change object", test_dbo_hsm_key_change)
        || !CU_add_test(pSuite, "update object", test_dbo_hsm_key_update)
        || !CU_add_test(pSuite, "reread object by id", test_dbo_hsm_key_read2)
        || !CU_add_test(pSuite, "verify fields after update", test_dbo_hsm_key_verify2)
        || !CU_add_test(pSuite, "delete object", test_dbo_hsm_key_delete)
        || !CU_add_test(pSuite, "list objects to verify delete", test_dbo_hsm_key_list2)
        || !CU_add_test(pSuite, "end test", test_dbo_hsm_key_end))
    {
        return CU_get_error();
    }
    return 0;
}

int test_dbo_hsm_key_add_suite(void) {
    CU_pSuite pSuite = NULL;
    int ret;

#if defined(ENFORCER_DATABASE_SQLITE3)
    pSuite = CU_add_suite("Test of dbo hsm key (SQLite)", test_dbo_hsm_key_init_suite_sqlite, test_dbo_hsm_key_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_dbo_hsm_key_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
#if defined(ENFORCER_DATABASE_COUCHDB)
    pSuite = CU_add_suite("Test of dbo hsm key (CouchDB)", test_dbo_hsm_key_init_suite_couchdb, test_dbo_hsm_key_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_dbo_hsm_key_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
    return 0;
}
