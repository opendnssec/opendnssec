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
#include "../enforcer_zone.h"

#include <string.h>

static db_configuration_list_t* configuration_list = NULL;
static db_configuration_t* configuration = NULL;
static db_connection_t* connection = NULL;

static enforcer_zone_t* object = NULL;
static enforcer_zone_list_t* object_list = NULL;
static db_value_t id;

#if defined(ENFORCER_DATABASE_SQLITE3)
int test_enforcer_zone_init_suite_sqlite(void) {
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

    db_value_reset(&id);
    return 0;
}
#endif

#if defined(ENFORCER_DATABASE_COUCHDB)
int test_enforcer_zone_init_suite_couchdb(void) {
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

    db_value_reset(&id);
    return 0;
}
#endif

static int test_enforcer_zone_clean_suite(void) {
    db_connection_free(connection);
    connection = NULL;
    db_configuration_free(configuration);
    configuration = NULL;
    db_configuration_list_free(configuration_list);
    configuration_list = NULL;
    db_value_reset(&id);
    return 0;
}

static void test_enforcer_zone_new(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((object = enforcer_zone_new(connection)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_list = enforcer_zone_list_new(connection)));
}

static void test_enforcer_zone_set(void) {
    CU_ASSERT(!enforcer_zone_set_name(object, "name 1"));
    CU_ASSERT(!enforcer_zone_set_policy(object, "policy 1"));
    CU_ASSERT(!enforcer_zone_set_signconf_needs_writing(object, 1));
    CU_ASSERT(!enforcer_zone_set_signconf_path(object, "signconf_path 1"));
    CU_ASSERT(!enforcer_zone_set_next_change(object, 1));
    CU_ASSERT(!enforcer_zone_set_ttl_end_ds(object, 1));
    CU_ASSERT(!enforcer_zone_set_ttl_end_dk(object, 1));
    CU_ASSERT(!enforcer_zone_set_ttl_end_rs(object, 1));
    CU_ASSERT(!enforcer_zone_set_roll_ksk_now(object, 1));
    CU_ASSERT(!enforcer_zone_set_roll_zsk_now(object, 1));
    CU_ASSERT(!enforcer_zone_set_roll_csk_now(object, 1));
    CU_ASSERT(!enforcer_zone_set_adapters(object, 1));
    CU_ASSERT(!enforcer_zone_set_next_ksk_roll(object, 1));
    CU_ASSERT(!enforcer_zone_set_next_zsk_roll(object, 1));
    CU_ASSERT(!enforcer_zone_set_next_csk_roll(object, 1));
}

static void test_enforcer_zone_get(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(enforcer_zone_name(object));
    CU_ASSERT(!strcmp(enforcer_zone_name(object), "name 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enforcer_zone_policy(object));
    CU_ASSERT(!strcmp(enforcer_zone_policy(object), "policy 1"));
    CU_ASSERT(enforcer_zone_signconf_needs_writing(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(enforcer_zone_signconf_path(object));
    CU_ASSERT(!strcmp(enforcer_zone_signconf_path(object), "signconf_path 1"));
    CU_ASSERT(enforcer_zone_next_change(object) == 1);
    CU_ASSERT(enforcer_zone_ttl_end_ds(object) == 1);
    CU_ASSERT(enforcer_zone_ttl_end_dk(object) == 1);
    CU_ASSERT(enforcer_zone_ttl_end_rs(object) == 1);
    CU_ASSERT(enforcer_zone_roll_ksk_now(object) == 1);
    CU_ASSERT(enforcer_zone_roll_zsk_now(object) == 1);
    CU_ASSERT(enforcer_zone_roll_csk_now(object) == 1);
    CU_ASSERT(enforcer_zone_adapters(object) == 1);
    CU_ASSERT(enforcer_zone_next_ksk_roll(object) == 1);
    CU_ASSERT(enforcer_zone_next_zsk_roll(object) == 1);
    CU_ASSERT(enforcer_zone_next_csk_roll(object) == 1);
}

static void test_enforcer_zone_create(void) {
    CU_ASSERT_FATAL(!enforcer_zone_create(object));
}

static void test_enforcer_zone_list(void) {
    const enforcer_zone_t* item;
    CU_ASSERT_FATAL(!enforcer_zone_list_get(object_list));
    CU_ASSERT_PTR_NOT_NULL_FATAL((item = enforcer_zone_list_begin(object_list)));
    CU_ASSERT_FATAL(!db_value_copy(&id, enforcer_zone_id(item)));
}

static void test_enforcer_zone_read(void) {
    CU_ASSERT_FATAL(!enforcer_zone_get_by_id(object, &id));
}

static void test_enforcer_zone_verify(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(enforcer_zone_name(object));
    CU_ASSERT(!strcmp(enforcer_zone_name(object), "name 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enforcer_zone_policy(object));
    CU_ASSERT(!strcmp(enforcer_zone_policy(object), "policy 1"));
    CU_ASSERT(enforcer_zone_signconf_needs_writing(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(enforcer_zone_signconf_path(object));
    CU_ASSERT(!strcmp(enforcer_zone_signconf_path(object), "signconf_path 1"));
    CU_ASSERT(enforcer_zone_next_change(object) == 1);
    CU_ASSERT(enforcer_zone_ttl_end_ds(object) == 1);
    CU_ASSERT(enforcer_zone_ttl_end_dk(object) == 1);
    CU_ASSERT(enforcer_zone_ttl_end_rs(object) == 1);
    CU_ASSERT(enforcer_zone_roll_ksk_now(object) == 1);
    CU_ASSERT(enforcer_zone_roll_zsk_now(object) == 1);
    CU_ASSERT(enforcer_zone_roll_csk_now(object) == 1);
    CU_ASSERT(enforcer_zone_adapters(object) == 1);
    CU_ASSERT(enforcer_zone_next_ksk_roll(object) == 1);
    CU_ASSERT(enforcer_zone_next_zsk_roll(object) == 1);
    CU_ASSERT(enforcer_zone_next_csk_roll(object) == 1);
}

static void test_enforcer_zone_change(void) {
    CU_ASSERT(!enforcer_zone_set_name(object, "name 2"));
    CU_ASSERT(!enforcer_zone_set_policy(object, "policy 2"));
    CU_ASSERT(!enforcer_zone_set_signconf_needs_writing(object, 2));
    CU_ASSERT(!enforcer_zone_set_signconf_path(object, "signconf_path 2"));
    CU_ASSERT(!enforcer_zone_set_next_change(object, 2));
    CU_ASSERT(!enforcer_zone_set_ttl_end_ds(object, 2));
    CU_ASSERT(!enforcer_zone_set_ttl_end_dk(object, 2));
    CU_ASSERT(!enforcer_zone_set_ttl_end_rs(object, 2));
    CU_ASSERT(!enforcer_zone_set_roll_ksk_now(object, 2));
    CU_ASSERT(!enforcer_zone_set_roll_zsk_now(object, 2));
    CU_ASSERT(!enforcer_zone_set_roll_csk_now(object, 2));
    CU_ASSERT(!enforcer_zone_set_adapters(object, 2));
    CU_ASSERT(!enforcer_zone_set_next_ksk_roll(object, 2));
    CU_ASSERT(!enforcer_zone_set_next_zsk_roll(object, 2));
    CU_ASSERT(!enforcer_zone_set_next_csk_roll(object, 2));
}

static void test_enforcer_zone_update(void) {
    CU_ASSERT_FATAL(!enforcer_zone_update(object));
}

static void test_enforcer_zone_read2(void) {
    CU_ASSERT_FATAL(!enforcer_zone_get_by_id(object, &id));
}

static void test_enforcer_zone_verify2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(enforcer_zone_name(object));
    CU_ASSERT(!strcmp(enforcer_zone_name(object), "name 2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enforcer_zone_policy(object));
    CU_ASSERT(!strcmp(enforcer_zone_policy(object), "policy 2"));
    CU_ASSERT(enforcer_zone_signconf_needs_writing(object) == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(enforcer_zone_signconf_path(object));
    CU_ASSERT(!strcmp(enforcer_zone_signconf_path(object), "signconf_path 2"));
    CU_ASSERT(enforcer_zone_next_change(object) == 2);
    CU_ASSERT(enforcer_zone_ttl_end_ds(object) == 2);
    CU_ASSERT(enforcer_zone_ttl_end_dk(object) == 2);
    CU_ASSERT(enforcer_zone_ttl_end_rs(object) == 2);
    CU_ASSERT(enforcer_zone_roll_ksk_now(object) == 2);
    CU_ASSERT(enforcer_zone_roll_zsk_now(object) == 2);
    CU_ASSERT(enforcer_zone_roll_csk_now(object) == 2);
    CU_ASSERT(enforcer_zone_adapters(object) == 2);
    CU_ASSERT(enforcer_zone_next_ksk_roll(object) == 2);
    CU_ASSERT(enforcer_zone_next_zsk_roll(object) == 2);
    CU_ASSERT(enforcer_zone_next_csk_roll(object) == 2);
}

static void test_enforcer_zone_delete(void) {
    CU_ASSERT_FATAL(!enforcer_zone_delete(object));
}

static void test_enforcer_zone_list2(void) {
    CU_ASSERT_FATAL(!enforcer_zone_list_get(object_list));
    CU_ASSERT_PTR_NULL(enforcer_zone_list_begin(object_list));
}

static void test_enforcer_zone_end(void) {
    if (object) {
        enforcer_zone_free(object);
        CU_PASS("enforcer_zone_free");
    }
    if (object_list) {
        enforcer_zone_list_free(object_list);
        CU_PASS("enforcer_zone_list_free");
    }
}

static int test_enforcer_zone_add_tests(CU_pSuite pSuite) {
    if (!CU_add_test(pSuite, "new object", test_enforcer_zone_new)
        || !CU_add_test(pSuite, "set fields", test_enforcer_zone_set)
        || !CU_add_test(pSuite, "get fields", test_enforcer_zone_get)
        || !CU_add_test(pSuite, "create object", test_enforcer_zone_create)
        || !CU_add_test(pSuite, "list objects", test_enforcer_zone_list)
        || !CU_add_test(pSuite, "read object by id", test_enforcer_zone_read)
        || !CU_add_test(pSuite, "verify fields", test_enforcer_zone_verify)
        || !CU_add_test(pSuite, "change object", test_enforcer_zone_change)
        || !CU_add_test(pSuite, "update object", test_enforcer_zone_update)
        || !CU_add_test(pSuite, "reread object by id", test_enforcer_zone_read2)
        || !CU_add_test(pSuite, "verify fields after update", test_enforcer_zone_verify2)
        || !CU_add_test(pSuite, "delete object", test_enforcer_zone_delete)
        || !CU_add_test(pSuite, "list objects to verify delete", test_enforcer_zone_list2)
        || !CU_add_test(pSuite, "end test", test_enforcer_zone_end))
    {
        return CU_get_error();
    }
    return 0;
}

int test_enforcer_zone_add_suite(void) {
    CU_pSuite pSuite = NULL;
    int ret;

#if defined(ENFORCER_DATABASE_SQLITE3)
    pSuite = CU_add_suite("Test of enforcer zone (SQLite)", test_enforcer_zone_init_suite_sqlite, test_enforcer_zone_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_enforcer_zone_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
#if defined(ENFORCER_DATABASE_COUCHDB)
    pSuite = CU_add_suite("Test of enforcer zone (CouchDB)", test_enforcer_zone_init_suite_couchdb, test_enforcer_zone_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_enforcer_zone_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
    return 0;
}
