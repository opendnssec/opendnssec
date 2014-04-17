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
#include "../key_data.h"

#include <string.h>

static db_configuration_list_t* configuration_list = NULL;
static db_configuration_t* configuration = NULL;
static db_connection_t* connection = NULL;

static key_data_t* object = NULL;
static key_data_list_t* object_list = NULL;
static db_value_t id;

#if defined(ENFORCER_DATABASE_SQLITE3)
int test_key_data_init_suite_sqlite(void) {
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
int test_key_data_init_suite_couchdb(void) {
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

static int test_key_data_clean_suite(void) {
    db_connection_free(connection);
    connection = NULL;
    db_configuration_free(configuration);
    configuration = NULL;
    db_configuration_list_free(configuration_list);
    configuration_list = NULL;
    db_value_reset(&id);
    return 0;
}

static void test_key_data_new(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((object = key_data_new(connection)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_list = key_data_list_new(connection)));
}

static void test_key_data_set(void) {
    CU_ASSERT(!key_data_set_locator(object, "locator 1"));
    CU_ASSERT(!key_data_set_algorithm(object, 1));
    CU_ASSERT(!key_data_set_inception(object, 1));
    CU_ASSERT(!key_data_set_ds(object, 1));
    CU_ASSERT(!key_data_set_rrsig(object, 1));
    CU_ASSERT(!key_data_set_dnskey(object, 1));
    CU_ASSERT(!key_data_set_role(object, KEY_DATA_ROLE_KSK));
    CU_ASSERT(!key_data_set_role_text(object, "KSK"));
    CU_ASSERT(!key_data_set_role(object, KEY_DATA_ROLE_ZSK));
    CU_ASSERT(!key_data_set_role_text(object, "ZSK"));
    CU_ASSERT(!key_data_set_role(object, KEY_DATA_ROLE_CSK));
    CU_ASSERT(!key_data_set_role_text(object, "CSK"));
    CU_ASSERT(!key_data_set_introducing(object, 1));
    CU_ASSERT(!key_data_set_shouldrevoke(object, 1));
    CU_ASSERT(!key_data_set_standby(object, 1));
    CU_ASSERT(!key_data_set_active_zsk(object, 1));
    CU_ASSERT(!key_data_set_publish(object, 1));
    CU_ASSERT(!key_data_set_rrsigdnskey(object, 1));
    CU_ASSERT(!key_data_set_active_ksk(object, 1));
    CU_ASSERT(!key_data_set_ds_at_parent(object, KEY_DATA_DS_AT_PARENT_UNSUBMITTED));
    CU_ASSERT(!key_data_set_ds_at_parent_text(object, "unsubmitted"));
    CU_ASSERT(!key_data_set_ds_at_parent(object, KEY_DATA_DS_AT_PARENT_SUBMIT));
    CU_ASSERT(!key_data_set_ds_at_parent_text(object, "submit"));
    CU_ASSERT(!key_data_set_ds_at_parent(object, KEY_DATA_DS_AT_PARENT_SUBMITTED));
    CU_ASSERT(!key_data_set_ds_at_parent_text(object, "submitted"));
    CU_ASSERT(!key_data_set_ds_at_parent(object, KEY_DATA_DS_AT_PARENT_SEEN));
    CU_ASSERT(!key_data_set_ds_at_parent_text(object, "seen"));
    CU_ASSERT(!key_data_set_ds_at_parent(object, KEY_DATA_DS_AT_PARENT_RETRACT));
    CU_ASSERT(!key_data_set_ds_at_parent_text(object, "retract"));
    CU_ASSERT(!key_data_set_ds_at_parent(object, KEY_DATA_DS_AT_PARENT_RETRACTED));
    CU_ASSERT(!key_data_set_ds_at_parent_text(object, "retracted"));
    CU_ASSERT(!key_data_set_keytag(object, 1));
}

static void test_key_data_get(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_data_locator(object));
    CU_ASSERT(!strcmp(key_data_locator(object), "locator 1"));
    CU_ASSERT(key_data_algorithm(object) == 1);
    CU_ASSERT(key_data_inception(object) == 1);
    CU_ASSERT(key_data_ds(object) == 1);
    CU_ASSERT(key_data_rrsig(object) == 1);
    CU_ASSERT(key_data_dnskey(object) == 1);
    CU_ASSERT(key_data_role(object) == KEY_DATA_ROLE_CSK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_data_role_text(object));
    CU_ASSERT(!strcmp(key_data_role_text(object), "CSK"));
    CU_ASSERT(key_data_introducing(object) == 1);
    CU_ASSERT(key_data_shouldrevoke(object) == 1);
    CU_ASSERT(key_data_standby(object) == 1);
    CU_ASSERT(key_data_active_zsk(object) == 1);
    CU_ASSERT(key_data_publish(object) == 1);
    CU_ASSERT(key_data_rrsigdnskey(object) == 1);
    CU_ASSERT(key_data_active_ksk(object) == 1);
    CU_ASSERT(key_data_ds_at_parent(object) == KEY_DATA_DS_AT_PARENT_RETRACTED);
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_data_ds_at_parent_text(object));
    CU_ASSERT(!strcmp(key_data_ds_at_parent_text(object), "retracted"));
    CU_ASSERT(key_data_keytag(object) == 1);
}

static void test_key_data_create(void) {
    CU_ASSERT_FATAL(!key_data_create(object));
}

static void test_key_data_list(void) {
    const key_data_t* item;
    CU_ASSERT_FATAL(!key_data_list_get(object_list));
    CU_ASSERT_PTR_NOT_NULL_FATAL((item = key_data_list_begin(object_list)));
    CU_ASSERT_FATAL(!db_value_copy(&id, key_data_id(item)));
}

static void test_key_data_read(void) {
    CU_ASSERT_FATAL(!key_data_get_by_id(object, &id));
}

static void test_key_data_verify(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_data_locator(object));
    CU_ASSERT(!strcmp(key_data_locator(object), "locator 1"));
    CU_ASSERT(key_data_algorithm(object) == 1);
    CU_ASSERT(key_data_inception(object) == 1);
    CU_ASSERT(key_data_ds(object) == 1);
    CU_ASSERT(key_data_rrsig(object) == 1);
    CU_ASSERT(key_data_dnskey(object) == 1);
    CU_ASSERT(key_data_role(object) == KEY_DATA_ROLE_CSK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_data_role_text(object));
    CU_ASSERT(!strcmp(key_data_role_text(object), "CSK"));
    CU_ASSERT(key_data_introducing(object) == 1);
    CU_ASSERT(key_data_shouldrevoke(object) == 1);
    CU_ASSERT(key_data_standby(object) == 1);
    CU_ASSERT(key_data_active_zsk(object) == 1);
    CU_ASSERT(key_data_publish(object) == 1);
    CU_ASSERT(key_data_rrsigdnskey(object) == 1);
    CU_ASSERT(key_data_active_ksk(object) == 1);
    CU_ASSERT(key_data_ds_at_parent(object) == KEY_DATA_DS_AT_PARENT_RETRACTED);
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_data_ds_at_parent_text(object));
    CU_ASSERT(!strcmp(key_data_ds_at_parent_text(object), "retracted"));
    CU_ASSERT(key_data_keytag(object) == 1);
}

static void test_key_data_change(void) {
    CU_ASSERT(!key_data_set_locator(object, "locator 2"));
    CU_ASSERT(!key_data_set_algorithm(object, 2));
    CU_ASSERT(!key_data_set_inception(object, 2));
    CU_ASSERT(!key_data_set_ds(object, 2));
    CU_ASSERT(!key_data_set_rrsig(object, 2));
    CU_ASSERT(!key_data_set_dnskey(object, 2));
    CU_ASSERT(!key_data_set_role(object, KEY_DATA_ROLE_KSK));
    CU_ASSERT(!key_data_set_role_text(object, "KSK"));
    CU_ASSERT(!key_data_set_introducing(object, 2));
    CU_ASSERT(!key_data_set_shouldrevoke(object, 2));
    CU_ASSERT(!key_data_set_standby(object, 2));
    CU_ASSERT(!key_data_set_active_zsk(object, 2));
    CU_ASSERT(!key_data_set_publish(object, 2));
    CU_ASSERT(!key_data_set_rrsigdnskey(object, 2));
    CU_ASSERT(!key_data_set_active_ksk(object, 2));
    CU_ASSERT(!key_data_set_ds_at_parent(object, KEY_DATA_DS_AT_PARENT_UNSUBMITTED));
    CU_ASSERT(!key_data_set_ds_at_parent_text(object, "unsubmitted"));
    CU_ASSERT(!key_data_set_keytag(object, 2));
}

static void test_key_data_update(void) {
    CU_ASSERT_FATAL(!key_data_update(object));
}

static void test_key_data_read2(void) {
    CU_ASSERT_FATAL(!key_data_get_by_id(object, &id));
}

static void test_key_data_verify2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_data_locator(object));
    CU_ASSERT(!strcmp(key_data_locator(object), "locator 2"));
    CU_ASSERT(key_data_algorithm(object) == 2);
    CU_ASSERT(key_data_inception(object) == 2);
    CU_ASSERT(key_data_ds(object) == 2);
    CU_ASSERT(key_data_rrsig(object) == 2);
    CU_ASSERT(key_data_dnskey(object) == 2);
    CU_ASSERT(key_data_role(object) == KEY_DATA_ROLE_KSK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_data_role_text(object));
    CU_ASSERT(!strcmp(key_data_role_text(object), "KSK"));
    CU_ASSERT(key_data_introducing(object) == 2);
    CU_ASSERT(key_data_shouldrevoke(object) == 2);
    CU_ASSERT(key_data_standby(object) == 2);
    CU_ASSERT(key_data_active_zsk(object) == 2);
    CU_ASSERT(key_data_publish(object) == 2);
    CU_ASSERT(key_data_rrsigdnskey(object) == 2);
    CU_ASSERT(key_data_active_ksk(object) == 2);
    CU_ASSERT(key_data_ds_at_parent(object) == KEY_DATA_DS_AT_PARENT_UNSUBMITTED);
    CU_ASSERT_PTR_NOT_NULL_FATAL(key_data_ds_at_parent_text(object));
    CU_ASSERT(!strcmp(key_data_ds_at_parent_text(object), "unsubmitted"));
    CU_ASSERT(key_data_keytag(object) == 2);
}

static void test_key_data_delete(void) {
    CU_ASSERT_FATAL(!key_data_delete(object));
}

static void test_key_data_list2(void) {
    CU_ASSERT_FATAL(!key_data_list_get(object_list));
    CU_ASSERT_PTR_NULL(key_data_list_begin(object_list));
}

static void test_key_data_end(void) {
    if (object) {
        key_data_free(object);
        CU_PASS("key_data_free");
    }
    if (object_list) {
        key_data_list_free(object_list);
        CU_PASS("key_data_list_free");
    }
}

static int test_key_data_add_tests(CU_pSuite pSuite) {
    if (!CU_add_test(pSuite, "new object", test_key_data_new)
        || !CU_add_test(pSuite, "set fields", test_key_data_set)
        || !CU_add_test(pSuite, "get fields", test_key_data_get)
        || !CU_add_test(pSuite, "create object", test_key_data_create)
        || !CU_add_test(pSuite, "list objects", test_key_data_list)
        || !CU_add_test(pSuite, "read object by id", test_key_data_read)
        || !CU_add_test(pSuite, "verify fields", test_key_data_verify)
        || !CU_add_test(pSuite, "change object", test_key_data_change)
        || !CU_add_test(pSuite, "update object", test_key_data_update)
        || !CU_add_test(pSuite, "reread object by id", test_key_data_read2)
        || !CU_add_test(pSuite, "verify fields after update", test_key_data_verify2)
        || !CU_add_test(pSuite, "delete object", test_key_data_delete)
        || !CU_add_test(pSuite, "list objects to verify delete", test_key_data_list2)
        || !CU_add_test(pSuite, "end test", test_key_data_end))
    {
        return CU_get_error();
    }
    return 0;
}

int test_key_data_add_suite(void) {
    CU_pSuite pSuite = NULL;
    int ret;

#if defined(ENFORCER_DATABASE_SQLITE3)
    pSuite = CU_add_suite("Test of key data (SQLite)", test_key_data_init_suite_sqlite, test_key_data_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_key_data_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
#if defined(ENFORCER_DATABASE_COUCHDB)
    pSuite = CU_add_suite("Test of key data (CouchDB)", test_key_data_init_suite_couchdb, test_key_data_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_key_data_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
    return 0;
}
