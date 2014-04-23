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
#include "../policy.h"

#include <string.h>

static db_configuration_list_t* configuration_list = NULL;
static db_configuration_t* configuration = NULL;
static db_connection_t* connection = NULL;

static policy_t* object = NULL;
static policy_list_t* object_list = NULL;
static db_value_t id = DB_VALUE_EMPTY;

#if defined(ENFORCER_DATABASE_SQLITE3)
int test_policy_init_suite_sqlite(void) {
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
int test_policy_init_suite_couchdb(void) {
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

static int test_policy_clean_suite(void) {
    db_connection_free(connection);
    connection = NULL;
    db_configuration_free(configuration);
    configuration = NULL;
    db_configuration_list_free(configuration_list);
    configuration_list = NULL;
    db_value_reset(&id);
    return 0;
}

static void test_policy_new(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((object = policy_new(connection)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_list = policy_list_new(connection)));
}

static void test_policy_set(void) {
    CU_ASSERT(!policy_set_name(object, "name 1"));
    CU_ASSERT(!policy_set_description(object, "description 1"));
    CU_ASSERT(!policy_set_signatures_resign(object, 1));
    CU_ASSERT(!policy_set_signatures_refresh(object, 1));
    CU_ASSERT(!policy_set_signatures_jitter(object, 1));
    CU_ASSERT(!policy_set_signatures_inception_offset(object, 1));
    CU_ASSERT(!policy_set_signatures_validity_default(object, 1));
    CU_ASSERT(!policy_set_signatures_validity_denial(object, 1));
    CU_ASSERT(!policy_set_signatures_max_zone_ttl(object, 1));
    CU_ASSERT(!policy_set_denial_type(object, POLICY_DENIAL_TYPE_NSEC));
    CU_ASSERT(!policy_set_denial_type_text(object, "NSEC"));
    CU_ASSERT(!policy_set_denial_type(object, POLICY_DENIAL_TYPE_NSEC3));
    CU_ASSERT(!policy_set_denial_type_text(object, "NSEC3"));
    CU_ASSERT(!policy_set_denial_optout(object, 1));
    CU_ASSERT(!policy_set_denial_ttl(object, 1));
    CU_ASSERT(!policy_set_denial_resalt(object, 1));
    CU_ASSERT(!policy_set_denial_algorithm(object, 1));
    CU_ASSERT(!policy_set_denial_iterations(object, 1));
    CU_ASSERT(!policy_set_denial_salt_length(object, 1));
    CU_ASSERT(!policy_set_denial_salt(object, "denial_salt 1"));
    CU_ASSERT(!policy_set_denial_salt_last_change(object, 1));
    CU_ASSERT(!policy_set_keys_ttl(object, 1));
    CU_ASSERT(!policy_set_keys_retire_safety(object, 1));
    CU_ASSERT(!policy_set_keys_publish_safety(object, 1));
    CU_ASSERT(!policy_set_keys_shared(object, 1));
    CU_ASSERT(!policy_set_keys_purge_after(object, 1));
    CU_ASSERT(!policy_set_zone_propagation_delay(object, 1));
    CU_ASSERT(!policy_set_zone_soa_ttl(object, 1));
    CU_ASSERT(!policy_set_zone_soa_minimum(object, 1));
    CU_ASSERT(!policy_set_zone_soa_serial(object, POLICY_ZONE_SOA_SERIAL_COUNTER));
    CU_ASSERT(!policy_set_zone_soa_serial_text(object, "counter"));
    CU_ASSERT(!policy_set_zone_soa_serial(object, POLICY_ZONE_SOA_SERIAL_DATECOUNTER));
    CU_ASSERT(!policy_set_zone_soa_serial_text(object, "datecounter"));
    CU_ASSERT(!policy_set_zone_soa_serial(object, POLICY_ZONE_SOA_SERIAL_UNIXTIME));
    CU_ASSERT(!policy_set_zone_soa_serial_text(object, "unixtime"));
    CU_ASSERT(!policy_set_zone_soa_serial(object, POLICY_ZONE_SOA_SERIAL_KEEP));
    CU_ASSERT(!policy_set_zone_soa_serial_text(object, "keep"));
    CU_ASSERT(!policy_set_parent_propagation_delay(object, 1));
    CU_ASSERT(!policy_set_parent_ds_ttl(object, 1));
    CU_ASSERT(!policy_set_parent_soa_ttl(object, 1));
    CU_ASSERT(!policy_set_parent_soa_minimum(object, 1));
}

static void test_policy_get(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_name(object));
    CU_ASSERT(!strcmp(policy_name(object), "name 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_description(object));
    CU_ASSERT(!strcmp(policy_description(object), "description 1"));
    CU_ASSERT(policy_signatures_resign(object) == 1);
    CU_ASSERT(policy_signatures_refresh(object) == 1);
    CU_ASSERT(policy_signatures_jitter(object) == 1);
    CU_ASSERT(policy_signatures_inception_offset(object) == 1);
    CU_ASSERT(policy_signatures_validity_default(object) == 1);
    CU_ASSERT(policy_signatures_validity_denial(object) == 1);
    CU_ASSERT(policy_signatures_max_zone_ttl(object) == 1);
    CU_ASSERT(policy_denial_type(object) == POLICY_DENIAL_TYPE_NSEC3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_denial_type_text(object));
    CU_ASSERT(!strcmp(policy_denial_type_text(object), "NSEC3"));
    CU_ASSERT(policy_denial_optout(object) == 1);
    CU_ASSERT(policy_denial_ttl(object) == 1);
    CU_ASSERT(policy_denial_resalt(object) == 1);
    CU_ASSERT(policy_denial_algorithm(object) == 1);
    CU_ASSERT(policy_denial_iterations(object) == 1);
    CU_ASSERT(policy_denial_salt_length(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_denial_salt(object));
    CU_ASSERT(!strcmp(policy_denial_salt(object), "denial_salt 1"));
    CU_ASSERT(policy_denial_salt_last_change(object) == 1);
    CU_ASSERT(policy_keys_ttl(object) == 1);
    CU_ASSERT(policy_keys_retire_safety(object) == 1);
    CU_ASSERT(policy_keys_publish_safety(object) == 1);
    CU_ASSERT(policy_keys_shared(object) == 1);
    CU_ASSERT(policy_keys_purge_after(object) == 1);
    CU_ASSERT(policy_zone_propagation_delay(object) == 1);
    CU_ASSERT(policy_zone_soa_ttl(object) == 1);
    CU_ASSERT(policy_zone_soa_minimum(object) == 1);
    CU_ASSERT(policy_zone_soa_serial(object) == POLICY_ZONE_SOA_SERIAL_KEEP);
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_zone_soa_serial_text(object));
    CU_ASSERT(!strcmp(policy_zone_soa_serial_text(object), "keep"));
    CU_ASSERT(policy_parent_propagation_delay(object) == 1);
    CU_ASSERT(policy_parent_ds_ttl(object) == 1);
    CU_ASSERT(policy_parent_soa_ttl(object) == 1);
    CU_ASSERT(policy_parent_soa_minimum(object) == 1);
}

static void test_policy_create(void) {
    CU_ASSERT_FATAL(!policy_create(object));
}

static void test_policy_list(void) {
    const policy_t* item;
    CU_ASSERT_FATAL(!policy_list_get(object_list));
    CU_ASSERT_PTR_NOT_NULL_FATAL((item = policy_list_begin(object_list)));
    CU_ASSERT_FATAL(!db_value_copy(&id, policy_id(item)));
}

static void test_policy_read(void) {
    CU_ASSERT_FATAL(!policy_get_by_id(object, &id));
}

static void test_policy_verify(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_name(object));
    CU_ASSERT(!strcmp(policy_name(object), "name 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_description(object));
    CU_ASSERT(!strcmp(policy_description(object), "description 1"));
    CU_ASSERT(policy_signatures_resign(object) == 1);
    CU_ASSERT(policy_signatures_refresh(object) == 1);
    CU_ASSERT(policy_signatures_jitter(object) == 1);
    CU_ASSERT(policy_signatures_inception_offset(object) == 1);
    CU_ASSERT(policy_signatures_validity_default(object) == 1);
    CU_ASSERT(policy_signatures_validity_denial(object) == 1);
    CU_ASSERT(policy_signatures_max_zone_ttl(object) == 1);
    CU_ASSERT(policy_denial_type(object) == POLICY_DENIAL_TYPE_NSEC3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_denial_type_text(object));
    CU_ASSERT(!strcmp(policy_denial_type_text(object), "NSEC3"));
    CU_ASSERT(policy_denial_optout(object) == 1);
    CU_ASSERT(policy_denial_ttl(object) == 1);
    CU_ASSERT(policy_denial_resalt(object) == 1);
    CU_ASSERT(policy_denial_algorithm(object) == 1);
    CU_ASSERT(policy_denial_iterations(object) == 1);
    CU_ASSERT(policy_denial_salt_length(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_denial_salt(object));
    CU_ASSERT(!strcmp(policy_denial_salt(object), "denial_salt 1"));
    CU_ASSERT(policy_denial_salt_last_change(object) == 1);
    CU_ASSERT(policy_keys_ttl(object) == 1);
    CU_ASSERT(policy_keys_retire_safety(object) == 1);
    CU_ASSERT(policy_keys_publish_safety(object) == 1);
    CU_ASSERT(policy_keys_shared(object) == 1);
    CU_ASSERT(policy_keys_purge_after(object) == 1);
    CU_ASSERT(policy_zone_propagation_delay(object) == 1);
    CU_ASSERT(policy_zone_soa_ttl(object) == 1);
    CU_ASSERT(policy_zone_soa_minimum(object) == 1);
    CU_ASSERT(policy_zone_soa_serial(object) == POLICY_ZONE_SOA_SERIAL_KEEP);
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_zone_soa_serial_text(object));
    CU_ASSERT(!strcmp(policy_zone_soa_serial_text(object), "keep"));
    CU_ASSERT(policy_parent_propagation_delay(object) == 1);
    CU_ASSERT(policy_parent_ds_ttl(object) == 1);
    CU_ASSERT(policy_parent_soa_ttl(object) == 1);
    CU_ASSERT(policy_parent_soa_minimum(object) == 1);
}

static void test_policy_change(void) {
    CU_ASSERT(!policy_set_name(object, "name 2"));
    CU_ASSERT(!policy_set_description(object, "description 2"));
    CU_ASSERT(!policy_set_signatures_resign(object, 2));
    CU_ASSERT(!policy_set_signatures_refresh(object, 2));
    CU_ASSERT(!policy_set_signatures_jitter(object, 2));
    CU_ASSERT(!policy_set_signatures_inception_offset(object, 2));
    CU_ASSERT(!policy_set_signatures_validity_default(object, 2));
    CU_ASSERT(!policy_set_signatures_validity_denial(object, 2));
    CU_ASSERT(!policy_set_signatures_max_zone_ttl(object, 2));
    CU_ASSERT(!policy_set_denial_type(object, POLICY_DENIAL_TYPE_NSEC));
    CU_ASSERT(!policy_set_denial_type_text(object, "NSEC"));
    CU_ASSERT(!policy_set_denial_optout(object, 2));
    CU_ASSERT(!policy_set_denial_ttl(object, 2));
    CU_ASSERT(!policy_set_denial_resalt(object, 2));
    CU_ASSERT(!policy_set_denial_algorithm(object, 2));
    CU_ASSERT(!policy_set_denial_iterations(object, 2));
    CU_ASSERT(!policy_set_denial_salt_length(object, 2));
    CU_ASSERT(!policy_set_denial_salt(object, "denial_salt 2"));
    CU_ASSERT(!policy_set_denial_salt_last_change(object, 2));
    CU_ASSERT(!policy_set_keys_ttl(object, 2));
    CU_ASSERT(!policy_set_keys_retire_safety(object, 2));
    CU_ASSERT(!policy_set_keys_publish_safety(object, 2));
    CU_ASSERT(!policy_set_keys_shared(object, 2));
    CU_ASSERT(!policy_set_keys_purge_after(object, 2));
    CU_ASSERT(!policy_set_zone_propagation_delay(object, 2));
    CU_ASSERT(!policy_set_zone_soa_ttl(object, 2));
    CU_ASSERT(!policy_set_zone_soa_minimum(object, 2));
    CU_ASSERT(!policy_set_zone_soa_serial(object, POLICY_ZONE_SOA_SERIAL_COUNTER));
    CU_ASSERT(!policy_set_zone_soa_serial_text(object, "counter"));
    CU_ASSERT(!policy_set_parent_propagation_delay(object, 2));
    CU_ASSERT(!policy_set_parent_ds_ttl(object, 2));
    CU_ASSERT(!policy_set_parent_soa_ttl(object, 2));
    CU_ASSERT(!policy_set_parent_soa_minimum(object, 2));
}

static void test_policy_update(void) {
    CU_ASSERT_FATAL(!policy_update(object));
}

static void test_policy_read2(void) {
    CU_ASSERT_FATAL(!policy_get_by_id(object, &id));
}

static void test_policy_verify2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_name(object));
    CU_ASSERT(!strcmp(policy_name(object), "name 2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_description(object));
    CU_ASSERT(!strcmp(policy_description(object), "description 2"));
    CU_ASSERT(policy_signatures_resign(object) == 2);
    CU_ASSERT(policy_signatures_refresh(object) == 2);
    CU_ASSERT(policy_signatures_jitter(object) == 2);
    CU_ASSERT(policy_signatures_inception_offset(object) == 2);
    CU_ASSERT(policy_signatures_validity_default(object) == 2);
    CU_ASSERT(policy_signatures_validity_denial(object) == 2);
    CU_ASSERT(policy_signatures_max_zone_ttl(object) == 2);
    CU_ASSERT(policy_denial_type(object) == POLICY_DENIAL_TYPE_NSEC);
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_denial_type_text(object));
    CU_ASSERT(!strcmp(policy_denial_type_text(object), "NSEC"));
    CU_ASSERT(policy_denial_optout(object) == 2);
    CU_ASSERT(policy_denial_ttl(object) == 2);
    CU_ASSERT(policy_denial_resalt(object) == 2);
    CU_ASSERT(policy_denial_algorithm(object) == 2);
    CU_ASSERT(policy_denial_iterations(object) == 2);
    CU_ASSERT(policy_denial_salt_length(object) == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_denial_salt(object));
    CU_ASSERT(!strcmp(policy_denial_salt(object), "denial_salt 2"));
    CU_ASSERT(policy_denial_salt_last_change(object) == 2);
    CU_ASSERT(policy_keys_ttl(object) == 2);
    CU_ASSERT(policy_keys_retire_safety(object) == 2);
    CU_ASSERT(policy_keys_publish_safety(object) == 2);
    CU_ASSERT(policy_keys_shared(object) == 2);
    CU_ASSERT(policy_keys_purge_after(object) == 2);
    CU_ASSERT(policy_zone_propagation_delay(object) == 2);
    CU_ASSERT(policy_zone_soa_ttl(object) == 2);
    CU_ASSERT(policy_zone_soa_minimum(object) == 2);
    CU_ASSERT(policy_zone_soa_serial(object) == POLICY_ZONE_SOA_SERIAL_COUNTER);
    CU_ASSERT_PTR_NOT_NULL_FATAL(policy_zone_soa_serial_text(object));
    CU_ASSERT(!strcmp(policy_zone_soa_serial_text(object), "counter"));
    CU_ASSERT(policy_parent_propagation_delay(object) == 2);
    CU_ASSERT(policy_parent_ds_ttl(object) == 2);
    CU_ASSERT(policy_parent_soa_ttl(object) == 2);
    CU_ASSERT(policy_parent_soa_minimum(object) == 2);
}

static void test_policy_delete(void) {
    CU_ASSERT_FATAL(!policy_delete(object));
}

static void test_policy_list2(void) {
    CU_ASSERT_FATAL(!policy_list_get(object_list));
    CU_ASSERT_PTR_NULL(policy_list_begin(object_list));
}

static void test_policy_end(void) {
    if (object) {
        policy_free(object);
        CU_PASS("policy_free");
    }
    if (object_list) {
        policy_list_free(object_list);
        CU_PASS("policy_list_free");
    }
}

static int test_policy_add_tests(CU_pSuite pSuite) {
    if (!CU_add_test(pSuite, "new object", test_policy_new)
        || !CU_add_test(pSuite, "set fields", test_policy_set)
        || !CU_add_test(pSuite, "get fields", test_policy_get)
        || !CU_add_test(pSuite, "create object", test_policy_create)
        || !CU_add_test(pSuite, "list objects", test_policy_list)
        || !CU_add_test(pSuite, "read object by id", test_policy_read)
        || !CU_add_test(pSuite, "verify fields", test_policy_verify)
        || !CU_add_test(pSuite, "change object", test_policy_change)
        || !CU_add_test(pSuite, "update object", test_policy_update)
        || !CU_add_test(pSuite, "reread object by id", test_policy_read2)
        || !CU_add_test(pSuite, "verify fields after update", test_policy_verify2)
        || !CU_add_test(pSuite, "delete object", test_policy_delete)
        || !CU_add_test(pSuite, "list objects to verify delete", test_policy_list2)
        || !CU_add_test(pSuite, "end test", test_policy_end))
    {
        return CU_get_error();
    }
    return 0;
}

int test_policy_add_suite(void) {
    CU_pSuite pSuite = NULL;
    int ret;

#if defined(ENFORCER_DATABASE_SQLITE3)
    pSuite = CU_add_suite("Test of policy (SQLite)", test_policy_init_suite_sqlite, test_policy_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_policy_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
#if defined(ENFORCER_DATABASE_COUCHDB)
    pSuite = CU_add_suite("Test of policy (CouchDB)", test_policy_init_suite_couchdb, test_policy_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_policy_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
    return 0;
}
