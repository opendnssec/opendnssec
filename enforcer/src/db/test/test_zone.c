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
#include "../zone.h"

#include <string.h>

static db_configuration_list_t* configuration_list = NULL;
static db_configuration_t* configuration = NULL;
static db_connection_t* connection = NULL;

static zone_t* object = NULL;
static zone_list_t* object_list = NULL;
static db_value_t id = DB_VALUE_EMPTY;
static db_clause_list_t* clause_list = NULL;

static int db_sqlite = 0;
static int db_mysql = 0;

#if defined(ENFORCER_DATABASE_SQLITE3)
int test_zone_init_suite_sqlite(void) {
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
int test_zone_init_suite_mysql(void) {
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

static int test_zone_clean_suite(void) {
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

static void test_zone_new(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((object = zone_new(connection)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_list = zone_list_new(connection)));
}

static void test_zone_set(void) {
    db_value_t policy_id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&policy_id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&policy_id, 1));
    }
    CU_ASSERT(!zone_set_policy_id(object, &policy_id));
    CU_ASSERT(!zone_set_name(object, "name 1"));
    CU_ASSERT(!zone_set_signconf_needs_writing(object, 1));
    CU_ASSERT(!zone_set_signconf_path(object, "signconf_path 1"));
    CU_ASSERT(!zone_set_next_change(object, 1));
    CU_ASSERT(!zone_set_ttl_end_ds(object, 1));
    CU_ASSERT(!zone_set_ttl_end_dk(object, 1));
    CU_ASSERT(!zone_set_ttl_end_rs(object, 1));
    CU_ASSERT(!zone_set_roll_ksk_now(object, 1));
    CU_ASSERT(!zone_set_roll_zsk_now(object, 1));
    CU_ASSERT(!zone_set_roll_csk_now(object, 1));
    CU_ASSERT(!zone_set_input_adapter_type(object, "input_adapter_type 1"));
    CU_ASSERT(!zone_set_input_adapter_uri(object, "input_adapter_uri 1"));
    CU_ASSERT(!zone_set_output_adapter_type(object, "output_adapter_type 1"));
    CU_ASSERT(!zone_set_output_adapter_uri(object, "output_adapter_uri 1"));
    CU_ASSERT(!zone_set_next_ksk_roll(object, 1));
    CU_ASSERT(!zone_set_next_zsk_roll(object, 1));
    CU_ASSERT(!zone_set_next_csk_roll(object, 1));
    db_value_reset(&policy_id);
}

static void test_zone_get(void) {
    int ret;
    db_value_t policy_id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&policy_id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&policy_id, 1));
    }
    CU_ASSERT(!db_value_cmp(zone_policy_id(object), &policy_id, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_name(object));
    CU_ASSERT(!strcmp(zone_name(object), "name 1"));
    CU_ASSERT(zone_signconf_needs_writing(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_signconf_path(object));
    CU_ASSERT(!strcmp(zone_signconf_path(object), "signconf_path 1"));
    CU_ASSERT(zone_next_change(object) == 1);
    CU_ASSERT(zone_ttl_end_ds(object) == 1);
    CU_ASSERT(zone_ttl_end_dk(object) == 1);
    CU_ASSERT(zone_ttl_end_rs(object) == 1);
    CU_ASSERT(zone_roll_ksk_now(object) == 1);
    CU_ASSERT(zone_roll_zsk_now(object) == 1);
    CU_ASSERT(zone_roll_csk_now(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_input_adapter_type(object));
    CU_ASSERT(!strcmp(zone_input_adapter_type(object), "input_adapter_type 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_input_adapter_uri(object));
    CU_ASSERT(!strcmp(zone_input_adapter_uri(object), "input_adapter_uri 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_output_adapter_type(object));
    CU_ASSERT(!strcmp(zone_output_adapter_type(object), "output_adapter_type 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_output_adapter_uri(object));
    CU_ASSERT(!strcmp(zone_output_adapter_uri(object), "output_adapter_uri 1"));
    CU_ASSERT(zone_next_ksk_roll(object) == 1);
    CU_ASSERT(zone_next_zsk_roll(object) == 1);
    CU_ASSERT(zone_next_csk_roll(object) == 1);
    db_value_reset(&policy_id);
}

static void test_zone_create(void) {
    CU_ASSERT_FATAL(!zone_create(object));
}

static void test_zone_clauses(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL(zone_policy_id_clause(clause_list, zone_policy_id(object)));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;
}

static void test_zone_count(void) {
    size_t count;

    CU_ASSERT(!zone_count(object, NULL, &count));
    CU_ASSERT(count == 1);

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL(zone_policy_id_clause(clause_list, zone_policy_id(object)));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT(!zone_count(object, clause_list, &count));
    CU_ASSERT(count == 1);
    db_clause_list_free(clause_list);
    clause_list = NULL;
}

static void test_zone_list(void) {
    const zone_t* item;
    zone_t* item2;
    zone_list_t* new_list;

    CU_ASSERT_FATAL(!zone_list_get(object_list));
    CU_ASSERT_PTR_NOT_NULL_FATAL((item = zone_list_next(object_list)));
    CU_ASSERT_FATAL(!db_value_copy(&id, zone_id(item)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((item = zone_list_begin(object_list)));

    CU_ASSERT_FATAL(!zone_list_get(object_list));
    CU_ASSERT_PTR_NOT_NULL_FATAL((item2 = zone_list_get_next(object_list)));
    zone_free(item2);
    CU_PASS("zone_free");

    CU_ASSERT_PTR_NOT_NULL((new_list = zone_list_new_get(connection)));
    CU_ASSERT_PTR_NOT_NULL(zone_list_next(new_list));
    zone_list_free(new_list);
}

static void test_zone_list_store(void) {
    zone_list_t* new_list;

    CU_ASSERT_PTR_NOT_NULL((new_list = zone_list_new(connection)));
    CU_ASSERT_FATAL(!zone_list_object_store(new_list));
    CU_ASSERT_FATAL(!zone_list_get(new_list));

    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_list_next(new_list));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_list_begin(new_list));

    CU_PASS("zone_free");

    zone_list_free(new_list);
}

static void test_zone_list_associated(void) {
    zone_list_t* new_list;

    CU_ASSERT_PTR_NOT_NULL((new_list = zone_list_new(connection)));
    CU_ASSERT_FATAL(!zone_list_get(new_list));

    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_list_next(new_list));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_list_begin(new_list));

    CU_PASS("zone_free");

    zone_list_free(new_list);
}

static void test_zone_read(void) {
    CU_ASSERT_FATAL(!zone_get_by_id(object, &id));
}

static void test_zone_verify(void) {
    int ret;
    db_value_t policy_id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&policy_id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&policy_id, 1));
    }
    CU_ASSERT(!db_value_cmp(zone_policy_id(object), &policy_id, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_name(object));
    CU_ASSERT(!strcmp(zone_name(object), "name 1"));
    CU_ASSERT(zone_signconf_needs_writing(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_signconf_path(object));
    CU_ASSERT(!strcmp(zone_signconf_path(object), "signconf_path 1"));
    CU_ASSERT(zone_next_change(object) == 1);
    CU_ASSERT(zone_ttl_end_ds(object) == 1);
    CU_ASSERT(zone_ttl_end_dk(object) == 1);
    CU_ASSERT(zone_ttl_end_rs(object) == 1);
    CU_ASSERT(zone_roll_ksk_now(object) == 1);
    CU_ASSERT(zone_roll_zsk_now(object) == 1);
    CU_ASSERT(zone_roll_csk_now(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_input_adapter_type(object));
    CU_ASSERT(!strcmp(zone_input_adapter_type(object), "input_adapter_type 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_input_adapter_uri(object));
    CU_ASSERT(!strcmp(zone_input_adapter_uri(object), "input_adapter_uri 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_output_adapter_type(object));
    CU_ASSERT(!strcmp(zone_output_adapter_type(object), "output_adapter_type 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_output_adapter_uri(object));
    CU_ASSERT(!strcmp(zone_output_adapter_uri(object), "output_adapter_uri 1"));
    CU_ASSERT(zone_next_ksk_roll(object) == 1);
    CU_ASSERT(zone_next_zsk_roll(object) == 1);
    CU_ASSERT(zone_next_csk_roll(object) == 1);
    db_value_reset(&policy_id);
}

static void test_zone_read_by_name(void) {
    CU_ASSERT_FATAL(!zone_get_by_name(object, "name 1"));
}

static void test_zone_verify_name(void) {
    int ret;
    db_value_t policy_id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&policy_id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&policy_id, 1));
    }
    CU_ASSERT(!db_value_cmp(zone_policy_id(object), &policy_id, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_name(object));
    CU_ASSERT(!strcmp(zone_name(object), "name 1"));
    CU_ASSERT(zone_signconf_needs_writing(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_signconf_path(object));
    CU_ASSERT(!strcmp(zone_signconf_path(object), "signconf_path 1"));
    CU_ASSERT(zone_next_change(object) == 1);
    CU_ASSERT(zone_ttl_end_ds(object) == 1);
    CU_ASSERT(zone_ttl_end_dk(object) == 1);
    CU_ASSERT(zone_ttl_end_rs(object) == 1);
    CU_ASSERT(zone_roll_ksk_now(object) == 1);
    CU_ASSERT(zone_roll_zsk_now(object) == 1);
    CU_ASSERT(zone_roll_csk_now(object) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_input_adapter_type(object));
    CU_ASSERT(!strcmp(zone_input_adapter_type(object), "input_adapter_type 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_input_adapter_uri(object));
    CU_ASSERT(!strcmp(zone_input_adapter_uri(object), "input_adapter_uri 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_output_adapter_type(object));
    CU_ASSERT(!strcmp(zone_output_adapter_type(object), "output_adapter_type 1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_output_adapter_uri(object));
    CU_ASSERT(!strcmp(zone_output_adapter_uri(object), "output_adapter_uri 1"));
    CU_ASSERT(zone_next_ksk_roll(object) == 1);
    CU_ASSERT(zone_next_zsk_roll(object) == 1);
    CU_ASSERT(zone_next_csk_roll(object) == 1);
    db_value_reset(&policy_id);
}

static void test_zone_change(void) {
    db_value_t policy_id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&policy_id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&policy_id, 1));
    }
    CU_ASSERT(!zone_set_policy_id(object, &policy_id));
    CU_ASSERT(!zone_set_name(object, "name 2"));
    CU_ASSERT(!zone_set_signconf_needs_writing(object, 2));
    CU_ASSERT(!zone_set_signconf_path(object, "signconf_path 2"));
    CU_ASSERT(!zone_set_next_change(object, 2));
    CU_ASSERT(!zone_set_ttl_end_ds(object, 2));
    CU_ASSERT(!zone_set_ttl_end_dk(object, 2));
    CU_ASSERT(!zone_set_ttl_end_rs(object, 2));
    CU_ASSERT(!zone_set_roll_ksk_now(object, 2));
    CU_ASSERT(!zone_set_roll_zsk_now(object, 2));
    CU_ASSERT(!zone_set_roll_csk_now(object, 2));
    CU_ASSERT(!zone_set_input_adapter_type(object, "input_adapter_type 2"));
    CU_ASSERT(!zone_set_input_adapter_uri(object, "input_adapter_uri 2"));
    CU_ASSERT(!zone_set_output_adapter_type(object, "output_adapter_type 2"));
    CU_ASSERT(!zone_set_output_adapter_uri(object, "output_adapter_uri 2"));
    CU_ASSERT(!zone_set_next_ksk_roll(object, 2));
    CU_ASSERT(!zone_set_next_zsk_roll(object, 2));
    CU_ASSERT(!zone_set_next_csk_roll(object, 2));
    db_value_reset(&policy_id);
}

static void test_zone_update(void) {
    CU_ASSERT_FATAL(!zone_update(object));
}

static void test_zone_read2(void) {
    CU_ASSERT_FATAL(!zone_get_by_id(object, &id));
}

static void test_zone_verify2(void) {
    int ret;
    db_value_t policy_id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&policy_id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&policy_id, 1));
    }
    CU_ASSERT(!db_value_cmp(zone_policy_id(object), &policy_id, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_name(object));
    CU_ASSERT(!strcmp(zone_name(object), "name 2"));
    CU_ASSERT(zone_signconf_needs_writing(object) == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_signconf_path(object));
    CU_ASSERT(!strcmp(zone_signconf_path(object), "signconf_path 2"));
    CU_ASSERT(zone_next_change(object) == 2);
    CU_ASSERT(zone_ttl_end_ds(object) == 2);
    CU_ASSERT(zone_ttl_end_dk(object) == 2);
    CU_ASSERT(zone_ttl_end_rs(object) == 2);
    CU_ASSERT(zone_roll_ksk_now(object) == 2);
    CU_ASSERT(zone_roll_zsk_now(object) == 2);
    CU_ASSERT(zone_roll_csk_now(object) == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_input_adapter_type(object));
    CU_ASSERT(!strcmp(zone_input_adapter_type(object), "input_adapter_type 2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_input_adapter_uri(object));
    CU_ASSERT(!strcmp(zone_input_adapter_uri(object), "input_adapter_uri 2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_output_adapter_type(object));
    CU_ASSERT(!strcmp(zone_output_adapter_type(object), "output_adapter_type 2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_output_adapter_uri(object));
    CU_ASSERT(!strcmp(zone_output_adapter_uri(object), "output_adapter_uri 2"));
    CU_ASSERT(zone_next_ksk_roll(object) == 2);
    CU_ASSERT(zone_next_zsk_roll(object) == 2);
    CU_ASSERT(zone_next_csk_roll(object) == 2);
    db_value_reset(&policy_id);
}

static void test_zone_read_by_name2(void) {
    CU_ASSERT_FATAL(!zone_get_by_name(object, "name 2"));
}

static void test_zone_verify_name2(void) {
    int ret;
    db_value_t policy_id = DB_VALUE_EMPTY;
    if (db_sqlite) {
        CU_ASSERT(!db_value_from_int32(&policy_id, 1));
    }
    if (db_mysql) {
        CU_ASSERT(!db_value_from_uint64(&policy_id, 1));
    }
    CU_ASSERT(!db_value_cmp(zone_policy_id(object), &policy_id, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_name(object));
    CU_ASSERT(!strcmp(zone_name(object), "name 2"));
    CU_ASSERT(zone_signconf_needs_writing(object) == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_signconf_path(object));
    CU_ASSERT(!strcmp(zone_signconf_path(object), "signconf_path 2"));
    CU_ASSERT(zone_next_change(object) == 2);
    CU_ASSERT(zone_ttl_end_ds(object) == 2);
    CU_ASSERT(zone_ttl_end_dk(object) == 2);
    CU_ASSERT(zone_ttl_end_rs(object) == 2);
    CU_ASSERT(zone_roll_ksk_now(object) == 2);
    CU_ASSERT(zone_roll_zsk_now(object) == 2);
    CU_ASSERT(zone_roll_csk_now(object) == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_input_adapter_type(object));
    CU_ASSERT(!strcmp(zone_input_adapter_type(object), "input_adapter_type 2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_input_adapter_uri(object));
    CU_ASSERT(!strcmp(zone_input_adapter_uri(object), "input_adapter_uri 2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_output_adapter_type(object));
    CU_ASSERT(!strcmp(zone_output_adapter_type(object), "output_adapter_type 2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(zone_output_adapter_uri(object));
    CU_ASSERT(!strcmp(zone_output_adapter_uri(object), "output_adapter_uri 2"));
    CU_ASSERT(zone_next_ksk_roll(object) == 2);
    CU_ASSERT(zone_next_zsk_roll(object) == 2);
    CU_ASSERT(zone_next_csk_roll(object) == 2);
    db_value_reset(&policy_id);
}

static void test_zone_delete(void) {
    CU_ASSERT_FATAL(!zone_delete(object));
}

static void test_zone_list2(void) {
    CU_ASSERT_FATAL(!zone_list_get(object_list));
    CU_ASSERT_PTR_NULL(zone_list_next(object_list));
}

static void test_zone_end(void) {
    if (object) {
        zone_free(object);
        CU_PASS("zone_free");
    }
    if (object_list) {
        zone_list_free(object_list);
        CU_PASS("zone_list_free");
    }
}

static int test_zone_add_tests(CU_pSuite pSuite) {
    if (!CU_add_test(pSuite, "new object", test_zone_new)
        || !CU_add_test(pSuite, "set fields", test_zone_set)
        || !CU_add_test(pSuite, "get fields", test_zone_get)
        || !CU_add_test(pSuite, "create object", test_zone_create)
        || !CU_add_test(pSuite, "object clauses", test_zone_clauses)
        || !CU_add_test(pSuite, "object count", test_zone_count)
        || !CU_add_test(pSuite, "list objects", test_zone_list)
        || !CU_add_test(pSuite, "list objects (store)", test_zone_list_store)
        || !CU_add_test(pSuite, "list objects (associated)", test_zone_list_associated)
        || !CU_add_test(pSuite, "read object by id", test_zone_read)
        || !CU_add_test(pSuite, "verify fields", test_zone_verify)
        || !CU_add_test(pSuite, "read object by name", test_zone_read_by_name)
        || !CU_add_test(pSuite, "verify fields (name)", test_zone_verify_name)
        || !CU_add_test(pSuite, "change object", test_zone_change)
        || !CU_add_test(pSuite, "update object", test_zone_update)
        || !CU_add_test(pSuite, "reread object by id", test_zone_read2)
        || !CU_add_test(pSuite, "verify fields after update", test_zone_verify2)
        || !CU_add_test(pSuite, "reread object by name", test_zone_read_by_name2)
        || !CU_add_test(pSuite, "verify fields after update (name)", test_zone_verify_name2)
        || !CU_add_test(pSuite, "delete object", test_zone_delete)
        || !CU_add_test(pSuite, "list objects to verify delete", test_zone_list2)
        || !CU_add_test(pSuite, "end test", test_zone_end))
    {
        return CU_get_error();
    }
    return 0;
}

int test_zone_add_suite(void) {
    CU_pSuite pSuite = NULL;
    int ret;

#if defined(ENFORCER_DATABASE_SQLITE3)
    pSuite = CU_add_suite("Test of zone (SQLite)", test_zone_init_suite_sqlite, test_zone_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_zone_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
#if defined(ENFORCER_DATABASE_MYSQL)
    pSuite = CU_add_suite("Test of zone (MySQL)", test_zone_init_suite_mysql, test_zone_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_zone_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
    return 0;
}
