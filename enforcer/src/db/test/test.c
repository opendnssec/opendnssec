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

#include "test.h"

#include "test_hsm_key.h"
#include "test_key_data.h"
#include "test_key_state.h"
#include "test_key_dependency.h"
#include "test_policy.h"
#include "test_policy_key.h"
#include "test_database_version.h"
#include "test_zone.h"

#include "CUnit/Basic.h"

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
        || !CU_add_test(pSuite, "test of db_backend", test_class_db_backend)
        || !CU_add_test(pSuite, "test of db_clause", test_class_db_clause)
        || !CU_add_test(pSuite, "test of db_clause_list", test_class_db_clause_list)
        || !CU_add_test(pSuite, "test of db_configuration", test_class_db_configuration)
        || !CU_add_test(pSuite, "test of db_configuration_list", test_class_db_configuration_list)
        || !CU_add_test(pSuite, "test of db_connection", test_class_db_connection)
        || !CU_add_test(pSuite, "test of db_object_field", test_class_db_object_field)
        || !CU_add_test(pSuite, "test of db_object_field_list", test_class_db_object_field_list)
        || !CU_add_test(pSuite, "test of db_object", test_class_db_object)
        || !CU_add_test(pSuite, "test of db_value_set", test_class_db_value_set)
        || !CU_add_test(pSuite, "test of db_result", test_class_db_result)
        || !CU_add_test(pSuite, "test of db_result_list", test_class_db_result_list)
        || !CU_add_test(pSuite, "test of db_value", test_class_db_value)
        || !CU_add_test(pSuite, "test of db_*_free", test_class_end))
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

#if defined(ENFORCER_DATABASE_SQLITE3)
    pSuite = CU_add_suite("SQLite database operations", init_suite_database_operations_sqlite, clean_suite_database_operations);
    if (!pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (!CU_add_test(pSuite, "test of read object 1", test_database_operations_read_object1)
        || !CU_add_test(pSuite, "test of create object 2", test_database_operations_create_object2)
        || !CU_add_test(pSuite, "test of read object 2", test_database_operations_read_object2)
        || !CU_add_test(pSuite, "test of read object 1 (#2)", test_database_operations_read_object1)
        || !CU_add_test(pSuite, "test of create object 3", test_database_operations_create_object3)
        || !CU_add_test(pSuite, "test of update object 2", test_database_operations_update_object2)
        || !CU_add_test(pSuite, "test of read all", test_database_operations_read_all)
        || !CU_add_test(pSuite, "test of count", test_database_operations_count)
        || !CU_add_test(pSuite, "test of delete object 3", test_database_operations_delete_object3)
        || !CU_add_test(pSuite, "test of read object 1 (#3)", test_database_operations_read_object1)
        || !CU_add_test(pSuite, "test of delete object 2", test_database_operations_delete_object2)
        || !CU_add_test(pSuite, "test of read object 1 (#4)", test_database_operations_read_object1)

        || !CU_add_test(pSuite, "test of read object 1 (REV)", test_database_operations_read_object1_2)
        || !CU_add_test(pSuite, "test of create object 2 (REV)", test_database_operations_create_object2_2)
        || !CU_add_test(pSuite, "test of read object 2 (REV)", test_database_operations_read_object2_2)
        || !CU_add_test(pSuite, "test of read object 1 (#2) (REV)", test_database_operations_read_object1_2)
        || !CU_add_test(pSuite, "test of create object 3 (REV)", test_database_operations_create_object3_2)
        || !CU_add_test(pSuite, "test of update object 2 (REV)", test_database_operations_update_object2_2)
        || !CU_add_test(pSuite, "test of updates revisions (REV)", test_database_operations_update_objects_revisions)
        || !CU_add_test(pSuite, "test of delete object 3 (REV)", test_database_operations_delete_object3_2)
        || !CU_add_test(pSuite, "test of read object 1 (#3) (REV)", test_database_operations_read_object1_2)
        || !CU_add_test(pSuite, "test of delete object 2 (REV)", test_database_operations_delete_object2_2)
        || !CU_add_test(pSuite, "test of read object 1 (#4) (REV)", test_database_operations_read_object1_2))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }
#endif

#if defined(ENFORCER_DATABASE_MYSQL)
    pSuite = CU_add_suite("MySQL database operations", init_suite_database_operations_mysql, clean_suite_database_operations);
    if (!pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (!CU_add_test(pSuite, "test of read object 1", test_database_operations_read_object1)
        || !CU_add_test(pSuite, "test of create object 2", test_database_operations_create_object2)
        || !CU_add_test(pSuite, "test of read object 2", test_database_operations_read_object2)
        || !CU_add_test(pSuite, "test of read object 1 (#2)", test_database_operations_read_object1)
        || !CU_add_test(pSuite, "test of create object 3", test_database_operations_create_object3)
        || !CU_add_test(pSuite, "test of update object 2", test_database_operations_update_object2)
        || !CU_add_test(pSuite, "test of read all", test_database_operations_read_all)
        || !CU_add_test(pSuite, "test of delete object 3", test_database_operations_delete_object3)
        || !CU_add_test(pSuite, "test of read object 1 (#3)", test_database_operations_read_object1)
        || !CU_add_test(pSuite, "test of delete object 2", test_database_operations_delete_object2)
        || !CU_add_test(pSuite, "test of read object 1 (#4)", test_database_operations_read_object1)

        || !CU_add_test(pSuite, "test of read object 1 (REV)", test_database_operations_read_object1_2)
        || !CU_add_test(pSuite, "test of create object 2 (REV)", test_database_operations_create_object2_2)
        || !CU_add_test(pSuite, "test of read object 2 (REV)", test_database_operations_read_object2_2)
        || !CU_add_test(pSuite, "test of read object 1 (#2) (REV)", test_database_operations_read_object1_2)
        || !CU_add_test(pSuite, "test of create object 3 (REV)", test_database_operations_create_object3_2)
        || !CU_add_test(pSuite, "test of update object 2 (REV)", test_database_operations_update_object2_2)
        || !CU_add_test(pSuite, "test of updates revisions (REV)", test_database_operations_update_objects_revisions)
        || !CU_add_test(pSuite, "test of delete object 3 (REV)", test_database_operations_delete_object3_2)
        || !CU_add_test(pSuite, "test of read object 1 (#3) (REV)", test_database_operations_read_object1_2)
        || !CU_add_test(pSuite, "test of delete object 2 (REV)", test_database_operations_delete_object2_2)
        || !CU_add_test(pSuite, "test of read object 1 (#4) (REV)", test_database_operations_read_object1_2))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }
#endif

    test_hsm_key_add_suite();
    test_key_data_add_suite();
    test_key_state_add_suite();
    test_key_dependency_add_suite();
    test_policy_add_suite();
    test_policy_key_add_suite();
    test_database_version_add_suite();
    test_zone_add_suite();

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}
