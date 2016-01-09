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

#include "config.h"

#ifndef __test_test_h
#define __test_test_h

int init_suite_classes(void);
int clean_suite_classes(void);
void test_class_db_backend_handle(void);
void test_class_db_backend(void);
void test_class_db_clause(void);
void test_class_db_clause_list(void);
void test_class_db_configuration(void);
void test_class_db_configuration_list(void);
void test_class_db_connection(void);
void test_class_db_join(void);
void test_class_db_join_list(void);
void test_class_db_object_field(void);
void test_class_db_object_field_list(void);
void test_class_db_object(void);
void test_class_db_value_set(void);
void test_class_db_result(void);
void test_class_db_result_list(void);
void test_class_db_value(void);
void test_class_end(void);

int init_suite_initialization(void);
int clean_suite_initialization(void);
void test_initialization_configuration(void);
void test_initialization_connection(void);

#if defined(ENFORCER_DATABASE_SQLITE3)
int init_suite_database_operations_sqlite(void);
#endif
int init_suite_database_operations_mysql(void);
int clean_suite_database_operations(void);
void test_database_operations_read_object1(void);
void test_database_operations_create_object2(void);
void test_database_operations_read_object2(void);
void test_database_operations_update_object2(void);
void test_database_operations_delete_object2(void);
void test_database_operations_create_object3(void);
void test_database_operations_delete_object3(void);
void test_database_operations_read_all(void);
void test_database_operations_count(void);

void test_database_operations_read_object1_2(void);
void test_database_operations_create_object2_2(void);
void test_database_operations_read_object2_2(void);
void test_database_operations_update_object2_2(void);
void test_database_operations_delete_object2_2(void);
void test_database_operations_create_object3_2(void);
void test_database_operations_delete_object3_2(void);
void test_database_operations_update_objects_revisions(void);

#endif
