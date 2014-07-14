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

#include "../db_backend.h"
#include "../db_clause.h"
#include "../db_configuration.h"
#include "../db_connection.h"
#include "../db_join.h"
#include "../db_object.h"
#include "../db_result.h"
#include "../db_value.h"

#include "CUnit/Basic.h"

static int fake_pointer = 0;
static db_backend_handle_t* backend_handle = NULL;
static db_backend_t* backend = NULL;
static db_backend_meta_data_t* backend_meta_data = NULL;
static db_backend_meta_data_t* backend_meta_data2 = NULL;
static db_backend_meta_data_t* backend_meta_data3 = NULL;
static db_backend_meta_data_t* backend_meta_data4 = NULL;
static db_backend_meta_data_list_t* backend_meta_data_list = NULL;
static db_backend_meta_data_list_t* backend_meta_data_list2 = NULL;
static db_clause_t* clause = NULL;
static db_clause_t* clause2 = NULL;
static db_clause_list_t* clause_list = NULL;
static db_configuration_t* configuration = NULL;
static db_configuration_t* configuration2 = NULL;
static db_configuration_list_t* configuration_list = NULL;
static db_connection_t* connection = NULL;
static db_join_t* join = NULL;
static db_join_t* join2 = NULL;
static db_join_list_t* join_list = NULL;
static db_object_field_t* object_field = NULL;
static db_object_field_t* object_field2 = NULL;
static db_object_field_list_t* object_field_list = NULL;
static db_object_t* object = NULL;
static db_value_set_t* value_set = NULL;
static db_value_set_t* value_set2 = NULL;
static db_result_t* result = NULL;
static db_result_t* result2 = NULL;
static db_result_list_t* result_list = NULL;
static db_value_t* value = NULL;
static db_value_t* value2 = NULL;
static const db_enum_t enum_set[] = {
    { "enum1", 1 },
    { "enum2", 2 },
    { "enum3", 3 },
    { NULL, 0 }
};

int init_suite_classes(void) {
    if (backend_handle) {
        return 1;
    }
    if (backend) {
        return 1;
    }
    if (backend_meta_data) {
        return 1;
    }
    if (backend_meta_data2) {
        return 1;
    }
    if (backend_meta_data3) {
        return 1;
    }
    if (backend_meta_data4) {
        return 1;
    }
    if (backend_meta_data_list) {
        return 1;
    }
    if (backend_meta_data_list2) {
        return 1;
    }
    if (clause) {
        return 1;
    }
    if (clause2) {
        return 1;
    }
    if (clause_list) {
        return 1;
    }
    if (configuration) {
        return 1;
    }
    if (configuration2) {
        return 1;
    }
    if (configuration_list) {
        return 1;
    }
    if (connection) {
        return 1;
    }
    if (join) {
        return 1;
    }
    if (join2) {
        return 1;
    }
    if (join_list) {
        return 1;
    }
    if (object_field) {
        return 1;
    }
    if (object_field2) {
        return 1;
    }
    if (object_field_list) {
        return 1;
    }
    if (object) {
        return 1;
    }
    if (value_set) {
        return 1;
    }
    if (value_set2) {
        return 1;
    }
    if (result) {
        return 1;
    }
    if (result2) {
        return 1;
    }
    if (result_list) {
        return 1;
    }
    if (value) {
        return 1;
    }
    if (value2) {
        return 1;
    }
    return 0;
}

int clean_suite_classes(void) {
    db_backend_handle_free(backend_handle);
    backend_handle = NULL;
    db_backend_free(backend);
    backend = NULL;
    db_backend_meta_data_free(backend_meta_data);
    backend_meta_data = NULL;
    db_backend_meta_data_free(backend_meta_data2);
    backend_meta_data2 = NULL;
    db_backend_meta_data_free(backend_meta_data3);
    backend_meta_data3 = NULL;
    db_backend_meta_data_free(backend_meta_data4);
    backend_meta_data4 = NULL;
    db_backend_meta_data_list_free(backend_meta_data_list);
    backend_meta_data_list = NULL;
    db_backend_meta_data_list_free(backend_meta_data_list2);
    backend_meta_data_list2 = NULL;
    db_clause_free(clause);
    clause = NULL;
    db_clause_free(clause2);
    clause2 = NULL;
    db_clause_list_free(clause_list);
    clause_list = NULL;
    db_configuration_free(configuration);
    configuration = NULL;
    db_configuration_free(configuration2);
    configuration2 = NULL;
    db_configuration_list_free(configuration_list);
    configuration_list = NULL;
    db_connection_free(connection);
    connection = NULL;
    db_join_free(join);
    join = NULL;
    db_join_free(join2);
    join2 = NULL;
    db_join_list_free(join_list);
    join_list = NULL;
    db_object_field_free(object_field);
    object_field = NULL;
    db_object_field_free(object_field2);
    object_field2 = NULL;
    db_object_field_list_free(object_field_list);
    object_field_list = NULL;
    db_object_free(object);
    object = NULL;
    db_value_set_free(value_set);
    value_set = NULL;
    db_value_set_free(value_set2);
    value_set2 = NULL;
    db_result_free(result);
    result = NULL;
    db_result_free(result2);
    result2 = NULL;
    db_result_list_free(result_list);
    result_list = NULL;
    db_value_free(value);
    value = NULL;
    db_value_free(value2);
    value2 = NULL;
    return 0;
}

int __db_backend_handle_initialize(void* data) {
    CU_ASSERT(data == &fake_pointer);
    return 0;
}

int __db_backend_handle_shutdown(void* data) {
    CU_ASSERT(data == &fake_pointer);
    return 0;
}

int __db_backend_handle_connect(void* data, const db_configuration_list_t* configuration_list) {
    CU_ASSERT(data == &fake_pointer);
    CU_ASSERT((void*)configuration_list == &fake_pointer);
    return 0;
}

int __db_backend_handle_disconnect(void* data) {
    CU_ASSERT(data == &fake_pointer);
    return 0;
}

int __db_backend_handle_create(void* data, const db_object_t* _object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set) {
    CU_ASSERT(data == &fake_pointer);
    CU_ASSERT((void*)_object == &fake_pointer || (object != NULL && _object == object));
    CU_ASSERT((void*)object_field_list == &fake_pointer);
    CU_ASSERT((void*)value_set == &fake_pointer);
    return 0;
}

db_result_list_t* __db_backend_handle_read(void* data, const db_object_t* _object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
    CU_ASSERT(data == &fake_pointer);
    CU_ASSERT((void*)_object == &fake_pointer || (object != NULL && _object == object));
    CU_ASSERT((void*)join_list == &fake_pointer);
    CU_ASSERT((void*)clause_list == &fake_pointer);
    return (db_result_list_t*)&fake_pointer;
}

int __db_backend_handle_update(void* data, const db_object_t* _object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list) {
    CU_ASSERT(data == &fake_pointer);
    CU_ASSERT((void*)_object == &fake_pointer || (object != NULL && _object == object));
    CU_ASSERT((void*)object_field_list == &fake_pointer);
    CU_ASSERT((void*)value_set == &fake_pointer);
    CU_ASSERT((void*)clause_list == &fake_pointer);
    return 0;
}

int __db_backend_handle_delete(void* data, const db_object_t* _object, const db_clause_list_t* clause_list) {
    CU_ASSERT(data == &fake_pointer);
    CU_ASSERT((void*)_object == &fake_pointer || (object != NULL && _object == object));
    CU_ASSERT((void*)clause_list == &fake_pointer);
    return 0;
}

int __db_backend_handle_count(void* data, const db_object_t* _object, const db_join_list_t* join_list, const db_clause_list_t* clause_list, size_t* count) {
    CU_ASSERT(data == &fake_pointer);
    CU_ASSERT((void*)_object == &fake_pointer || (object != NULL && _object == object));
    CU_ASSERT((void*)join_list == &fake_pointer);
    CU_ASSERT((void*)clause_list == &fake_pointer);
    CU_ASSERT((void*)count == &fake_pointer);
    return 0;
}

void __db_backend_handle_free(void* data) {
    CU_ASSERT(data == &fake_pointer);
}

int __db_backend_handle_transaction_begin(void* data) {
    CU_ASSERT(data == &fake_pointer);
    return 0;
}

int __db_backend_handle_transaction_commit(void* data) {
    CU_ASSERT(data == &fake_pointer);
    return 0;
}

int __db_backend_handle_transaction_rollback(void* data) {
    CU_ASSERT(data == &fake_pointer);
    return 0;
}

void test_class_db_backend_handle(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((backend_handle = db_backend_handle_new()));

    CU_ASSERT(!db_backend_handle_set_initialize(backend_handle, __db_backend_handle_initialize));
    CU_ASSERT(!db_backend_handle_set_shutdown(backend_handle, __db_backend_handle_shutdown));
    CU_ASSERT(!db_backend_handle_set_connect(backend_handle, __db_backend_handle_connect));
    CU_ASSERT(!db_backend_handle_set_disconnect(backend_handle, __db_backend_handle_disconnect));
    CU_ASSERT(!db_backend_handle_set_create(backend_handle, __db_backend_handle_create));
    CU_ASSERT(!db_backend_handle_set_read(backend_handle, __db_backend_handle_read));
    CU_ASSERT(!db_backend_handle_set_update(backend_handle, __db_backend_handle_update));
    CU_ASSERT(!db_backend_handle_set_delete(backend_handle, __db_backend_handle_delete));
    CU_ASSERT(!db_backend_handle_set_count(backend_handle, __db_backend_handle_count));
    CU_ASSERT(!db_backend_handle_set_free(backend_handle, __db_backend_handle_free));
    CU_ASSERT(!db_backend_handle_set_transaction_begin(backend_handle, __db_backend_handle_transaction_begin));
    CU_ASSERT(!db_backend_handle_set_transaction_commit(backend_handle, __db_backend_handle_transaction_commit));
    CU_ASSERT(!db_backend_handle_set_transaction_rollback(backend_handle, __db_backend_handle_transaction_rollback));
    CU_ASSERT(!db_backend_handle_set_data(backend_handle, &fake_pointer));

    CU_ASSERT(!db_backend_handle_not_empty(backend_handle));
    CU_ASSERT(db_backend_handle_data(backend_handle) == &fake_pointer);

    CU_ASSERT(!db_backend_handle_initialize(backend_handle));
    CU_ASSERT(!db_backend_handle_shutdown(backend_handle));
    CU_ASSERT(!db_backend_handle_connect(backend_handle, (db_configuration_list_t*)&fake_pointer));
    CU_ASSERT(!db_backend_handle_disconnect(backend_handle));
    CU_ASSERT(!db_backend_handle_create(backend_handle, (db_object_t*)&fake_pointer, (db_object_field_list_t*)&fake_pointer, (db_value_set_t*)&fake_pointer));
    CU_ASSERT(db_backend_handle_read(backend_handle, (db_object_t*)&fake_pointer, (db_join_list_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer) == (db_result_list_t*)&fake_pointer);
    CU_ASSERT(!db_backend_handle_update(backend_handle, (db_object_t*)&fake_pointer, (db_object_field_list_t*)&fake_pointer, (db_value_set_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer));
    CU_ASSERT(!db_backend_handle_delete(backend_handle, (db_object_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer));
    CU_ASSERT(!db_backend_handle_count(backend_handle, (db_object_t*)&fake_pointer, (db_join_list_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer, (size_t*)&fake_pointer));
    CU_ASSERT(!db_backend_handle_transaction_begin(backend_handle));
    CU_ASSERT(!db_backend_handle_transaction_commit(backend_handle));
    CU_ASSERT(!db_backend_handle_transaction_rollback(backend_handle));
}

void test_class_db_backend(void) {
    db_backend_handle_t* local_backend_handle = backend_handle;

    CU_ASSERT_PTR_NOT_NULL_FATAL((backend = db_backend_new()));
    CU_ASSERT(!db_backend_set_name(backend, "test"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_backend_name(backend));
    CU_ASSERT(!strcmp(db_backend_name(backend), "test"));
    CU_ASSERT_FATAL(!db_backend_set_handle(backend, backend_handle));
    backend_handle = NULL;
    CU_ASSERT(db_backend_handle(backend) == local_backend_handle);
    CU_ASSERT(!db_backend_not_empty(backend));

    CU_ASSERT(!db_backend_initialize(backend));
    CU_ASSERT(!db_backend_shutdown(backend));
    CU_ASSERT(!db_backend_connect(backend, (db_configuration_list_t*)&fake_pointer));
    CU_ASSERT(!db_backend_disconnect(backend));
    CU_ASSERT(!db_backend_create(backend, (db_object_t*)&fake_pointer, (db_object_field_list_t*)&fake_pointer, (db_value_set_t*)&fake_pointer));
    CU_ASSERT(db_backend_read(backend, (db_object_t*)&fake_pointer, (db_join_list_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer) == (db_result_list_t*)&fake_pointer);
    CU_ASSERT(!db_backend_update(backend, (db_object_t*)&fake_pointer, (db_object_field_list_t*)&fake_pointer, (db_value_set_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer));
    CU_ASSERT(!db_backend_delete(backend, (db_object_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer));
    CU_ASSERT(!db_backend_count(backend, (db_object_t*)&fake_pointer, (db_join_list_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer, (size_t*)&fake_pointer));
    CU_ASSERT(!db_backend_transaction_begin(backend));
    CU_ASSERT(!db_backend_transaction_commit(backend));
    CU_ASSERT(!db_backend_transaction_rollback(backend));
}

void test_class_db_backend_meta_data(void) {
    db_value_t* local_value;

    CU_ASSERT_PTR_NOT_NULL_FATAL((backend_meta_data = db_backend_meta_data_new()));
    CU_ASSERT(!db_backend_meta_data_set_name(backend_meta_data, "name1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL((local_value = db_value_new()));
    CU_ASSERT(!db_value_from_text(local_value, "value1"));
    CU_ASSERT(!db_backend_meta_data_set_value(backend_meta_data, local_value));
    CU_ASSERT(!db_backend_meta_data_not_empty(backend_meta_data));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_backend_meta_data_name(backend_meta_data));
    CU_ASSERT(!strcmp(db_backend_meta_data_name(backend_meta_data), "name1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_backend_meta_data_value(backend_meta_data));
    CU_ASSERT(!strcmp(db_value_text(db_backend_meta_data_value(backend_meta_data)), "value1"));

    CU_ASSERT_PTR_NOT_NULL_FATAL((backend_meta_data2 = db_backend_meta_data_new()));
    CU_ASSERT_FATAL(!db_backend_meta_data_copy(backend_meta_data2, backend_meta_data));
    CU_ASSERT(!db_backend_meta_data_not_empty(backend_meta_data2));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_backend_meta_data_name(backend_meta_data2));
    CU_ASSERT(!strcmp(db_backend_meta_data_name(backend_meta_data2), "name1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_backend_meta_data_value(backend_meta_data2));
    CU_ASSERT(!strcmp(db_value_text(db_backend_meta_data_value(backend_meta_data2)), "value1"));
    db_backend_meta_data_free(backend_meta_data2);
    backend_meta_data2 = NULL;
    CU_PASS("db_backend_meta_data_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((backend_meta_data2 = db_backend_meta_data_new()));
    CU_ASSERT(!db_backend_meta_data_set_name(backend_meta_data2, "name2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL((local_value = db_value_new()));
    CU_ASSERT(!db_value_from_text(local_value, "value2"));
    CU_ASSERT(!db_backend_meta_data_set_value(backend_meta_data2, local_value));
    CU_ASSERT(!db_backend_meta_data_not_empty(backend_meta_data2));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_backend_meta_data_name(backend_meta_data2));
    CU_ASSERT(!strcmp(db_backend_meta_data_name(backend_meta_data2), "name2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_backend_meta_data_value(backend_meta_data2));
    CU_ASSERT(!strcmp(db_value_text(db_backend_meta_data_value(backend_meta_data2)), "value2"));

    CU_ASSERT_PTR_NOT_NULL_FATAL((backend_meta_data3 = db_backend_meta_data_new()));
    CU_ASSERT(!db_backend_meta_data_set_name(backend_meta_data3, "name3"));
    CU_ASSERT_PTR_NOT_NULL_FATAL((local_value = db_value_new()));
    CU_ASSERT(!db_value_from_text(local_value, "value3"));
    CU_ASSERT(!db_backend_meta_data_set_value(backend_meta_data3, local_value));
    CU_ASSERT(!db_backend_meta_data_not_empty(backend_meta_data3));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_backend_meta_data_name(backend_meta_data3));
    CU_ASSERT(!strcmp(db_backend_meta_data_name(backend_meta_data3), "name3"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_backend_meta_data_value(backend_meta_data3));
    CU_ASSERT(!strcmp(db_value_text(db_backend_meta_data_value(backend_meta_data3)), "value3"));

    CU_ASSERT_PTR_NOT_NULL_FATAL((backend_meta_data4 = db_backend_meta_data_new()));
    CU_ASSERT(!db_backend_meta_data_set_name(backend_meta_data4, "name4"));
    CU_ASSERT_PTR_NOT_NULL_FATAL((local_value = db_value_new()));
    CU_ASSERT(!db_value_from_text(local_value, "value4"));
    CU_ASSERT(!db_backend_meta_data_set_value(backend_meta_data4, local_value));
    CU_ASSERT(!db_backend_meta_data_not_empty(backend_meta_data4));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_backend_meta_data_name(backend_meta_data4));
    CU_ASSERT(!strcmp(db_backend_meta_data_name(backend_meta_data4), "name4"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_backend_meta_data_value(backend_meta_data4));
    CU_ASSERT(!strcmp(db_value_text(db_backend_meta_data_value(backend_meta_data4)), "value4"));
}

void test_class_db_backend_meta_data_list(void) {
    db_backend_meta_data_t* local_backend_meta_data = backend_meta_data;
    db_backend_meta_data_t* local_backend_meta_data2 = backend_meta_data2;
    db_backend_meta_data_t* local_backend_meta_data3 = backend_meta_data3;
    db_backend_meta_data_t* local_backend_meta_data4 = backend_meta_data4;

    CU_ASSERT_PTR_NOT_NULL_FATAL((backend_meta_data_list = db_backend_meta_data_list_new()));
    CU_ASSERT_FATAL(!db_backend_meta_data_list_add(backend_meta_data_list, backend_meta_data));
    backend_meta_data = NULL;
    CU_ASSERT_FATAL(!db_backend_meta_data_list_add(backend_meta_data_list, backend_meta_data2));
    backend_meta_data2 = NULL;
    CU_ASSERT(db_backend_meta_data_list_find(backend_meta_data_list, "name1") == local_backend_meta_data);
    CU_ASSERT(db_backend_meta_data_list_find(backend_meta_data_list, "name2") == local_backend_meta_data2);

    CU_ASSERT_PTR_NOT_NULL_FATAL((backend_meta_data_list2 = db_backend_meta_data_list_new()));
    CU_ASSERT_FATAL(!db_backend_meta_data_list_copy(backend_meta_data_list2, backend_meta_data_list));
    CU_ASSERT_PTR_NOT_NULL(db_backend_meta_data_list_find(backend_meta_data_list2, "name1"));
    CU_ASSERT_PTR_NOT_NULL(db_backend_meta_data_list_find(backend_meta_data_list2, "name2"));
    db_backend_meta_data_list_free(backend_meta_data_list2);
    backend_meta_data_list2 = NULL;
    CU_PASS("db_backend_meta_data_list_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((backend_meta_data_list2 = db_backend_meta_data_list_new()));
    CU_ASSERT_FATAL(!db_backend_meta_data_list_add(backend_meta_data_list2, backend_meta_data3));
    backend_meta_data3 = NULL;
    CU_ASSERT_FATAL(!db_backend_meta_data_list_add(backend_meta_data_list2, backend_meta_data4));
    backend_meta_data4 = NULL;
    CU_ASSERT(db_backend_meta_data_list_find(backend_meta_data_list2, "name3") == local_backend_meta_data3);
    CU_ASSERT(db_backend_meta_data_list_find(backend_meta_data_list2, "name4") == local_backend_meta_data4);
}

void test_class_db_clause(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));

    CU_ASSERT(!db_clause_set_table(clause, "table"));
    CU_ASSERT(!db_clause_set_field(clause, "field"));
    CU_ASSERT(!db_clause_set_type(clause, DB_CLAUSE_NOT_EQUAL));
    CU_ASSERT(!db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_OR));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_clause_get_value(clause));
    CU_ASSERT(!db_value_from_int32(db_clause_get_value(clause), 1));
    CU_ASSERT(!db_clause_not_empty(clause));

    CU_ASSERT_PTR_NOT_NULL_FATAL(db_clause_table(clause));
    CU_ASSERT(!strcmp(db_clause_table(clause), "table"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_clause_field(clause));
    CU_ASSERT(!strcmp(db_clause_field(clause), "field"));
    CU_ASSERT(db_clause_type(clause) == DB_CLAUSE_NOT_EQUAL);
    CU_ASSERT(db_clause_operator(clause) == DB_CLAUSE_OPERATOR_OR);
    CU_ASSERT_PTR_NOT_NULL(db_clause_value(clause));
    CU_ASSERT_PTR_NULL(db_clause_next(clause));

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause2 = db_clause_new()));

    CU_ASSERT(!db_clause_set_type(clause2, DB_CLAUSE_NESTED));
    CU_ASSERT(!db_clause_set_operator(clause2, DB_CLAUSE_OPERATOR_OR));
    CU_ASSERT(!db_clause_set_list(clause2, (db_clause_list_t*)&fake_pointer));
    CU_ASSERT(!db_clause_not_empty(clause2));

    CU_ASSERT(db_clause_type(clause2) == DB_CLAUSE_NESTED);
    CU_ASSERT(db_clause_operator(clause2) == DB_CLAUSE_OPERATOR_OR);
    CU_ASSERT(db_clause_list(clause2) == (db_clause_list_t*)&fake_pointer);
    CU_ASSERT_PTR_NOT_NULL(db_clause_value(clause2));
}

void test_class_db_clause_list(void) {
    db_clause_t* local_clause = clause;
    db_clause_t* local_clause2 = clause2;
    const db_clause_t* clause_walk;

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));

    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause2));
    clause2 = NULL;

    CU_ASSERT((clause_walk = db_clause_list_begin(clause_list)) == local_clause);
    CU_ASSERT(db_clause_next(clause_walk) == local_clause2);

    db_clause_list_free(clause_list);
    clause_list = NULL;
    CU_PASS("db_clause_list_free");
    CU_PASS("db_clause_free");
}

void test_class_db_configuration(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((configuration = db_configuration_new()));
    CU_ASSERT(!db_configuration_set_name(configuration, "name1"));
    CU_ASSERT(!db_configuration_set_value(configuration, "value1"));
    CU_ASSERT(!db_configuration_not_empty(configuration));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_configuration_name(configuration));
    CU_ASSERT(!strcmp(db_configuration_name(configuration), "name1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_configuration_value(configuration));
    CU_ASSERT(!strcmp(db_configuration_value(configuration), "value1"));

    CU_ASSERT_PTR_NOT_NULL_FATAL((configuration2 = db_configuration_new()));
    CU_ASSERT(!db_configuration_set_name(configuration2, "name2"));
    CU_ASSERT(!db_configuration_set_value(configuration2, "value2"));
    CU_ASSERT(!db_configuration_not_empty(configuration2));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_configuration_name(configuration2));
    CU_ASSERT(!strcmp(db_configuration_name(configuration2), "name2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_configuration_value(configuration2));
    CU_ASSERT(!strcmp(db_configuration_value(configuration2), "value2"));
}

void test_class_db_configuration_list(void) {
    db_configuration_t* local_configuration = configuration;
    db_configuration_t* local_configuration2 = configuration2;

    CU_ASSERT_PTR_NOT_NULL_FATAL((configuration_list = db_configuration_list_new()));

    CU_ASSERT_FATAL(!db_configuration_list_add(configuration_list, configuration));
    configuration = NULL;
    CU_ASSERT_FATAL(!db_configuration_list_add(configuration_list, configuration2));
    configuration2 = NULL;

    CU_ASSERT(db_configuration_list_find(configuration_list, "name1") == local_configuration);
    CU_ASSERT(db_configuration_list_find(configuration_list, "name2") == local_configuration2);

    db_configuration_list_free(configuration_list);
    configuration_list = NULL;
    CU_PASS("db_configuration_list_free");
    CU_PASS("db_configuration_free");
}

void test_class_db_connection(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((connection = db_connection_new()));

    CU_ASSERT_FATAL(!db_connection_set_configuration_list(connection, (db_configuration_list_t*)&fake_pointer));

    connection->backend = backend;
    backend = NULL;

    CU_ASSERT_FATAL(!db_connection_setup(connection));
    CU_ASSERT(!db_connection_connect(connection));
    CU_ASSERT(!db_connection_disconnect(connection));
    CU_ASSERT(!db_connection_create(connection, (db_object_t*)&fake_pointer, (db_object_field_list_t*)&fake_pointer, (db_value_set_t*)&fake_pointer));
    CU_ASSERT(db_connection_read(connection, (db_object_t*)&fake_pointer, (db_join_list_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer) == (db_result_list_t*)&fake_pointer);
    CU_ASSERT(!db_connection_update(connection, (db_object_t*)&fake_pointer, (db_object_field_list_t*)&fake_pointer, (db_value_set_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer));
    CU_ASSERT(!db_connection_delete(connection, (db_object_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer));
    CU_ASSERT(!db_connection_count(connection, (db_object_t*)&fake_pointer, (db_join_list_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer, (size_t*)&fake_pointer));
    CU_ASSERT(!db_connection_transaction_begin(connection));
    CU_ASSERT(!db_connection_transaction_commit(connection));
    CU_ASSERT(!db_connection_transaction_rollback(connection));
}

void test_class_db_join(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((join = db_join_new()));
    CU_ASSERT(!db_join_set_from_table(join, "from_table1"));
    CU_ASSERT(!db_join_set_from_field(join, "from_field1"));
    CU_ASSERT(!db_join_set_to_table(join, "to_table1"));
    CU_ASSERT(!db_join_set_to_field(join, "to_field1"));
    CU_ASSERT(!db_join_not_empty(join));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_join_from_table(join));
    CU_ASSERT(!strcmp(db_join_from_table(join), "from_table1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_join_from_field(join));
    CU_ASSERT(!strcmp(db_join_from_field(join), "from_field1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_join_to_table(join));
    CU_ASSERT(!strcmp(db_join_to_table(join), "to_table1"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_join_to_field(join));
    CU_ASSERT(!strcmp(db_join_to_field(join), "to_field1"));

    CU_ASSERT_PTR_NOT_NULL_FATAL((join2 = db_join_new()));
    CU_ASSERT(!db_join_set_from_table(join2, "from_table2"));
    CU_ASSERT(!db_join_set_from_field(join2, "from_field2"));
    CU_ASSERT(!db_join_set_to_table(join2, "to_table2"));
    CU_ASSERT(!db_join_set_to_field(join2, "to_field2"));
    CU_ASSERT(!db_join_not_empty(join2));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_join_from_table(join2));
    CU_ASSERT(!strcmp(db_join_from_table(join2), "from_table2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_join_from_field(join2));
    CU_ASSERT(!strcmp(db_join_from_field(join2), "from_field2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_join_to_table(join2));
    CU_ASSERT(!strcmp(db_join_to_table(join2), "to_table2"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_join_to_field(join2));
    CU_ASSERT(!strcmp(db_join_to_field(join2), "to_field2"));
}

void test_class_db_join_list(void) {
    db_join_t* local_join = join;
    db_join_t* local_join2 = join2;
    const db_join_t* join_walk;

    CU_ASSERT_PTR_NOT_NULL_FATAL((join_list = db_join_list_new()));

    CU_ASSERT_FATAL(!db_join_list_add(join_list, join));
    join = NULL;
    CU_ASSERT_FATAL(!db_join_list_add(join_list, join2));
    join2 = NULL;

    CU_ASSERT((join_walk = db_join_list_begin(join_list)) == local_join);
    CU_ASSERT(db_join_next(join_walk) == local_join2);

    db_join_list_free(join_list);
    join_list = NULL;
    CU_PASS("db_join_list_free");
    CU_PASS("db_join_free");
}

void test_class_db_object_field(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field = db_object_field_new()));
    CU_ASSERT(!db_object_field_set_name(object_field, "field1"));
    CU_ASSERT(!db_object_field_set_type(object_field, DB_TYPE_INT32));
    CU_ASSERT(!db_object_field_not_empty(object_field));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_object_field_name(object_field));
    CU_ASSERT(!strcmp(db_object_field_name(object_field), "field1"));
    CU_ASSERT(db_object_field_type(object_field) == DB_TYPE_INT32);

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field2 = db_object_field_new()));
    CU_ASSERT(!db_object_field_set_name(object_field2, "field2"));
    CU_ASSERT(!db_object_field_set_type(object_field2, DB_TYPE_ENUM));
    CU_ASSERT(!db_object_field_set_enum_set(object_field2, (db_enum_t*)&fake_pointer));
    CU_ASSERT(!db_object_field_not_empty(object_field2));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_object_field_name(object_field2));
    CU_ASSERT(!strcmp(db_object_field_name(object_field2), "field2"));
    CU_ASSERT(db_object_field_type(object_field2) == DB_TYPE_ENUM);
    CU_ASSERT(db_object_field_enum_set(object_field2) == (db_enum_t*)&fake_pointer);
}

void test_class_db_object_field_list(void) {
    db_object_field_t* local_object_field = object_field;
    db_object_field_t* local_object_field2 = object_field2;
    const db_object_field_t* object_field_walk;

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field_list = db_object_field_list_new()));

    CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field));
    object_field = NULL;
    CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field2));
    object_field2 = NULL;

    CU_ASSERT((object_field_walk = db_object_field_list_begin(object_field_list)) == local_object_field);
    CU_ASSERT(db_object_field_next(object_field_walk) == local_object_field2);
}

void test_class_db_object(void) {
    db_object_field_list_t* local_object_field_list = object_field_list;
    db_backend_meta_data_list_t* local_backend_meta_data_list = backend_meta_data_list;

    CU_ASSERT_PTR_NOT_NULL_FATAL((object = db_object_new()));

    CU_ASSERT(!db_object_set_connection(object, connection));
    CU_ASSERT(!db_object_set_table(object, "table"));
    CU_ASSERT(!db_object_set_primary_key_name(object, "primary_key"));
    CU_ASSERT(!db_object_set_object_field_list(object, object_field_list));
    object_field_list = NULL;
    CU_ASSERT(!db_object_set_backend_meta_data_list(object, backend_meta_data_list));
    backend_meta_data_list = NULL;

    CU_ASSERT(db_object_connection(object) == connection);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_object_table(object));
    CU_ASSERT(!strcmp(db_object_table(object), "table"));
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_object_primary_key_name(object));
    CU_ASSERT(!strcmp(db_object_primary_key_name(object), "primary_key"));
    CU_ASSERT(db_object_object_field_list(object) == local_object_field_list);
    CU_ASSERT(db_object_backend_meta_data_list(object) == local_backend_meta_data_list);

    CU_ASSERT(!db_object_create(object, (db_object_field_list_t*)&fake_pointer, (db_value_set_t*)&fake_pointer));
    CU_ASSERT(db_object_read(object, (db_join_list_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer) == (db_result_list_t*)&fake_pointer);
    CU_ASSERT(!db_object_update(object, (db_object_field_list_t*)&fake_pointer, (db_value_set_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer));
    CU_ASSERT(!db_object_delete(object, (db_clause_list_t*)&fake_pointer));
    CU_ASSERT(!db_object_count(object, (db_join_list_t*)&fake_pointer, (db_clause_list_t*)&fake_pointer, (size_t*)&fake_pointer));

    db_object_free(object);
    object = NULL;
    CU_PASS("db_object_free");
}

void test_class_db_value_set(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((value_set = db_value_set_new(2)));
    CU_ASSERT(db_value_set_size(value_set) == 2);
    CU_ASSERT_PTR_NOT_NULL(db_value_set_at(value_set, 0));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_at(value_set, 1));
    CU_ASSERT_PTR_NULL(db_value_set_at(value_set, 2));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_get(value_set, 0));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_get(value_set, 1));
    CU_ASSERT_PTR_NULL(db_value_set_get(value_set, 2));

    CU_ASSERT_PTR_NOT_NULL_FATAL((value_set2 = db_value_set_new(6)));
    CU_ASSERT(db_value_set_size(value_set2) == 6);
    CU_ASSERT_PTR_NOT_NULL(db_value_set_at(value_set2, 0));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_at(value_set2, 1));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_at(value_set2, 2));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_at(value_set2, 3));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_at(value_set2, 4));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_at(value_set2, 5));
    CU_ASSERT_PTR_NULL(db_value_set_at(value_set2, 6));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_get(value_set2, 0));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_get(value_set2, 1));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_get(value_set2, 2));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_get(value_set2, 3));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_get(value_set2, 4));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_get(value_set2, 5));
    CU_ASSERT_PTR_NULL(db_value_set_get(value_set2, 6));
}

void test_class_db_result(void) {
    db_value_set_t* local_value_set = value_set;
    db_value_set_t* local_value_set2 = value_set2;
    db_backend_meta_data_list_t* local_backend_meta_data_list2 = backend_meta_data_list2;

    CU_ASSERT_PTR_NOT_NULL_FATAL((result = db_result_new()));
    CU_ASSERT(!db_result_set_value_set(result, value_set));
    value_set = NULL;
    CU_ASSERT(db_result_value_set(result) == local_value_set);
    CU_ASSERT(!db_result_set_backend_meta_data_list(result, backend_meta_data_list2));
    backend_meta_data_list2 = NULL;
    CU_ASSERT(db_result_backend_meta_data_list(result) == local_backend_meta_data_list2);
    CU_ASSERT(!db_result_not_empty(result));

    CU_ASSERT_PTR_NOT_NULL_FATAL((result2 = db_result_new()));
    CU_ASSERT(!db_result_set_value_set(result2, value_set2));
    value_set2 = NULL;
    CU_ASSERT(db_result_value_set(result2) == local_value_set2);
    CU_ASSERT(!db_result_not_empty(result2));
}

static int __db_result_list_next_count = 0;
db_result_t* __db_result_list_next(void* data, int finish) {
    db_value_set_t* value_set;
    db_result_t* result;

    CU_ASSERT_FATAL(data == &fake_pointer);

    if (finish) {
        return NULL;
    }

    if (__db_result_list_next_count > 2) {
        return NULL;
    }

    CU_ASSERT_PTR_NOT_NULL_FATAL((value_set = db_value_set_new(2)));
    CU_ASSERT(db_value_set_size(value_set) == 2);
    CU_ASSERT_PTR_NOT_NULL(db_value_set_at(value_set, 0));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_at(value_set, 1));
    CU_ASSERT_PTR_NULL(db_value_set_at(value_set, 2));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_get(value_set, 0));
    CU_ASSERT_PTR_NOT_NULL(db_value_set_get(value_set, 1));
    CU_ASSERT_PTR_NULL(db_value_set_get(value_set, 2));

    CU_ASSERT_PTR_NOT_NULL_FATAL((result = db_result_new()));
    CU_ASSERT(!db_result_set_value_set(result, value_set));
    CU_ASSERT(!db_result_not_empty(result));

    __db_result_list_next_count++;

    return result;
}

void test_class_db_result_list(void) {
    db_result_t* local_result = result;
    db_result_t* local_result2 = result2;

    CU_ASSERT_PTR_NOT_NULL_FATAL((result_list = db_result_list_new()));

    CU_ASSERT_FATAL(!db_result_list_add(result_list, result));
    result = NULL;
    CU_ASSERT_FATAL(!db_result_list_add(result_list, result2));
    result2 = NULL;

    CU_ASSERT(db_result_list_size(result_list) == 2);
    CU_ASSERT(db_result_list_begin(result_list) == local_result);
    CU_ASSERT(db_result_list_next(result_list) == local_result2);

    db_result_list_free(result_list);
    result_list = NULL;
    CU_PASS("db_result_list_free");
    CU_PASS("db_result_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((result_list = db_result_list_new()));

    CU_ASSERT_FATAL(!db_result_list_set_next(result_list, __db_result_list_next, &fake_pointer, 2));

    CU_ASSERT(db_result_list_size(result_list) == 2);
    CU_ASSERT_PTR_NOT_NULL(db_result_list_begin(result_list));
    CU_ASSERT_PTR_NOT_NULL(db_result_list_next(result_list));

    db_result_list_free(result_list);
    result_list = NULL;
    CU_PASS("db_result_list_free");
    CU_PASS("db_result_free");
}

void test_class_db_value(void) {
    char* text = NULL;
    const char* enum_text;
    int ret;
    db_type_int32_t int32;
    db_type_uint32_t uint32;
    db_type_int64_t int64;
    db_type_uint64_t uint64;
    CU_ASSERT_PTR_NOT_NULL_FATAL((value2 = db_value_new()));

    CU_ASSERT_PTR_NOT_NULL_FATAL((value = db_value_new()));
    CU_ASSERT(!db_value_from_text(value, "test"));
    CU_ASSERT(db_value_type(value) == DB_TYPE_TEXT);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_text(value));
    CU_ASSERT(!strcmp(db_value_text(value), "test"));
    CU_ASSERT(!db_value_to_text(value, &text));
    CU_ASSERT_PTR_NOT_NULL(text);
    free(text);
    text = NULL;
    CU_ASSERT(!db_value_not_empty(value));
    CU_ASSERT(!db_value_copy(value2, value));
    CU_ASSERT(db_value_type(value2) == DB_TYPE_TEXT);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_text(value2));
    CU_ASSERT(!strcmp(db_value_text(value2), "test"));
    CU_ASSERT(!db_value_cmp(value, value2, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(!db_value_set_primary_key(value));
    CU_ASSERT(db_value_primary_key(value));

    db_value_reset(value);
    CU_PASS("db_value_reset");

    CU_ASSERT(!db_value_from_int32(value, -12345));
    CU_ASSERT(db_value_type(value) == DB_TYPE_INT32);
    CU_ASSERT(!db_value_to_int32(value, &int32));
    CU_ASSERT(int32 == -12345);
    CU_ASSERT(!db_value_not_empty(value));
    db_value_reset(value2);
    CU_PASS("db_value_reset");
    CU_ASSERT(!db_value_copy(value2, value));
    CU_ASSERT(db_value_type(value2) == DB_TYPE_INT32);
    CU_ASSERT(!db_value_to_int32(value2, &int32));
    CU_ASSERT(int32 == -12345);
    CU_ASSERT(!db_value_cmp(value, value2, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(!db_value_set_primary_key(value));
    CU_ASSERT(db_value_primary_key(value));

    db_value_reset(value);
    CU_PASS("db_value_reset");

    CU_ASSERT(!db_value_from_uint32(value, 12345));
    CU_ASSERT(db_value_type(value) == DB_TYPE_UINT32);
    CU_ASSERT(!db_value_to_uint32(value, &uint32));
    CU_ASSERT(uint32 == 12345);
    CU_ASSERT(!db_value_not_empty(value));
    db_value_reset(value2);
    CU_PASS("db_value_reset");
    CU_ASSERT(!db_value_copy(value2, value));
    CU_ASSERT(db_value_type(value2) == DB_TYPE_UINT32);
    CU_ASSERT(!db_value_to_uint32(value2, &uint32));
    CU_ASSERT(uint32 == 12345);
    CU_ASSERT(!db_value_cmp(value, value2, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(!db_value_set_primary_key(value));
    CU_ASSERT(db_value_primary_key(value));

    db_value_reset(value);
    CU_PASS("db_value_reset");

    CU_ASSERT(!db_value_from_int64(value, -9223372036854775800));
    CU_ASSERT(db_value_type(value) == DB_TYPE_INT64);
    CU_ASSERT(!db_value_to_int64(value, &int64));
    CU_ASSERT(int64 == -9223372036854775800);
    CU_ASSERT(!db_value_not_empty(value));
    db_value_reset(value2);
    CU_PASS("db_value_reset");
    CU_ASSERT(!db_value_copy(value2, value));
    CU_ASSERT(db_value_type(value2) == DB_TYPE_INT64);
    CU_ASSERT(!db_value_to_int64(value2, &int64));
    CU_ASSERT(int64 == -9223372036854775800);
    CU_ASSERT(!db_value_cmp(value, value2, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(!db_value_set_primary_key(value));
    CU_ASSERT(db_value_primary_key(value));

    db_value_reset(value);
    CU_PASS("db_value_reset");


    CU_ASSERT(!db_value_from_uint64(value, 17446744073709551615UL));
    CU_ASSERT(db_value_type(value) == DB_TYPE_UINT64);
    CU_ASSERT(!db_value_to_uint64(value, &uint64));
    CU_ASSERT(uint64 == 17446744073709551615UL);
    CU_ASSERT(!db_value_not_empty(value));
    db_value_reset(value2);
    CU_PASS("db_value_reset");
    CU_ASSERT(!db_value_copy(value2, value));
    CU_ASSERT(db_value_type(value2) == DB_TYPE_UINT64);
    CU_ASSERT(!db_value_to_uint64(value2, &uint64));
    CU_ASSERT(uint64 == 17446744073709551615UL);
    CU_ASSERT(!db_value_cmp(value, value2, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(!db_value_set_primary_key(value));
    CU_ASSERT(db_value_primary_key(value));

    db_value_reset(value);
    CU_PASS("db_value_reset");

    CU_ASSERT(!db_value_from_enum_value(value, 2, enum_set));
    CU_ASSERT(db_value_type(value) == DB_TYPE_ENUM);
    CU_ASSERT(!db_value_enum_value(value, &ret));
    CU_ASSERT(ret == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_enum_text(value));
    CU_ASSERT(!strcmp(db_value_enum_text(value), "enum2"));
    CU_ASSERT(!db_value_to_enum_value(value, &ret, enum_set));
    CU_ASSERT(ret == 2);
    CU_ASSERT(!db_value_to_enum_text(value, &enum_text, enum_set));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enum_text);
    CU_ASSERT(!strcmp(enum_text, "enum2"));
    CU_ASSERT(!db_value_not_empty(value));
    db_value_reset(value2);
    CU_PASS("db_value_reset");
    CU_ASSERT(!db_value_copy(value2, value));
    CU_ASSERT(db_value_type(value2) == DB_TYPE_ENUM);
    CU_ASSERT(!db_value_enum_value(value2, &ret));
    CU_ASSERT(ret == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_enum_text(value2));
    CU_ASSERT(!strcmp(db_value_enum_text(value2), "enum2"));
    CU_ASSERT(!db_value_to_enum_value(value2, &ret, enum_set));
    CU_ASSERT(ret == 2);
    CU_ASSERT(!db_value_to_enum_text(value2, &enum_text, enum_set));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enum_text);
    CU_ASSERT(!strcmp(enum_text, "enum2"));
    CU_ASSERT(!db_value_cmp(value, value2, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(db_value_set_primary_key(value));
    CU_ASSERT(!db_value_primary_key(value));

    db_value_reset(value);
    CU_PASS("db_value_reset");

    CU_ASSERT(!db_value_from_enum_text(value, "enum2", enum_set));
    CU_ASSERT(db_value_type(value) == DB_TYPE_ENUM);
    CU_ASSERT(!db_value_enum_value(value, &ret));
    CU_ASSERT(ret == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_enum_text(value));
    CU_ASSERT(!strcmp(db_value_enum_text(value), "enum2"));
    CU_ASSERT(!db_value_to_enum_value(value, &ret, enum_set));
    CU_ASSERT(ret == 2);
    CU_ASSERT(!db_value_to_enum_text(value, &enum_text, enum_set));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enum_text);
    CU_ASSERT(!strcmp(enum_text, "enum2"));
    CU_ASSERT(!db_value_not_empty(value));
    db_value_reset(value2);
    CU_PASS("db_value_reset");
    CU_ASSERT(!db_value_copy(value2, value));
    CU_ASSERT(db_value_type(value2) == DB_TYPE_ENUM);
    CU_ASSERT(!db_value_enum_value(value2, &ret));
    CU_ASSERT(ret == 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_enum_text(value2));
    CU_ASSERT(!strcmp(db_value_enum_text(value2), "enum2"));
    CU_ASSERT(!db_value_to_enum_value(value2, &ret, enum_set));
    CU_ASSERT(ret == 2);
    CU_ASSERT(!db_value_to_enum_text(value2, &enum_text, enum_set));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enum_text);
    CU_ASSERT(!strcmp(enum_text, "enum2"));
    CU_ASSERT(!db_value_cmp(value, value2, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(db_value_set_primary_key(value));
    CU_ASSERT(!db_value_primary_key(value));

    db_value_reset(value);
    CU_PASS("db_value_reset");

    CU_ASSERT(!db_value_from_enum_value(value, 3, enum_set));
    CU_ASSERT(db_value_type(value) == DB_TYPE_ENUM);
    CU_ASSERT(!db_value_enum_value(value, &ret));
    CU_ASSERT(ret == 3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_enum_text(value));
    CU_ASSERT(!strcmp(db_value_enum_text(value), "enum3"));
    CU_ASSERT(!db_value_to_enum_value(value, &ret, enum_set));
    CU_ASSERT(ret == 3);
    CU_ASSERT(!db_value_to_enum_text(value, &enum_text, enum_set));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enum_text);
    CU_ASSERT(!strcmp(enum_text, "enum3"));
    CU_ASSERT(!db_value_not_empty(value));
    db_value_reset(value2);
    CU_PASS("db_value_reset");
    CU_ASSERT(!db_value_copy(value2, value));
    CU_ASSERT(db_value_type(value2) == DB_TYPE_ENUM);
    CU_ASSERT(!db_value_enum_value(value2, &ret));
    CU_ASSERT(ret == 3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_enum_text(value2));
    CU_ASSERT(!strcmp(db_value_enum_text(value2), "enum3"));
    CU_ASSERT(!db_value_to_enum_value(value2, &ret, enum_set));
    CU_ASSERT(ret == 3);
    CU_ASSERT(!db_value_to_enum_text(value2, &enum_text, enum_set));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enum_text);
    CU_ASSERT(!strcmp(enum_text, "enum3"));
    CU_ASSERT(!db_value_cmp(value, value2, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(db_value_set_primary_key(value));
    CU_ASSERT(!db_value_primary_key(value));

    db_value_reset(value);
    CU_PASS("db_value_reset");

    CU_ASSERT(!db_value_from_enum_text(value, "enum3", enum_set));
    CU_ASSERT(db_value_type(value) == DB_TYPE_ENUM);
    CU_ASSERT(!db_value_enum_value(value, &ret));
    CU_ASSERT(ret == 3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_enum_text(value));
    CU_ASSERT(!strcmp(db_value_enum_text(value), "enum3"));
    CU_ASSERT(!db_value_to_enum_value(value, &ret, enum_set));
    CU_ASSERT(ret == 3);
    CU_ASSERT(!db_value_to_enum_text(value, &enum_text, enum_set));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enum_text);
    CU_ASSERT(!strcmp(enum_text, "enum3"));
    CU_ASSERT(!db_value_not_empty(value));
    db_value_reset(value2);
    CU_PASS("db_value_reset");
    CU_ASSERT(!db_value_copy(value2, value));
    CU_ASSERT(db_value_type(value2) == DB_TYPE_ENUM);
    CU_ASSERT(!db_value_enum_value(value2, &ret));
    CU_ASSERT(ret == 3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_enum_text(value2));
    CU_ASSERT(!strcmp(db_value_enum_text(value2), "enum3"));
    CU_ASSERT(!db_value_to_enum_value(value2, &ret, enum_set));
    CU_ASSERT(ret == 3);
    CU_ASSERT(!db_value_to_enum_text(value2, &enum_text, enum_set));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enum_text);
    CU_ASSERT(!strcmp(enum_text, "enum3"));
    CU_ASSERT(!db_value_cmp(value, value2, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(db_value_set_primary_key(value));
    CU_ASSERT(!db_value_primary_key(value));

    db_value_reset(value);
    CU_PASS("db_value_reset");

    CU_ASSERT(!db_value_from_enum_value(value, 1, enum_set));
    CU_ASSERT(db_value_type(value) == DB_TYPE_ENUM);
    CU_ASSERT(!db_value_enum_value(value, &ret));
    CU_ASSERT(ret == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_enum_text(value));
    CU_ASSERT(!strcmp(db_value_enum_text(value), "enum1"));
    CU_ASSERT(!db_value_to_enum_value(value, &ret, enum_set));
    CU_ASSERT(ret == 1);
    CU_ASSERT(!db_value_to_enum_text(value, &enum_text, enum_set));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enum_text);
    CU_ASSERT(!strcmp(enum_text, "enum1"));
    CU_ASSERT(!db_value_not_empty(value));
    db_value_reset(value2);
    CU_PASS("db_value_reset");
    CU_ASSERT(!db_value_copy(value2, value));
    CU_ASSERT(db_value_type(value2) == DB_TYPE_ENUM);
    CU_ASSERT(!db_value_enum_value(value2, &ret));
    CU_ASSERT(ret == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_enum_text(value2));
    CU_ASSERT(!strcmp(db_value_enum_text(value2), "enum1"));
    CU_ASSERT(!db_value_to_enum_value(value2, &ret, enum_set));
    CU_ASSERT(ret == 1);
    CU_ASSERT(!db_value_to_enum_text(value2, &enum_text, enum_set));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enum_text);
    CU_ASSERT(!strcmp(enum_text, "enum1"));
    CU_ASSERT(!db_value_cmp(value, value2, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(db_value_set_primary_key(value));
    CU_ASSERT(!db_value_primary_key(value));

    db_value_reset(value);
    CU_PASS("db_value_reset");

    CU_ASSERT(!db_value_from_enum_text(value, "enum1", enum_set));
    CU_ASSERT(db_value_type(value) == DB_TYPE_ENUM);
    CU_ASSERT(!db_value_enum_value(value, &ret));
    CU_ASSERT(ret == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_enum_text(value));
    CU_ASSERT(!strcmp(db_value_enum_text(value), "enum1"));
    CU_ASSERT(!db_value_to_enum_value(value, &ret, enum_set));
    CU_ASSERT(ret == 1);
    CU_ASSERT(!db_value_to_enum_text(value, &enum_text, enum_set));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enum_text);
    CU_ASSERT(!strcmp(enum_text, "enum1"));
    CU_ASSERT(!db_value_not_empty(value));
    db_value_reset(value2);
    CU_PASS("db_value_reset");
    CU_ASSERT(!db_value_copy(value2, value));
    CU_ASSERT(db_value_type(value2) == DB_TYPE_ENUM);
    CU_ASSERT(!db_value_enum_value(value2, &ret));
    CU_ASSERT(ret == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(db_value_enum_text(value2));
    CU_ASSERT(!strcmp(db_value_enum_text(value2), "enum1"));
    CU_ASSERT(!db_value_to_enum_value(value2, &ret, enum_set));
    CU_ASSERT(ret == 1);
    CU_ASSERT(!db_value_to_enum_text(value2, &enum_text, enum_set));
    CU_ASSERT_PTR_NOT_NULL_FATAL(enum_text);
    CU_ASSERT(!strcmp(enum_text, "enum1"));
    CU_ASSERT(!db_value_cmp(value, value2, &ret));
    CU_ASSERT(!ret);
    CU_ASSERT(db_value_set_primary_key(value));
    CU_ASSERT(!db_value_primary_key(value));

    db_value_free(value);
    value = NULL;
    CU_PASS("db_value_free");
    db_value_free(value2);
    value2 = NULL;
    CU_PASS("db_value_free");
}

void test_class_end(void) {
    db_result_free(result);
    result = NULL;
    db_result_free(result2);
    result2 = NULL;
    CU_PASS("db_result_free");

    db_value_set_free(value_set);
    value_set = NULL;
    db_value_set_free(value_set2);
    value_set2 = NULL;
    CU_PASS("db_value_set_free");

    db_object_field_list_free(object_field_list);
    object_field_list = NULL;
    CU_PASS("db_object_field_list_free");
    CU_PASS("db_object_field_free");

    db_connection_free(connection);
    connection = NULL;
    CU_PASS("db_connection_free");

    db_backend_free(backend);
    backend = NULL;
    CU_PASS("db_backend_handle_free");
    CU_PASS("db_backend_free");
}
