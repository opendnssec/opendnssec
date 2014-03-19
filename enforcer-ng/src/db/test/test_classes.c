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

#include "../db_configuration.h"
#include "../db_connection.h"
#include "../db_backend.h"

#include "CUnit/Basic.h"

static db_backend_handle_t* backend_handle = NULL;
static db_backend_t* backend = NULL;
static int backend_data = 0;

int init_suite_classes(void) {
    if (backend_handle) {
        return 1;
    }
    if (backend) {
        return 1;
    }
    return 0;
}

int clean_suite_classes(void) {
    db_backend_handle_free(backend_handle);
    backend_handle = NULL;
    db_backend_free(backend);
    backend = NULL;
    return 0;
}

int __db_backend_handle_initialize(void* data) {
    CU_ASSERT(data == &backend_data);
    return 0;
}

int __db_backend_handle_shutdown(void* data) {
    CU_ASSERT(data == &backend_data);
    return 0;
}

int __db_backend_handle_connect(void* data, const db_configuration_list_t* configuration_list) {
    CU_ASSERT(data == &backend_data);
    CU_ASSERT((void*)configuration_list == &backend_data);
    return 0;
}

int __db_backend_handle_disconnect(void* data) {
    CU_ASSERT(data == &backend_data);
    return 0;
}

int __db_backend_handle_create(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set) {
    CU_ASSERT(data == &backend_data);
    CU_ASSERT((void*)object == &backend_data);
    CU_ASSERT((void*)object_field_list == &backend_data);
    CU_ASSERT((void*)value_set == &backend_data);
    return 0;
}

db_result_list_t* __db_backend_handle_read(void* data, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
    CU_ASSERT(data == &backend_data);
    CU_ASSERT((void*)object == &backend_data);
    CU_ASSERT((void*)join_list == &backend_data);
    CU_ASSERT((void*)clause_list == &backend_data);
    return (db_result_list_t*)&backend_data;
}

int __db_backend_handle_update(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list) {
    CU_ASSERT(data == &backend_data);
    CU_ASSERT((void*)object == &backend_data);
    CU_ASSERT((void*)object_field_list == &backend_data);
    CU_ASSERT((void*)value_set == &backend_data);
    CU_ASSERT((void*)clause_list == &backend_data);
    return 0;
}

int __db_backend_handle_delete(void* data, const db_object_t* object, const db_clause_list_t* clause_list) {
    CU_ASSERT(data == &backend_data);
    CU_ASSERT((void*)object == &backend_data);
    CU_ASSERT((void*)clause_list == &backend_data);
    return 0;
}

void __db_backend_handle_free(void* data) {
    CU_ASSERT(data == &backend_data);
}

int __db_backend_handle_transaction_begin(void* data) {
    CU_ASSERT(data == &backend_data);
    return 0;
}

int __db_backend_handle_transaction_commit(void* data) {
    CU_ASSERT(data == &backend_data);
    return 0;
}

int __db_backend_handle_transaction_rollback(void* data) {
    CU_ASSERT(data == &backend_data);
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
    CU_ASSERT(!db_backend_handle_set_free(backend_handle, __db_backend_handle_free));
    CU_ASSERT(!db_backend_handle_set_transaction_begin(backend_handle, __db_backend_handle_transaction_begin));
    CU_ASSERT(!db_backend_handle_set_transaction_commit(backend_handle, __db_backend_handle_transaction_commit));
    CU_ASSERT(!db_backend_handle_set_transaction_rollback(backend_handle, __db_backend_handle_transaction_rollback));
    CU_ASSERT(!db_backend_handle_set_data(backend_handle, &backend_data));

    CU_ASSERT_FATAL(!db_backend_handle_not_empty(backend_handle));
    CU_ASSERT(db_backend_handle_data(backend_handle) == &backend_data);

    CU_ASSERT(!db_backend_handle_initialize(backend_handle));
    CU_ASSERT(!db_backend_handle_shutdown(backend_handle));
    CU_ASSERT(!db_backend_handle_connect(backend_handle, (db_configuration_list_t*)&backend_data));
    CU_ASSERT(!db_backend_handle_disconnect(backend_handle));
    CU_ASSERT(!db_backend_handle_create(backend_handle, (db_object_t*)&backend_data, (db_object_field_list_t*)&backend_data, (db_value_set_t*)&backend_data));
    CU_ASSERT(db_backend_handle_read(backend_handle, (db_object_t*)&backend_data, (db_join_list_t*)&backend_data, (db_clause_list_t*)&backend_data) == (db_result_list_t*)&backend_data);
    CU_ASSERT(!db_backend_handle_update(backend_handle, (db_object_t*)&backend_data, (db_object_field_list_t*)&backend_data, (db_value_set_t*)&backend_data, (db_clause_list_t*)&backend_data));
    CU_ASSERT(!db_backend_handle_delete(backend_handle, (db_object_t*)&backend_data, (db_clause_list_t*)&backend_data));
    CU_ASSERT(!db_backend_handle_transaction_begin(backend_handle));
    CU_ASSERT(!db_backend_handle_transaction_commit(backend_handle));
    CU_ASSERT(!db_backend_handle_transaction_rollback(backend_handle));
}

void test_class_db_backend(void) {
    db_backend_handle_t* local_backend_handle;

    CU_ASSERT_PTR_NOT_NULL_FATAL((backend = db_backend_new()));
    CU_ASSERT_FATAL(!db_backend_set_name(backend, "test"));
    CU_ASSERT_FATAL(!strcmp(db_backend_name(backend), "test"));
    CU_ASSERT_FATAL(!db_backend_set_handle(backend, backend_handle));
    local_backend_handle = backend_handle;
    backend_handle = NULL;
    CU_ASSERT_FATAL(db_backend_handle(backend) == local_backend_handle);
    CU_ASSERT_FATAL(!db_backend_not_empty(backend));

    CU_ASSERT(!db_backend_initialize(backend));
    CU_ASSERT(!db_backend_shutdown(backend));
    CU_ASSERT(!db_backend_connect(backend, (db_configuration_list_t*)&backend_data));
    CU_ASSERT(!db_backend_disconnect(backend));
    CU_ASSERT(!db_backend_create(backend, (db_object_t*)&backend_data, (db_object_field_list_t*)&backend_data, (db_value_set_t*)&backend_data));
    CU_ASSERT(db_backend_read(backend, (db_object_t*)&backend_data, (db_join_list_t*)&backend_data, (db_clause_list_t*)&backend_data) == (db_result_list_t*)&backend_data);
    CU_ASSERT(!db_backend_update(backend, (db_object_t*)&backend_data, (db_object_field_list_t*)&backend_data, (db_value_set_t*)&backend_data, (db_clause_list_t*)&backend_data));
    CU_ASSERT(!db_backend_delete(backend, (db_object_t*)&backend_data, (db_clause_list_t*)&backend_data));
    CU_ASSERT(!db_backend_transaction_begin(backend));
    CU_ASSERT(!db_backend_transaction_commit(backend));
    CU_ASSERT(!db_backend_transaction_rollback(backend));

    db_backend_free(backend);
    backend = NULL;
    CU_PASS("db_backend_handle_free");
    CU_PASS("db_backend_free");
}
