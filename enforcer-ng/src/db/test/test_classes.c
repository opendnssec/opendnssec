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

void test_class_db_backend_handle(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((backend_handle = db_backend_handle_new()));
    /*
    int db_backend_handle_initialize(const db_backend_handle_t*);
    int db_backend_handle_shutdown(const db_backend_handle_t*);
    int db_backend_handle_connect(const db_backend_handle_t*, const db_configuration_list_t*);
    int db_backend_handle_disconnect(const db_backend_handle_t*);
    int db_backend_handle_create(const db_backend_handle_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*);
    db_result_list_t* db_backend_handle_read(const db_backend_handle_t*, const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
    int db_backend_handle_update(const db_backend_handle_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*, const db_clause_list_t*);
    int db_backend_handle_delete(const db_backend_handle_t*, const db_object_t*, const db_clause_list_t*);
    int db_backend_handle_transaction_begin(const db_backend_handle_t*);
    int db_backend_handle_transaction_commit(const db_backend_handle_t*);
    int db_backend_handle_transaction_rollback(const db_backend_handle_t*);
    const void* db_backend_handle_data(const db_backend_handle_t*);
    int db_backend_handle_set_initialize(db_backend_handle_t*, db_backend_handle_initialize_t);
    int db_backend_handle_set_shutdown(db_backend_handle_t*, db_backend_handle_shutdown_t);
    int db_backend_handle_set_connect(db_backend_handle_t*, db_backend_handle_connect_t);
    int db_backend_handle_set_disconnect(db_backend_handle_t*, db_backend_handle_disconnect_t);
    int db_backend_handle_set_create(db_backend_handle_t*, db_backend_handle_create_t);
    int db_backend_handle_set_read(db_backend_handle_t*, db_backend_handle_read_t);
    int db_backend_handle_set_update(db_backend_handle_t*, db_backend_handle_update_t);
    int db_backend_handle_set_delete(db_backend_handle_t*, db_backend_handle_delete_t);
    int db_backend_handle_set_free(db_backend_handle_t*, db_backend_handle_free_t);
    int db_backend_handle_set_transaction_begin(db_backend_handle_t*, db_backend_handle_transaction_begin_t);
    int db_backend_handle_set_transaction_commit(db_backend_handle_t*, db_backend_handle_transaction_commit_t);
    int db_backend_handle_set_transaction_rollback(db_backend_handle_t*, db_backend_handle_transaction_rollback_t);
    int db_backend_handle_set_data(db_backend_handle_t*, void*);
    int db_backend_handle_not_empty(const db_backend_handle_t*);
    */
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
    /*
    int db_backend_initialize(const db_backend_t*);
    int db_backend_shutdown(const db_backend_t*);
    int db_backend_connect(const db_backend_t*, const db_configuration_list_t*);
    int db_backend_disconnect(const db_backend_t*);
    int db_backend_create(const db_backend_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*);
    db_result_list_t* db_backend_read(const db_backend_t*, const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
    int db_backend_update(const db_backend_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*, const db_clause_list_t*);
    int db_backend_delete(const db_backend_t*, const db_object_t*, const db_clause_list_t*);
    int db_backend_transaction_begin(const db_backend_t*);
    int db_backend_transaction_commit(const db_backend_t*);
    int db_backend_transaction_rollback(const db_backend_t*);
    */
    db_backend_free(backend);
    backend = NULL;
    CU_PASS("db_backend_handle_free");
    CU_PASS("db_backend_free");
}
