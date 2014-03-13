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

#ifndef __db_backend_h
#define __db_backend_h

#ifdef __cplusplus
extern "C" {
#endif

struct db_backend_handle;
struct db_backend;
typedef struct db_backend_handle db_backend_handle_t;
typedef struct db_backend db_backend_t;
/* TODO: db_backend_result(_list)_t: walkable results for backend that support it, tied into db_result_list_t */

#ifdef __cplusplus
}
#endif

#include "db_configuration.h"
#include "db_result.h"
#include "db_object.h"
#include "db_join.h"
#include "db_clause.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*db_backend_handle_initialize_t)(void*);
typedef int (*db_backend_handle_shutdown_t)(void*);
typedef int (*db_backend_handle_connect_t)(void*, const db_configuration_list_t*);
typedef int (*db_backend_handle_disconnect_t)(void*);
typedef int (*db_backend_handle_create_t)(void*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*);
typedef db_result_list_t* (*db_backend_handle_read_t)(void*, const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
typedef int (*db_backend_handle_update_t)(void*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*, const db_join_list_t*, const db_clause_list_t*);
typedef int (*db_backend_handle_delete_t)(void*, const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
typedef void (*db_backend_handle_free_t)(void*);
typedef int (*db_backend_handle_transaction_begin_t)(void*);
typedef int (*db_backend_handle_transaction_commit_t)(void*);
typedef int (*db_backend_handle_transaction_rollback_t)(void*);

struct db_backend_handle {
    void* data;
    db_backend_handle_initialize_t initialize_function;
    db_backend_handle_shutdown_t shutdown_function;
    db_backend_handle_connect_t connect_function;
    db_backend_handle_disconnect_t disconnect_function;
    db_backend_handle_create_t create_function;
    db_backend_handle_read_t read_function;
    db_backend_handle_update_t update_function;
    db_backend_handle_delete_t delete_function;
    db_backend_handle_free_t free_function;
    db_backend_handle_transaction_begin_t transaction_begin_function;
    db_backend_handle_transaction_commit_t transaction_commit_function;
    db_backend_handle_transaction_rollback_t transaction_rollback_function;
};

db_backend_handle_t* db_backend_handle_new(void);
void db_backend_handle_free(db_backend_handle_t*);
int db_backend_handle_initialize(const db_backend_handle_t*);
int db_backend_handle_shutdown(const db_backend_handle_t*);
int db_backend_handle_connect(const db_backend_handle_t*, const db_configuration_list_t*);
int db_backend_handle_disconnect(const db_backend_handle_t*);
int db_backend_handle_create(const db_backend_handle_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*);
db_result_list_t* db_backend_handle_read(const db_backend_handle_t*, const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
int db_backend_handle_update(const db_backend_handle_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*, const db_join_list_t*, const db_clause_list_t*);
int db_backend_handle_delete(const db_backend_handle_t*, const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
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

struct db_backend {
    db_backend_t* next;
    char* name;
    db_backend_handle_t* handle;
};

db_backend_t* db_backend_new(void);
void db_backend_free(db_backend_t*);
const char* db_backend_name(const db_backend_t*);
const db_backend_handle_t* db_backend_handle(const db_backend_t*);
int db_backend_set_name(db_backend_t*, const char*);
int db_backend_set_handle(db_backend_t*, db_backend_handle_t*);
int db_backend_not_empty(const db_backend_t*);
int db_backend_initialize(const db_backend_t*);
int db_backend_shutdown(const db_backend_t*);
int db_backend_connect(const db_backend_t*, const db_configuration_list_t*);
int db_backend_disconnect(const db_backend_t*);
int db_backend_create(const db_backend_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*);
db_result_list_t* db_backend_read(const db_backend_t*, const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
int db_backend_update(const db_backend_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*, const db_join_list_t*, const db_clause_list_t*);
int db_backend_delete(const db_backend_t*, const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
int db_backend_transaction_begin(const db_backend_t*);
int db_backend_transaction_commit(const db_backend_t*);
int db_backend_transaction_rollback(const db_backend_t*);

db_backend_t* db_backend_factory_get_backend(const char*);

#ifdef __cplusplus
}
#endif

#endif
