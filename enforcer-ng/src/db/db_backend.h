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
struct db_backend_meta_data;
struct db_backend_meta_data_list;
typedef struct db_backend_handle db_backend_handle_t;
typedef struct db_backend db_backend_t;
typedef struct db_backend_meta_data db_backend_meta_data_t;
typedef struct db_backend_meta_data_list db_backend_meta_data_list_t;

#ifdef __cplusplus
}
#endif

#include "db_configuration.h"
#include "db_result.h"
#include "db_object.h"
#include "db_join.h"
#include "db_clause.h"
#include "db_value.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Function pointer for initializing a database backend. The backend handle
 * specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_initialize_t)(void* data);

/**
 * Function pointer for shutting down a database backend. The backend handle
 * specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_shutdown_t)(void* data);

/**
 * Function pointer for connecting a database backend. The backend handle
 * specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \param[in] configuration_list TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_connect_t)(void* data, const db_configuration_list_t* configuration_list);

/**
 * Function pointer for disconnecting a database backend. The backend handle
 * specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_disconnect_t)(void* data);

/**
 * Function pointer for creating a object in a database backend. The backend
 * handle specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \param[in] object TODO 
 * \param[in] object_field_list TODO 
 * \param[in] value_set TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_create_t)(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set);

/**
 * Function pointer for reading objects from database backend. The backend
 * handle specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \param[in] object TODO 
 * \param[in] join_list TODO 
 * \param[in] clause_list TODO 
 * \return a db_result_list_t pointer or NULL on error or if no objects where
 * read.
 */
typedef db_result_list_t* (*db_backend_handle_read_t)(void* data, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list);

/**
 * Function pointer for updating objects in a database backend. The backend
 * handle specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \param[in] object TODO 
 * \param[in] object_field_list TODO 
 * \param[in] value_set TODO 
 * \param[in] clause_list TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_update_t)(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list);

/**
 * Function pointer for deleting objects from database backend. The backend
 * handle specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \param[in] object TODO 
 * \param[in] clause_list TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_delete_t)(void* data, const db_object_t* object, const db_clause_list_t* clause_list);

/**
 * Function pointer for freeing the backend handle specific data in `data`.
 * \param[in] data a void pointer.
 * \return `typedef void` TODO
 */
typedef void (*db_backend_handle_free_t)(void* data);

/**
 * Function pointer for beginning a transaction in a database backend. The
 * backend handle specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_transaction_begin_t)(void* data);

/**
 * Function pointer for committing a transaction in a database backend. The
 * backend handle specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_transaction_commit_t)(void* data);

/**
 * Function pointer for rolling back a transaction in a database backend. The
 * backend handle specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_transaction_rollback_t)(void* data);

/**
 * A database backend handle that contains all function pointers for a backend
 * and the backend specific data.
 */
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

/**
 * Create a new database backend handle.
 * \return a db_backend_handle_t pointer or NULL on error.
 */
db_backend_handle_t* db_backend_handle_new(void);

/**
 * Delete a database backend handle, disconnecting the backend and freeing the
 * backend specific data.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 */
void db_backend_handle_free(db_backend_handle_t* backend_handle);

/**
 * Initiate the backend of a database backend.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_initialize(const db_backend_handle_t* backend_handle);

/**
 * Shutdown the backend of a database backend.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_shutdown(const db_backend_handle_t* backend_handle);

/**
 * Connect to the database of a database backend, the connection specific
 * configuration is given by `configuration_list`.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] configuration_list a db_configuration_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_connect(const db_backend_handle_t* backend_handle, const db_configuration_list_t* configuration_list);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_disconnect(const db_backend_handle_t* backend_handle);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] object TODO 
 * \param[in] object_field_list TODO 
 * \param[in] value_set TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_create(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] object TODO 
 * \param[in] join_list TODO 
 * \param[in] clause_list TODO 
 * \return a db_result_list_t pointer or NULL on error or if no objects where
 * read.
 */
db_result_list_t* db_backend_handle_read(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] object TODO 
 * \param[in] object_field_list TODO 
 * \param[in] value_set TODO 
 * \param[in] clause_list TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_update(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] object TODO 
 * \param[in] clause_list TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_delete(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_clause_list_t* clause_list);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_transaction_begin(const db_backend_handle_t* backend_handle);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_transaction_commit(const db_backend_handle_t* backend_handle);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_transaction_rollback(const db_backend_handle_t* backend_handle);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \return `const void*` TODO
 */
const void* db_backend_handle_data(const db_backend_handle_t* backend_handle);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] initialize_function TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_initialize(db_backend_handle_t* backend_handle, db_backend_handle_initialize_t initialize_function);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] shutdown_function TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_shutdown(db_backend_handle_t* backend_handle, db_backend_handle_shutdown_t shutdown_function);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] connect_function TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_connect(db_backend_handle_t* backend_handle, db_backend_handle_connect_t connect_function);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] disconnect_function TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_disconnect(db_backend_handle_t* backend_handle, db_backend_handle_disconnect_t disconnect_function);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] create_function TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_create(db_backend_handle_t* backend_handle, db_backend_handle_create_t create_function);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] read_function TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_read(db_backend_handle_t* backend_handle, db_backend_handle_read_t read_function);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] update_function TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_update(db_backend_handle_t* backend_handle, db_backend_handle_update_t update_function);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] delete_function TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_delete(db_backend_handle_t* backend_handle, db_backend_handle_delete_t delete_function);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] free_function TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_free(db_backend_handle_t* backend_handle, db_backend_handle_free_t free_function);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] transaction_begin_function TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_transaction_begin(db_backend_handle_t* backend_handle, db_backend_handle_transaction_begin_t transaction_begin_function);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] transaction_commit_function TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_transaction_commit(db_backend_handle_t* backend_handle, db_backend_handle_transaction_commit_t transaction_commit_function);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] transaction_rollback_function TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_transaction_rollback(db_backend_handle_t* backend_handle, db_backend_handle_transaction_rollback_t transaction_rollback_function);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] data a void pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_data(db_backend_handle_t* backend_handle, void* data);

/**
 * TODO
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \return DB_ERROR_* if empty, otherwise DB_OK.
 */
int db_backend_handle_not_empty(const db_backend_handle_t* backend_handle);

/**
 * TODO
 */
struct db_backend {
    db_backend_t* next;
    char* name;
    db_backend_handle_t* handle;
};

/**
 * TODO
 * \param[in] void TODO 
 * \return `db_backend_t*` TODO
 */
db_backend_t* db_backend_new(void);

/**
 * TODO
 * \param[in] backend TODO 
 * \return `void` TODO
 */
void db_backend_free(db_backend_t* backend);

/**
 * TODO
 * \param[in] backend TODO 
 * \return `const char*` TODO
 */
const char* db_backend_name(const db_backend_t* backend);

/**
 * TODO
 * \param[in] backend TODO 
 * \return `const db_backend_handle_t*` TODO
 */
const db_backend_handle_t* db_backend_handle(const db_backend_t* backend);

/**
 * TODO
 * \param[in] backend TODO 
 * \param[in] name TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_set_name(db_backend_t* backend, const char* name);

/**
 * TODO
 * \param[in] backend TODO 
 * \param[in] handle TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_set_handle(db_backend_t* backend, db_backend_handle_t* handle);

/**
 * TODO
 * \param[in] backend TODO 
 * \return DB_ERROR_* if empty, otherwise DB_OK.
 */
int db_backend_not_empty(const db_backend_t* backend);

/**
 * TODO
 * \param[in] backend TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_initialize(const db_backend_t* backend);

/**
 * TODO
 * \param[in] backend TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_shutdown(const db_backend_t* backend);

/**
 * TODO
 * \param[in] backend TODO 
 * \param[in] configuration_list TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_connect(const db_backend_t* backend, const db_configuration_list_t* configuration_list);

/**
 * TODO
 * \param[in] backend TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_disconnect(const db_backend_t* backend);

/**
 * TODO
 * \param[in] backend TODO 
 * \param[in] object TODO 
 * \param[in] object_field_list TODO 
 * \param[in] value_set TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_create(const db_backend_t* backend, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set);

/**
 * TODO
 * \param[in] backend TODO 
 * \param[in] object TODO 
 * \param[in] join_list TODO 
 * \param[in] clause_list TODO 
 * \return a db_result_list_t pointer or NULL on error or if no objects where
 * read.
 */
db_result_list_t* db_backend_read(const db_backend_t* backend, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list);

/**
 * TODO
 * \param[in] backend TODO 
 * \param[in] object TODO 
 * \param[in] object_field_list TODO 
 * \param[in] value_set TODO 
 * \param[in] clause_list TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_update(const db_backend_t* backend, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list);

/**
 * TODO
 * \param[in] backend TODO 
 * \param[in] object TODO 
 * \param[in] clause_list TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_delete(const db_backend_t* backend, const db_object_t* object, const db_clause_list_t* clause_list);

/**
 * TODO
 * \param[in] backend TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_transaction_begin(const db_backend_t* backend);

/**
 * TODO
 * \param[in] backend TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_transaction_commit(const db_backend_t* backend);

/**
 * TODO
 * \param[in] backend TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_transaction_rollback(const db_backend_t* backend);

/**
 * TODO
 * \param[in] name TODO 
 * \return `db_backend_t*` TODO
 */
db_backend_t* db_backend_factory_get_backend(const char* name);

/**
 * TODO
 * \param[in] void TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_factory_shutdown(void);

/**
 * TODO
 */
struct db_backend_meta_data {
    db_backend_meta_data_t* next;
    char* name;
    db_value_t* value;
};

/**
 * TODO
 * \param[in] void TODO 
 * \return `db_backend_meta_data_t*` TODO
 */
db_backend_meta_data_t* db_backend_meta_data_new(void);

/**
 * TODO
 * \param[in] backend_meta_data TODO 
 * \return `void` TODO
 */
void db_backend_meta_data_free(db_backend_meta_data_t* backend_meta_data);

/**
 * TODO
 * \param[in] backend_meta_data TODO 
 * \param[in] from_backend_meta_data TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_meta_data_copy(db_backend_meta_data_t* backend_meta_data, const db_backend_meta_data_t* from_backend_meta_data);

/**
 * TODO
 * \param[in] backend_meta_data TODO 
 * \return `const char*` TODO
 */
const char* db_backend_meta_data_name(const db_backend_meta_data_t* backend_meta_data);

/**
 * TODO
 * \param[in] backend_meta_data TODO 
 * \return `const db_value_t*` TODO
 */
const db_value_t* db_backend_meta_data_value(const db_backend_meta_data_t* backend_meta_data);

/**
 * TODO
 * \param[in] backend_meta_data TODO 
 * \param[in] name TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_meta_data_set_name(db_backend_meta_data_t* backend_meta_data, const char* name);

/**
 * TODO
 * \param[in] backend_meta_data TODO 
 * \param[in] value TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_meta_data_set_value(db_backend_meta_data_t* backend_meta_data, db_value_t* value);

/**
 * TODO
 * \param[in] backend_meta_data TODO 
 * \return DB_ERROR_* if empty, otherwise DB_OK.
 */
int db_backend_meta_data_not_empty(const db_backend_meta_data_t* backend_meta_data);

/**
 * TODO
 */
struct db_backend_meta_data_list {
    db_backend_meta_data_t* begin;
    db_backend_meta_data_t* end;
};

/**
 * TODO
 * \param[in] void TODO 
 * \return `db_backend_meta_data_list_t*` TODO
 */
db_backend_meta_data_list_t* db_backend_meta_data_list_new(void);

/**
 * TODO
 * \param[in] backend_meta_data_list TODO 
 * \return `void` TODO
 */
void db_backend_meta_data_list_free(db_backend_meta_data_list_t* backend_meta_data_list);

/**
 * TODO
 * \param[in] backend_meta_data_list TODO 
 * \param[in] from_backend_meta_data_list TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_meta_data_list_copy(db_backend_meta_data_list_t* backend_meta_data_list, const db_backend_meta_data_list_t* from_backend_meta_data_list);

/**
 * TODO
 * \param[in] backend_meta_data_list TODO 
 * \param[in] backend_meta_data TODO 
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_meta_data_list_add(db_backend_meta_data_list_t* backend_meta_data_list, db_backend_meta_data_t* backend_meta_data);

/**
 * TODO
 * \param[in] backend_meta_data_list TODO 
 * \param[in] name TODO 
 * \return `const db_backend_meta_data_t*` TODO
 */
const db_backend_meta_data_t* db_backend_meta_data_list_find(const db_backend_meta_data_list_t* backend_meta_data_list, const char* name);

#ifdef __cplusplus
}
#endif

#endif
