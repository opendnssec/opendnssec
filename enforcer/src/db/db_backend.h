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

struct db_backend_handle;
struct db_backend;
typedef struct db_backend_handle db_backend_handle_t;
typedef struct db_backend db_backend_t;

#include "db_configuration.h"
#include "db_result.h"
#include "db_object.h"
#include "db_join.h"
#include "db_clause.h"
#include "db_value.h"

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
 * \param[in] configuration_list a db_configuration_list_t pointer.
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

typedef int (*db_backend_handle_last_id_t)(void* data, int *last_id);

/**
 * Function pointer for creating a object in a database backend. The backend
 * handle specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \param[in] value_set a db_value_set_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_create_t)(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set);

/**
 * Function pointer for reading objects from database backend. The backend
 * handle specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] join_list a db_join_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a db_result_list_t pointer or NULL on error or if no objects where
 * read.
 */
typedef db_result_list_t* (*db_backend_handle_read_t)(void* data, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list);

/**
 * Function pointer for updating objects in a database backend. The backend
 * handle specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \param[in] value_set a db_value_set_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_update_t)(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list);

/**
 * Function pointer for deleting objects from database backend. The backend
 * handle specific data is supplied in `data`.
 * \param[in] data a void pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_delete_t)(void* data, const db_object_t* object, const db_clause_list_t* clause_list);

/**
 * Function pointer for counting objects from database backend. The backend
 * handle specific data is supplied in `data`. Returns the size in `size`.
 * \param[in] data a void pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] join_list a db_join_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \param[out] count a size_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
typedef int (*db_backend_handle_count_t)(void* data, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list, size_t* count);

/**
 * Function pointer for freeing the backend handle specific data in `data`.
 * \param[in] data a void pointer.
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
    db_backend_handle_last_id_t last_id_function;
    db_backend_handle_create_t create_function;
    db_backend_handle_read_t read_function;
    db_backend_handle_update_t update_function;
    db_backend_handle_delete_t delete_function;
    db_backend_handle_count_t count_function;
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
 * Connect to the database of a database backend, the connection specific
 * configuration is given by `configuration_list`.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] configuration_list a db_configuration_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_connect(const db_backend_handle_t* backend_handle, const db_configuration_list_t* configuration_list);

/**
 * Create an object in the database. The `object` refer to the database object
 * begin created, the `object_field_list` describes the fields that should be
 * set in the object and the `value_set` has the values for each field.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \param[in] value_set a db_value_set_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_create(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set);

/**
 * Read an object or objects from the database.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] join_list a db_join_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a db_result_list_t pointer or NULL on error or if no objects where
 * read.
 */
db_result_list_t* db_backend_handle_read(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list);

/**
 * Update an object or objects in the database.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \param[in] value_set a db_value_set_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_update(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list);

/**
 * Delete an object or objects from the database.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_delete(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_clause_list_t* clause_list);

/**
 * Count objects from the database. Return the count in `count`.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] join_list a db_join_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \param[out] count a size_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_count(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list, size_t* count);

/**
 * Set the initialize function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] initialize_function a db_backend_handle_initialize_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_initialize(db_backend_handle_t* backend_handle, db_backend_handle_initialize_t initialize_function);

/**
 * Set the shutdown function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] shutdown_function a db_backend_handle_shutdown_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_shutdown(db_backend_handle_t* backend_handle, db_backend_handle_shutdown_t shutdown_function);

/**
 * Set the connect function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] connect_function a db_backend_handle_connect_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_connect(db_backend_handle_t* backend_handle, db_backend_handle_connect_t connect_function);

/**
 * Set the disconnect function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] disconnect_function a db_backend_handle_disconnect_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_disconnect(db_backend_handle_t* backend_handle, db_backend_handle_disconnect_t disconnect_function);

int db_backend_handle_set_last_id(db_backend_handle_t* backend_handle, db_backend_handle_last_id_t last_id_function);

/**
 * Set the create function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] create_function a db_backend_handle_create_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_create(db_backend_handle_t* backend_handle, db_backend_handle_create_t create_function);

/**
 * Set the read function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] read_function a db_backend_handle_read_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_read(db_backend_handle_t* backend_handle, db_backend_handle_read_t read_function);

/**
 * Set the update function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] update_function a db_backend_handle_update_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_update(db_backend_handle_t* backend_handle, db_backend_handle_update_t update_function);

/**
 * Set the delete function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] delete_function a db_backend_handle_delete_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_delete(db_backend_handle_t* backend_handle, db_backend_handle_delete_t delete_function);

/**
 * Set the count function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] count_function a db_backend_handle_count_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_count(db_backend_handle_t* backend_handle, db_backend_handle_count_t count_function);

/**
 * Set the free function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] free_function a db_backend_handle_free_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_free(db_backend_handle_t* backend_handle, db_backend_handle_free_t free_function);

/**
 * Set the transaction begin function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] transaction_begin_function a db_backend_handle_transaction_begin_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_transaction_begin(db_backend_handle_t* backend_handle, db_backend_handle_transaction_begin_t transaction_begin_function);

/**
 * Set the transaction commit function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] transaction_commit_function a db_backend_handle_transaction_commit_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_transaction_commit(db_backend_handle_t* backend_handle, db_backend_handle_transaction_commit_t transaction_commit_function);

/**
 * Set the transaction rollback function of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] transaction_rollback_function a db_backend_handle_transaction_rollback_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_transaction_rollback(db_backend_handle_t* backend_handle, db_backend_handle_transaction_rollback_t transaction_rollback_function);

/**
 * Set the backend specific data of a database backend handle.
 * \param[in] backend_handle a db_backend_handle_t pointer.
 * \param[in] data a void pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_handle_set_data(db_backend_handle_t* backend_handle, void* data);

/**
 * A database backend.
 */
struct db_backend {
    db_backend_t* next;
    char* name;
    db_backend_handle_t* handle;
};

/**
 * Create a new database backend.
 * \return a db_backend_t pointer or NULL on error.
 */
db_backend_t* db_backend_new(void);

/**
 * Delete a database backend.
 * \param[in] backend a db_backend_t pointer.
 */
void db_backend_free(db_backend_t* backend);

/**
 * Get the database backend handle of a database backend.
 * \param[in] backend a db_backend_t pointer.
 * \return a db_backend_handle_t pointer or NULL on error or if no database
 * backend handle has been set.
 */
const db_backend_handle_t* db_backend_handle(const db_backend_t* backend);

/**
 * Set the name of a database backend.
 * \param[in] backend a db_backend_t pointer.
 * \param[in] name a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_set_name(db_backend_t* backend, const char* name);

/**
 * Det the database backend handle of a database backend, this takes over the
 * ownership of the database backend handle.
 * \param[in] backend a db_backend_t pointer.
 * \param[in] handle a db_backend_handle_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_set_handle(db_backend_t* backend, db_backend_handle_t* handle);

/**
 * Initiate the backend of a database backend.
 * \param[in] backend a db_backend_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_initialize(const db_backend_t* backend);

/**
 * Connect to the database of a database backend, the connection specific
 * configuration is given by `configuration_list`.
 * \param[in] backend a db_backend_t pointer.
 * \param[in] configuration_list a db_configuration_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_connect(const db_backend_t* backend, const db_configuration_list_t* configuration_list);

int db_backend_last_id(const db_backend_t* backend, int *last_id);

/**
 * Create an object in the database. The `object` refer to the database object
 * begin created, the `object_field_list` describes the fields that should be
 * set in the object and the `value_set` has the values for each field.
 * \param[in] backend a db_backend_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \param[in] value_set a db_value_set_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_create(const db_backend_t* backend, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set);

/**
 * Read an object or objects from the database.
 * \param[in] backend a db_backend_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] join_list a db_join_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a db_result_list_t pointer or NULL on error or if no objects where
 * read.
 */
db_result_list_t* db_backend_read(const db_backend_t* backend, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list);

/**
 * Update an object or objects in the database.
 * \param[in] backend a db_backend_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] object_field_list a db_object_field_list_t pointer.
 * \param[in] value_set a db_value_set_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_update(const db_backend_t* backend, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list);

/**
 * Delete an object or objects from the database.
 * \param[in] backend a db_backend_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_delete(const db_backend_t* backend, const db_object_t* object, const db_clause_list_t* clause_list);

/**
 * Count objects from the database. Return the count in `count`.
 * \param[in] backend a db_backend_t pointer.
 * \param[in] object a db_object_t pointer.
 * \param[in] join_list a db_join_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \param[out] count a size_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_backend_count(const db_backend_t* backend, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list, size_t* count);

/**
 * Get a new database backend by the name supplied in `name`.
 * \param[in] name a character pointer.
 * \return a db_backend_t pointer or NULL on error or if the database backend
 * does not exist.
 */
db_backend_t* db_backend_factory_get_backend(const char* name);

#endif
