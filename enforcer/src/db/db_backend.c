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

#include "db_backend.h"
#if defined(ENFORCER_DATABASE_SQLITE3)
#include "db_backend_sqlite.h"
#endif
#include "db_backend_mysql.h"
#include "db_error.h"
#include "database_version.h"
#include "hsm_key.h"


#include <stdlib.h>
#include <string.h>

/* DB BACKEND HANDLE */



db_backend_handle_t* db_backend_handle_new(void) {
    db_backend_handle_t* backend_handle =
        (db_backend_handle_t*)calloc(1, sizeof(db_backend_handle_t));

    return backend_handle;
}

void db_backend_handle_free(db_backend_handle_t* backend_handle) {
    if (backend_handle) {
        if (backend_handle->disconnect_function) {
            (void)(*backend_handle->disconnect_function)(backend_handle->data);
        }
        if (backend_handle->free_function) {
            (*backend_handle->free_function)(backend_handle->data);
        }
        free(backend_handle);
    }
}

int db_backend_handle_initialize(const db_backend_handle_t* backend_handle) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->initialize_function) {
        return DB_ERROR_UNKNOWN;
    }

    return backend_handle->initialize_function((void*)backend_handle->data);
}

int db_backend_handle_shutdown(const db_backend_handle_t* backend_handle) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->shutdown_function) {
        return DB_ERROR_UNKNOWN;
    }

    return backend_handle->shutdown_function((void*)backend_handle->data);
}

int db_backend_handle_connect(const db_backend_handle_t* backend_handle, const db_configuration_list_t* configuration_list) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!configuration_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->connect_function) {
        return DB_ERROR_UNKNOWN;
    }

    return backend_handle->connect_function((void*)backend_handle->data, configuration_list);
}

int db_backend_handle_disconnect(const db_backend_handle_t* backend_handle) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->disconnect_function) {
        return DB_ERROR_UNKNOWN;
    }

    return backend_handle->disconnect_function((void*)backend_handle->data);
}

int db_backend_handle_create(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object_field_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value_set) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->create_function) {
        return DB_ERROR_UNKNOWN;
    }

    return backend_handle->create_function((void*)backend_handle->data, object, object_field_list, value_set);
}

db_result_list_t* db_backend_handle_read(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
    if (!backend_handle) {
        return NULL;
    }
    if (!object) {
        return NULL;
    }
    if (!backend_handle->read_function) {
        return NULL;
    }

    return backend_handle->read_function((void*)backend_handle->data, object, join_list, clause_list);
}

int db_backend_handle_update(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object_field_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value_set) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->update_function) {
        return DB_ERROR_UNKNOWN;
    }

    return backend_handle->update_function((void*)backend_handle->data, object, object_field_list, value_set, clause_list);
}

int db_backend_handle_delete(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_clause_list_t* clause_list) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->delete_function) {
        return DB_ERROR_UNKNOWN;
    }

    return backend_handle->delete_function((void*)backend_handle->data, object, clause_list);
}

int db_backend_handle_count(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list, size_t* count) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!count) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->count_function) {
        return DB_ERROR_UNKNOWN;
    }

    return backend_handle->count_function((void*)backend_handle->data, object, join_list, clause_list, count);
}

int db_backend_handle_transaction_begin(const db_backend_handle_t* backend_handle) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->transaction_begin_function) {
        return DB_ERROR_UNKNOWN;
    }

    return backend_handle->transaction_begin_function((void*)backend_handle->data);
}

int db_backend_handle_transaction_commit(const db_backend_handle_t* backend_handle) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->transaction_commit_function) {
        return DB_ERROR_UNKNOWN;
    }

    return backend_handle->transaction_commit_function((void*)backend_handle->data);
}

int db_backend_handle_transaction_rollback(const db_backend_handle_t* backend_handle) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->transaction_rollback_function) {
        return DB_ERROR_UNKNOWN;
    }

    return backend_handle->transaction_rollback_function((void*)backend_handle->data);
}

const void* db_backend_handle_data(const db_backend_handle_t* backend_handle) {
    if (!backend_handle) {
        return NULL;
    }

    return backend_handle->data;
}

int db_backend_handle_set_initialize(db_backend_handle_t* backend_handle, db_backend_handle_initialize_t initialize_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->initialize_function = initialize_function;
    return DB_OK;
}

int db_backend_handle_set_shutdown(db_backend_handle_t* backend_handle, db_backend_handle_shutdown_t shutdown_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->shutdown_function = shutdown_function;
    return DB_OK;
}

int db_backend_handle_set_connect(db_backend_handle_t* backend_handle, db_backend_handle_connect_t connect_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->connect_function = connect_function;
    return DB_OK;
}

int db_backend_handle_set_disconnect(db_backend_handle_t* backend_handle, db_backend_handle_disconnect_t disconnect_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->disconnect_function = disconnect_function;
    return DB_OK;
}

int db_backend_handle_set_create(db_backend_handle_t* backend_handle, db_backend_handle_create_t create_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->create_function = create_function;
    return DB_OK;
}

int db_backend_handle_set_read(db_backend_handle_t* backend_handle, db_backend_handle_read_t read_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->read_function = read_function;
    return DB_OK;
}

int db_backend_handle_set_update(db_backend_handle_t* backend_handle, db_backend_handle_update_t update_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->update_function = update_function;
    return DB_OK;
}

int db_backend_handle_set_delete(db_backend_handle_t* backend_handle, db_backend_handle_delete_t delete_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->delete_function = delete_function;
    return DB_OK;
}

int db_backend_handle_set_count(db_backend_handle_t* backend_handle, db_backend_handle_count_t count_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->count_function = count_function;
    return DB_OK;
}

int db_backend_handle_set_free(db_backend_handle_t* backend_handle, db_backend_handle_free_t free_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->free_function = free_function;
    return DB_OK;
}

int db_backend_handle_set_transaction_begin(db_backend_handle_t* backend_handle, db_backend_handle_transaction_begin_t transaction_begin_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->transaction_begin_function = transaction_begin_function;
    return DB_OK;
}

int db_backend_handle_set_transaction_commit(db_backend_handle_t* backend_handle, db_backend_handle_transaction_commit_t transaction_commit_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->transaction_commit_function = transaction_commit_function;
    return DB_OK;
}

int db_backend_handle_set_transaction_rollback(db_backend_handle_t* backend_handle, db_backend_handle_transaction_rollback_t transaction_rollback_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->transaction_rollback_function = transaction_rollback_function;
    return DB_OK;
}

int db_backend_handle_set_data(db_backend_handle_t* backend_handle, void* data) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (backend_handle->data) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->data = data;
    return DB_OK;
}

int db_backend_handle_not_empty(const db_backend_handle_t* backend_handle) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->initialize_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->shutdown_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->connect_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->disconnect_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->create_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->read_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->update_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->count_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->delete_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->free_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->transaction_begin_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->transaction_commit_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->transaction_rollback_function) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

/* DB BACKEND */



db_backend_t* db_backend_new(void) {
    db_backend_t* backend =
        (db_backend_t*)calloc(1, sizeof(db_backend_t));

    return backend;
}

void db_backend_free(db_backend_t* backend) {
    if (backend) {
        if (backend->handle) {
            db_backend_handle_free(backend->handle);
        }
        if (backend->name) {
            free(backend->name);
        }
        free(backend);
    }
}

const char* db_backend_name(const db_backend_t* backend) {
    if (!backend) {
        return NULL;
    }

    return backend->name;
}

const db_backend_handle_t* db_backend_handle(const db_backend_t* backend) {
    if (!backend) {
        return NULL;
    }

    return backend->handle;
}

int db_backend_set_name(db_backend_t* backend, const char* name) {
    char* new_name;

    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_name = strdup(name))) {
        return DB_ERROR_UNKNOWN;
    }

    if (backend->name) {
        free(backend->name);
    }
    backend->name = new_name;
    return DB_OK;
}

int db_backend_set_handle(db_backend_t* backend, db_backend_handle_t* handle) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend->handle = handle;
    return DB_OK;
}

int db_backend_not_empty(const db_backend_t* backend) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->name) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

int db_backend_initialize(const db_backend_t* backend) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_initialize(backend->handle);
}

int db_backend_shutdown(const db_backend_t* backend) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_shutdown(backend->handle);
}

int db_backend_connect(const db_backend_t* backend, const db_configuration_list_t* configuration_list) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!configuration_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_connect(backend->handle, configuration_list);
}

int db_backend_disconnect(const db_backend_t* backend) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_disconnect(backend->handle);
}

int db_backend_create(const db_backend_t* backend, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object_field_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value_set) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_create(backend->handle, object, object_field_list, value_set);
}

db_result_list_t* db_backend_read(const db_backend_t* backend, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
    if (!backend) {
        return NULL;
    }
    if (!object) {
        return NULL;
    }
    if (!backend->handle) {
        return NULL;
    }

    return db_backend_handle_read(backend->handle, object, join_list, clause_list);
}

int db_backend_update(const db_backend_t* backend, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object_field_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value_set) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_update(backend->handle, object, object_field_list, value_set, clause_list);
}

int db_backend_delete(const db_backend_t* backend, const db_object_t* object, const db_clause_list_t* clause_list) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_delete(backend->handle, object, clause_list);
}

int db_backend_count(const db_backend_t* backend, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list, size_t* count) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!count) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_count(backend->handle, object, join_list, clause_list, count);
}

int db_backend_transaction_begin(const db_backend_t* backend) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_transaction_begin(backend->handle);
}

int db_backend_transaction_commit(const db_backend_t* backend) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_transaction_commit(backend->handle);
}

int db_backend_transaction_rollback(const db_backend_t* backend) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_transaction_rollback(backend->handle);
}

/* DB BACKEND FACTORY */

db_backend_t* db_backend_factory_get_backend(const char* name) {
    db_backend_t* backend = NULL;

    if (!name) {
        return NULL;
    }

#if defined(ENFORCER_DATABASE_SQLITE3)
    if (!strcmp(name, "sqlite")) {
        if (!(backend = db_backend_new())
            || db_backend_set_name(backend, "sqlite")
            || db_backend_set_handle(backend, db_backend_sqlite_new_handle())
            || db_backend_initialize(backend))
        {
            db_backend_free(backend);
            return NULL;
        }
        return backend;
    }
#endif
#if defined(ENFORCER_DATABASE_MYSQL)
    if (!strcmp(name, "mysql")) {
        if (!(backend = db_backend_new())
            || db_backend_set_name(backend, "mysql")
            || db_backend_set_handle(backend, db_backend_mysql_new_handle())
            || db_backend_initialize(backend))
        {
            db_backend_free(backend);
            return NULL;
        }
        return backend;
    }
#endif

    return backend;
}

int db_backend_factory_shutdown(void) {
    /* TODO: Implement support for shutting down backends at exit/stop */
    return 1;
}

/* DB BACKEND META DATA */



db_backend_meta_data_t* db_backend_meta_data_new(void) {
    db_backend_meta_data_t* backend_meta_data =
        (db_backend_meta_data_t*)calloc(1, sizeof(db_backend_meta_data_t));

    return backend_meta_data;
}

/* TODO: unit test */
db_backend_meta_data_t* db_backend_meta_data_new_copy(const db_backend_meta_data_t* from_backend_meta_data) {
    db_backend_meta_data_t* backend_meta_data;

    if (!from_backend_meta_data) {
        return NULL;
    }

    backend_meta_data = (db_backend_meta_data_t*)calloc(1, sizeof(db_backend_meta_data_t));
    if (backend_meta_data) {
        if (db_backend_meta_data_copy(backend_meta_data, from_backend_meta_data)) {
            db_backend_meta_data_free(backend_meta_data);
            return NULL;
        }
    }

    return backend_meta_data;
}

void db_backend_meta_data_free(db_backend_meta_data_t* backend_meta_data) {
    if (backend_meta_data) {
        if (backend_meta_data->name) {
            free(backend_meta_data->name);
        }
        if (backend_meta_data->value) {
            db_value_free(backend_meta_data->value);
        }
        free(backend_meta_data);
    }
}

int db_backend_meta_data_copy(db_backend_meta_data_t* backend_meta_data, const db_backend_meta_data_t* from_backend_meta_data) {
    if (!backend_meta_data) {
        return DB_ERROR_UNKNOWN;
    }
    if (!from_backend_meta_data) {
        return DB_ERROR_UNKNOWN;
    }

    if (backend_meta_data->name) {
        free(backend_meta_data->name);
        backend_meta_data->name = NULL;
    }
    if (from_backend_meta_data->name) {
        if (!(backend_meta_data->name = strdup(from_backend_meta_data->name))) {
            return DB_ERROR_UNKNOWN;
        }
    }

    if (from_backend_meta_data->value) {
        if (backend_meta_data->value) {
            db_value_reset(backend_meta_data->value);
        }
        else {
            if (!(backend_meta_data->value = db_value_new())) {
                return DB_ERROR_UNKNOWN;
            }
        }
        if (db_value_copy(backend_meta_data->value, from_backend_meta_data->value)) {
            return DB_ERROR_UNKNOWN;
        }
    }
    else {
        if (backend_meta_data->value) {
            db_value_free(backend_meta_data->value);
            backend_meta_data->value = NULL;
        }
    }

    return DB_OK;
}

const char* db_backend_meta_data_name(const db_backend_meta_data_t* backend_meta_data) {
    if (!backend_meta_data) {
        return NULL;
    }

    return backend_meta_data->name;
}

const db_value_t* db_backend_meta_data_value(const db_backend_meta_data_t* backend_meta_data) {
    if (!backend_meta_data) {
        return NULL;
    }

    return backend_meta_data->value;
}

int db_backend_meta_data_set_name(db_backend_meta_data_t* backend_meta_data, const char* name) {
    char* new_name;

    if (!backend_meta_data) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_name = strdup(name))) {
        return DB_ERROR_UNKNOWN;
    }

    if (backend_meta_data->name) {
        free(backend_meta_data->name);
    }
    backend_meta_data->name = new_name;
    return DB_OK;
}

int db_backend_meta_data_set_value(db_backend_meta_data_t* backend_meta_data, db_value_t* value) {
    if (!backend_meta_data) {
        return DB_ERROR_UNKNOWN;
    }
    if (backend_meta_data->value) {
        return DB_ERROR_UNKNOWN;
    }

    backend_meta_data->value = value;
    return DB_OK;
}

int db_backend_meta_data_not_empty(const db_backend_meta_data_t* backend_meta_data) {
    if (!backend_meta_data) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_meta_data->name) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_meta_data->value) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

/* DB BACKEND META DATA LIST */



db_backend_meta_data_list_t* db_backend_meta_data_list_new(void) {
    db_backend_meta_data_list_t* backend_meta_data_list =
        (db_backend_meta_data_list_t*)calloc(1, sizeof(db_backend_meta_data_list_t));

    return backend_meta_data_list;
}

/* TODO: unit test */
db_backend_meta_data_list_t* db_backend_meta_data_list_new_copy(const db_backend_meta_data_list_t* from_backend_meta_data_list) {
    db_backend_meta_data_list_t* backend_meta_data_list;

    if (!from_backend_meta_data_list) {
        return NULL;
    }

    backend_meta_data_list = (db_backend_meta_data_list_t*)calloc(1, sizeof(db_backend_meta_data_list_t));
    if (backend_meta_data_list) {
        if (db_backend_meta_data_list_copy(backend_meta_data_list, from_backend_meta_data_list)) {
            db_backend_meta_data_list_free(backend_meta_data_list);
            return NULL;
        }
    }

    return backend_meta_data_list;
}

void db_backend_meta_data_list_free(db_backend_meta_data_list_t* backend_meta_data_list) {
    if (backend_meta_data_list) {
        if (backend_meta_data_list->begin) {
            db_backend_meta_data_t* this = backend_meta_data_list->begin;
            db_backend_meta_data_t* next = NULL;

            while (this) {
                next = this->next;
                db_backend_meta_data_free(this);
                this = next;
            }
        }
        free(backend_meta_data_list);
    }
}

int db_backend_meta_data_list_copy(db_backend_meta_data_list_t* backend_meta_data_list, const db_backend_meta_data_list_t* from_backend_meta_data_list) {
    const db_backend_meta_data_t* backend_meta_data;
    db_backend_meta_data_t* backend_meta_data_copy;

    if (!backend_meta_data_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!from_backend_meta_data_list) {
        return DB_ERROR_UNKNOWN;
    }

    if (backend_meta_data_list->begin) {
        db_backend_meta_data_t* this = backend_meta_data_list->begin;
        db_backend_meta_data_t* next = NULL;

        while (this) {
            next = this->next;
            db_backend_meta_data_free(this);
            this = next;
        }
    }

    backend_meta_data_list->begin = NULL;;
    backend_meta_data_list->end = NULL;

    backend_meta_data = from_backend_meta_data_list->begin;
    while (backend_meta_data) {
        if (!(backend_meta_data_copy = db_backend_meta_data_new())) {
            return DB_ERROR_UNKNOWN;
        }

        if (db_backend_meta_data_copy(backend_meta_data_copy, backend_meta_data)
            || db_backend_meta_data_list_add(backend_meta_data_list, backend_meta_data_copy))
        {
            db_backend_meta_data_free(backend_meta_data_copy);
            return DB_ERROR_UNKNOWN;
        }

        backend_meta_data = backend_meta_data->next;
    }

    return DB_OK;
}

int db_backend_meta_data_list_add(db_backend_meta_data_list_t* backend_meta_data_list, db_backend_meta_data_t* backend_meta_data) {
    if (!backend_meta_data_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_meta_data) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_backend_meta_data_not_empty(backend_meta_data)) {
        return DB_ERROR_UNKNOWN;
    }
    if (backend_meta_data->next) {
        return DB_ERROR_UNKNOWN;
    }

    if (backend_meta_data_list->begin) {
        if (!backend_meta_data_list->end) {
            return DB_ERROR_UNKNOWN;
        }
        backend_meta_data_list->end->next = backend_meta_data;
        backend_meta_data_list->end = backend_meta_data;
    }
    else {
        backend_meta_data_list->begin = backend_meta_data;
        backend_meta_data_list->end = backend_meta_data;
    }

    return DB_OK;
}

const db_backend_meta_data_t* db_backend_meta_data_list_find(const db_backend_meta_data_list_t* backend_meta_data_list, const char* name) {
    db_backend_meta_data_t* backend_meta_data;

    if (!backend_meta_data_list) {
        return NULL;
    }
    if (!name) {
        return NULL;
    }

    backend_meta_data = backend_meta_data_list->begin;
    while (backend_meta_data) {
        if (db_backend_meta_data_not_empty(backend_meta_data)) {
            return NULL;
        }
        if (!strcmp(backend_meta_data->name, name)) {
            break;
        }
        backend_meta_data = backend_meta_data->next;
    }

    return backend_meta_data;
}
