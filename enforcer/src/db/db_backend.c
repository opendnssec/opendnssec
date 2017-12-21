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

int db_backend_handle_last_id(const db_backend_handle_t* backend_handle, int *last_id) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_handle->last_id_function) {
        return DB_ERROR_UNKNOWN;
    }

    return backend_handle->last_id_function((void*)backend_handle->data, last_id);
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

int db_backend_handle_set_last_id(db_backend_handle_t* backend_handle, db_backend_handle_last_id_t last_id_function) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }

    backend_handle->last_id_function = last_id_function;
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

int db_backend_initialize(const db_backend_t* backend) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_initialize(backend->handle);
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

int db_backend_last_id(const db_backend_t* backend, int *last_id) {
    if (!backend) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend->handle) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_handle_last_id(backend->handle, last_id);
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
