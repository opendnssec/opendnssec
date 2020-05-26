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
}

int db_backend_handle_initialize(const db_backend_handle_t* backend_handle) {
}

int db_backend_handle_connect(const db_backend_handle_t* backend_handle, const db_configuration_list_t* configuration_list) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!configuration_list) {
        return DB_ERROR_UNKNOWN;
    }
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
}

db_result_list_t* db_backend_handle_read(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
    if (!backend_handle) {
        return NULL;
    }
    if (!object) {
        return NULL;
    }
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
}

int db_backend_handle_delete(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_clause_list_t* clause_list) {
    if (!backend_handle) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
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



db_backend_t* db_backend_new(const char* name) {
    db_backend_t* backend =
        (db_backend_t*)calloc(1, sizeof(db_backend_t));
    backend->name = strdup(name);

    return backend;
}

void db_backend_free(db_backend_t* backend) {
    if (backend) {
        if (backend->handle) {
            db_backend_handle_free(backend->handle);
        }
        free(backend->name);
        free(backend);
    }
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

    db_backend_new(name);

    return backend;
}
