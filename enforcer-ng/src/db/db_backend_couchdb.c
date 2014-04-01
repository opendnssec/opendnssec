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

#include "db_backend_couchdb.h"
#include "db_error.h"

#include "mm.h"

int db_backend_couchdb_transaction_rollback(void*);

static int __couchdb_initialized = 0;

typedef struct db_backend_couchdb {
} db_backend_couchdb_t;

static mm_alloc_t __couchdb_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_backend_couchdb_t));

typedef struct db_backend_couchdb_query {
    db_backend_couchdb_t* backend_couchdb;
    int fields;
    const db_object_t* object;
} db_backend_couchdb_query_t;

static mm_alloc_t __couchdb_query_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_backend_couchdb_query_t));

int db_backend_couchdb_initialize(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }

    if (!__couchdb_initialized) {
        __couchdb_initialized = 1;
    }
    return DB_OK;
}

int db_backend_couchdb_shutdown(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }

    if (__couchdb_initialized) {
        __couchdb_initialized = 0;
    }
    return DB_OK;
}

int db_backend_couchdb_connect(void* data, const db_configuration_list_t* configuration_list) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;
    const db_configuration_t* file;
    int ret;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }
    if (!configuration_list) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int db_backend_couchdb_disconnect(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;
    int ret;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int db_backend_couchdb_create(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
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

    return DB_OK;
}

db_result_list_t* db_backend_couchdb_read(void* data, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return NULL;
    }
    if (!backend_couchdb) {
        return NULL;
    }
    if (!object) {
        return NULL;
    }

    return NULL;
}

int db_backend_couchdb_update(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
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

    return DB_OK;
}

int db_backend_couchdb_delete(void* data, const db_object_t* object, const db_clause_list_t* clause_list) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

void db_backend_couchdb_free(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (backend_couchdb) {
        mm_alloc_delete(&__couchdb_alloc, backend_couchdb);
    }
}

int db_backend_couchdb_transaction_begin(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int db_backend_couchdb_transaction_commit(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int db_backend_couchdb_transaction_rollback(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

db_backend_handle_t* db_backend_couchdb_new_handle(void) {
    db_backend_handle_t* backend_handle = NULL;
    db_backend_couchdb_t* backend_couchdb =
        (db_backend_couchdb_t*)mm_alloc_new0(&__couchdb_alloc);

    if (backend_couchdb && (backend_handle = db_backend_handle_new())) {
        if (db_backend_handle_set_data(backend_handle, (void*)backend_couchdb)
            || db_backend_handle_set_initialize(backend_handle, db_backend_couchdb_initialize)
            || db_backend_handle_set_shutdown(backend_handle, db_backend_couchdb_shutdown)
            || db_backend_handle_set_connect(backend_handle, db_backend_couchdb_connect)
            || db_backend_handle_set_disconnect(backend_handle, db_backend_couchdb_disconnect)
            || db_backend_handle_set_create(backend_handle, db_backend_couchdb_create)
            || db_backend_handle_set_read(backend_handle, db_backend_couchdb_read)
            || db_backend_handle_set_update(backend_handle, db_backend_couchdb_update)
            || db_backend_handle_set_delete(backend_handle, db_backend_couchdb_delete)
            || db_backend_handle_set_free(backend_handle, db_backend_couchdb_free)
            || db_backend_handle_set_transaction_begin(backend_handle, db_backend_couchdb_transaction_begin)
            || db_backend_handle_set_transaction_commit(backend_handle, db_backend_couchdb_transaction_commit)
            || db_backend_handle_set_transaction_rollback(backend_handle, db_backend_couchdb_transaction_rollback))
        {
            db_backend_handle_free(backend_handle);
            mm_alloc_delete(&__couchdb_alloc, backend_couchdb);
            return NULL;
        }
    }
    return backend_handle;
}
