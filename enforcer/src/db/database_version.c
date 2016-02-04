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

#include "database_version.h"
#include "db_error.h"


#include <string.h>

/**
 * Create a new database version object.
 * \param[in] connection a db_connection_t pointer.
 * \return a database_version_t pointer or NULL on error.
 */
static db_object_t* __database_version_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "databaseVersion")
        || db_object_set_primary_key_name(object, "id")
        || !(object_field_list = db_object_field_list_new()))
    {
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "id")
        || db_object_field_set_type(object_field, DB_TYPE_PRIMARY_KEY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rev")
        || db_object_field_set_type(object_field, DB_TYPE_REVISION)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "version")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (db_object_set_object_field_list(object, object_field_list)) {
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    return object;
}

/* DATABASE VERSION */



database_version_t* database_version_new(const db_connection_t* connection) {
    database_version_t* database_version =
        (database_version_t*)calloc(1, sizeof(database_version_t));

    if (database_version) {
        if (!(database_version->dbo = __database_version_new_object(connection))) {
            free(database_version);
            return NULL;
        }
        db_value_reset(&(database_version->id));
        db_value_reset(&(database_version->rev));
    }

    return database_version;
}

void database_version_free(database_version_t* database_version) {
    if (database_version) {
        if (database_version->dbo) {
            db_object_free(database_version->dbo);
        }
        db_value_reset(&(database_version->id));
        db_value_reset(&(database_version->rev));
        free(database_version);
    }
}

int database_version_from_result(database_version_t* database_version, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!database_version) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(database_version->id));
    db_value_reset(&(database_version->rev));
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 3
        || db_value_copy(&(database_version->id), db_value_set_at(value_set, 0))
        || db_value_copy(&(database_version->rev), db_value_set_at(value_set, 1))
        || db_value_to_uint32(db_value_set_at(value_set, 2), &(database_version->version)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

unsigned int database_version_version(const database_version_t* database_version) {
    if (!database_version) {
        return 0;
    }

    return database_version->version;
}

/* DATABASE VERSION LIST */



database_version_list_t* database_version_list_new(const db_connection_t* connection) {
    database_version_list_t* database_version_list =
        (database_version_list_t*)calloc(1, sizeof(database_version_list_t));

    if (database_version_list) {
        if (!(database_version_list->dbo = __database_version_new_object(connection))) {
            free(database_version_list);
            return NULL;
        }
    }

    return database_version_list;
}

void database_version_list_free(database_version_list_t* database_version_list) {
    size_t i;

    if (database_version_list) {
        if (database_version_list->dbo) {
            db_object_free(database_version_list->dbo);
        }
        if (database_version_list->result_list) {
            db_result_list_free(database_version_list->result_list);
        }
        if (database_version_list->database_version) {
            database_version_free(database_version_list->database_version);
        }
        for (i = 0; i < database_version_list->object_list_size; i++) {
            if (database_version_list->object_list[i]) {
                database_version_free(database_version_list->object_list[i]);
            }
        }
        if (database_version_list->object_list) {
            free(database_version_list->object_list);
        }
        free(database_version_list);
    }
}

static int database_version_list_get_associated(database_version_list_t* database_version_list) {
    (void)database_version_list;
    return DB_OK;
}

int database_version_list_get(database_version_list_t* database_version_list) {
    size_t i;

    if (!database_version_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!database_version_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (database_version_list->result_list) {
        db_result_list_free(database_version_list->result_list);
    }
    if (database_version_list->object_list_size) {
        for (i = 0; i < database_version_list->object_list_size; i++) {
            if (database_version_list->object_list[i]) {
                database_version_free(database_version_list->object_list[i]);
            }
        }
        database_version_list->object_list_size = 0;
        database_version_list->object_list_first = 0;
    }
    if (database_version_list->object_list) {
        free(database_version_list->object_list);
        database_version_list->object_list = NULL;
    }
    if (!(database_version_list->result_list = db_object_read(database_version_list->dbo, NULL, NULL))
        || db_result_list_fetch_all(database_version_list->result_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    if (database_version_list->associated_fetch
        && database_version_list_get_associated(database_version_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

database_version_list_t* database_version_list_new_get(const db_connection_t* connection) {
    database_version_list_t* database_version_list;

    if (!connection) {
        return NULL;
    }

    if (!(database_version_list = database_version_list_new(connection))
        || database_version_list_get(database_version_list))
    {
        database_version_list_free(database_version_list);
        return NULL;
    }

    return database_version_list;
}

const database_version_t* database_version_list_next(database_version_list_t* database_version_list) {
    const db_result_t* result;

    if (!database_version_list) {
        return NULL;
    }

    if (database_version_list->object_store) {
        if (!database_version_list->object_list) {
            if (!database_version_list->result_list) {
                return NULL;
            }
            if (!db_result_list_size(database_version_list->result_list)) {
                return NULL;
            }
            if (!(database_version_list->object_list = (database_version_t**)calloc(db_result_list_size(database_version_list->result_list), sizeof(database_version_t*)))) {
                return NULL;
            }
            database_version_list->object_list_size = db_result_list_size(database_version_list->result_list);
            database_version_list->object_list_position = 0;
        }
        else if (database_version_list->object_list_first) {
            database_version_list->object_list_first = 0;
            database_version_list->object_list_position = 0;
        }
        else {
            database_version_list->object_list_position++;
        }
        if (database_version_list->object_list_position >= database_version_list->object_list_size) {
            return NULL;
        }
        if (!(database_version_list->object_list[database_version_list->object_list_position])) {
            if (!database_version_list->result_list) {
                return NULL;
            }
            if (!(result = db_result_list_next(database_version_list->result_list))) {
                return NULL;
            }
            if (!(database_version_list->object_list[database_version_list->object_list_position] = database_version_new(db_object_connection(database_version_list->dbo)))) {
                return NULL;
            }
            if (database_version_from_result(database_version_list->object_list[database_version_list->object_list_position], result)) {
                return NULL;
            }
        }
        return database_version_list->object_list[database_version_list->object_list_position];
    } else {
        database_version_free(database_version_list->database_version);
        database_version_list->database_version = NULL;
    }

    if (!database_version_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(database_version_list->result_list))) {
        return NULL;
    }
    if (!database_version_list->database_version) {
        if (!(database_version_list->database_version = database_version_new(db_object_connection(database_version_list->dbo)))) {
            return NULL;
        }
    }
    if (database_version_from_result(database_version_list->database_version, result)) {
        return NULL;
    }
    return database_version_list->database_version;
}
