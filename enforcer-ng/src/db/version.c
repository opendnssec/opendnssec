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

#include "version.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new version object.
 * \param[in] connection a db_connection_t pointer.
 * \return a version_t pointer or NULL on error.
 */
static db_object_t* __version_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "version")
        || db_object_set_primary_key_name(object, "id")
        || !(object_field_list = db_object_field_list_new()))
    {
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

/* VERSION */

static mm_alloc_t __version_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(version_t));

version_t* version_new(const db_connection_t* connection) {
    version_t* version =
        (version_t*)mm_alloc_new0(&__version_alloc);

    if (version) {
        if (!(version->dbo = __version_new_object(connection))) {
            mm_alloc_delete(&__version_alloc, version);
            return NULL;
        }
    }

    return version;
}

void version_free(version_t* version) {
    if (version) {
        if (version->dbo) {
            db_object_free(version->dbo);
        }
        mm_alloc_delete(&__version_alloc, version);
    }
}

void version_reset(version_t* version) {
    if (version) {
        version->version = 0;
    }
}

int version_copy(version_t* version, const version_t* version_copy) {
    if (!version) {
        return DB_ERROR_UNKNOWN;
    }
    if (!version_copy) {
        return DB_ERROR_UNKNOWN;
    }

    version->version = version_copy->version;
    return DB_OK;
}

int version_from_result(version_t* version, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!version) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 1
        || db_value_to_uint32(db_value_set_at(value_set, 0), &(version->version)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

unsigned int version_version(const version_t* version) {
    if (!version) {
        return 0;
    }

    return version->version;
}

int version_set_version(version_t* version, unsigned int version) {
    if (!version) {
        return DB_ERROR_UNKNOWN;
    }

    version->version = version;

    return DB_OK;
}

int version_create(version_t* version) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!version) {
        return DB_ERROR_UNKNOWN;
    }
    if (!version->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "version")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(0))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(version->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int version_update(version_t* version) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!version) {
        return DB_ERROR_UNKNOWN;
    }
    if (!version->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "version")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(1))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(version->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int version_delete(version_t* version) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!version) {
        return DB_ERROR_UNKNOWN;
    }
    if (!version->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(version->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* VERSION LIST */

static mm_alloc_t __version_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(version_list_t));

version_list_t* version_list_new(const db_connection_t* connection) {
    version_list_t* version_list =
        (version_list_t*)mm_alloc_new0(&__version_list_alloc);

    if (version_list) {
        if (!(version_list->dbo = __version_new_object(connection))) {
            mm_alloc_delete(&__version_list_alloc, version_list);
            return NULL;
        }
    }

    return version_list;
}

void version_list_free(version_list_t* version_list) {
    if (version_list) {
        if (version_list->dbo) {
            db_object_free(version_list->dbo);
        }
        if (version_list->result_list) {
            db_result_list_free(version_list->result_list);
        }
        if (version_list->version) {
            version_free(version_list->version);
        }
        mm_alloc_delete(&__version_list_alloc, version_list);
    }
}

int version_list_get(version_list_t* version_list) {
    if (!version_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!version_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (version_list->result_list) {
        db_result_list_free(version_list->result_list);
    }
    if (!(version_list->result_list = db_object_read(version_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const version_t* version_list_begin(version_list_t* version_list) {
    const db_result_t* result;

    if (!version_list) {
        return NULL;
    }
    if (!version_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(version_list->result_list))) {
        return NULL;
    }
    if (!version_list->version) {
        if (!(version_list->version = version_new(db_object_connection(version_list->dbo)))) {
            return NULL;
        }
    }
    if (version_from_result(version_list->version, result)) {
        return NULL;
    }
    return version_list->version;
}

const version_t* version_list_next(version_list_t* version_list) {
    const db_result_t* result;

    if (!version_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(version_list->result_list))) {
        return NULL;
    }
    if (!version_list->version) {
        if (!(version_list->version = version_new(db_object_connection(version_list->dbo)))) {
            return NULL;
        }
    }
    if (version_from_result(version_list->version, result)) {
        return NULL;
    }
    return version_list->version;
}
