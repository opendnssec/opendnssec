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

#include <string.h>

#include "db_value.h"
#include "db_error.h"
#include "log.h"

/* DB VALUE */

db_value_t* db_value_new()
{
    db_value_t* value =
        (db_value_t*)calloc(1, sizeof(db_value_t));

    if (value) {
        value->type = DB_TYPE_EMPTY;
    }

    return value;
}

void db_value_free(db_value_t* value)
{
    if (value) free(value->text);
    free(value);
}

void db_value_reset(db_value_t* value)
{
    ods_log_assert(value);

    value->type = DB_TYPE_EMPTY;
    value->primary_key = 0;
    free(value->text);
    value->text = NULL;
    value->int32 = 0;
    value->uint32 = 0;
    value->int64 = 0;
    value->uint64 = 0;
    value->enum_value = 0;
    value->enum_text = NULL;
}

int db_value_copy(db_value_t* value, const db_value_t* from_value)
{
    ods_log_assert(value);
    ods_log_assert(value->type == DB_TYPE_EMPTY);
    ods_log_assert(from_value);
    ods_log_assert(from_value->type != DB_TYPE_EMPTY);

    memcpy(value, from_value, sizeof(db_value_t));
    if (from_value->text) {
        value->text = strdup(from_value->text);
        if (!value->text) {
            db_value_reset(value);
            return DB_ERROR_UNKNOWN;
        }
    }
    return DB_OK;
}

int db_value_cmp(const db_value_t* value_a, const db_value_t* value_b)
{
    ods_log_assert(value_a);
    ods_log_assert(value_b);
    
    if (value_a->type == DB_TYPE_EMPTY && value_b->type != DB_TYPE_EMPTY)
        return -1;
    else if (value_a->type == DB_TYPE_EMPTY && value_b->type == DB_TYPE_EMPTY)
        return 0;
    else if (value_a->type != DB_TYPE_EMPTY && value_b->type == DB_TYPE_EMPTY)
        return 1;

    switch (value_a->type) {
    case DB_TYPE_INT32:
        if (value_b->type == DB_TYPE_INT32) {
            if (value_a->int32 < value_b->int32) return -1;
            if (value_a->int32 > value_b->int32) return 1;
            return 0;
        } else if (value_b->type == DB_TYPE_INT64) {
            if (value_a->int32 < value_b->int64) return -1;
            if (value_a->int32 > value_b->int64) return 1;
            return 0;
        }
        break;
    case DB_TYPE_UINT32:
        if (value_b->type == DB_TYPE_UINT32) {
            if (value_a->uint32 < value_b->uint32) return -1;
            if (value_a->uint32 > value_b->uint32) return 1;
            return 0;
        } else if (value_b->type == DB_TYPE_UINT64) {
            if (value_a->uint32 < value_b->uint64) return -1;
            if (value_a->uint32 > value_b->uint64) return 1;
            return 0;
        }
        break;
    case DB_TYPE_INT64:
        if (value_b->type == DB_TYPE_INT64) {
            if (value_a->int64 < value_b->int64) return -1;
            if (value_a->int64 > value_b->int64) return 1;
            return 0;
        } else if (value_b->type == DB_TYPE_INT32) {
            if (value_a->int64 < value_b->int32) return -1;
            if (value_a->int64 > value_b->int32) return 1;
            return 0;
        }
        break;
    case DB_TYPE_UINT64:
        if (value_b->type == DB_TYPE_UINT64) {
            if (value_a->uint64 < value_b->uint64) return -1;
            if (value_a->uint64 > value_b->uint64) return 1;
            return 0;
        } else if (value_b->type == DB_TYPE_UINT32) {
            if (value_a->uint64 < value_b->uint32) return -1;
            if (value_a->uint64 > value_b->uint32) return 1;
            return 0;
        }
        break;
    case DB_TYPE_TEXT:
        ods_log_assert(value_b->type == DB_TYPE_TEXT);
        return strcmp(value_a->text, value_b->text);
    case DB_TYPE_ENUM:
        ods_log_assert(value_b->type == DB_TYPE_ENUM);
        /* TODO: Document that enum can only really be checked if eq */
        if (value_a->enum_value < value_b->enum_value) return -1;
        else if (value_a->enum_value > value_b->enum_value) return 1;
        return 0;
    default:
        break; /* not allowed to compare any other type */
    }
    ods_log_assert(0);
}

db_type_t db_value_type(const db_value_t* value)
{
    ods_log_assert(value);
    return value->type;
}

int db_value_empty(const db_value_t* value)
{
    ods_log_assert(value);
    return value->type == DB_TYPE_EMPTY;
}

int db_value_to_int32(const db_value_t* value, db_type_int32_t* to_int32) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (!to_int32) {
        return DB_ERROR_UNKNOWN;
    }
    if (value->type != DB_TYPE_INT32) {
        return DB_ERROR_UNKNOWN;
    }

    *to_int32 = value->int32;
    return DB_OK;
}

int db_value_to_uint32(const db_value_t* value, db_type_uint32_t* to_uint32) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (!to_uint32) {
        return DB_ERROR_UNKNOWN;
    }
    if (value->type != DB_TYPE_UINT32) {
        return DB_ERROR_UNKNOWN;
    }

    *to_uint32 = value->uint32;
    return DB_OK;
}

int db_value_to_int64(const db_value_t* value, db_type_int64_t* to_int64) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (!to_int64) {
        return DB_ERROR_UNKNOWN;
    }
    if (value->type != DB_TYPE_INT64) {
        return DB_ERROR_UNKNOWN;
    }

    *to_int64 = value->int64;
    return DB_OK;
}

int db_value_to_uint64(const db_value_t* value, db_type_uint64_t* to_uint64) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (!to_uint64) {
        return DB_ERROR_UNKNOWN;
    }
    if (value->type != DB_TYPE_UINT64) {
        return DB_ERROR_UNKNOWN;
    }

    *to_uint64 = value->uint64;
    return DB_OK;
}

int db_value_to_text(const db_value_t* value, char** to_text) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (!to_text) {
        return DB_ERROR_UNKNOWN;
    }
    if (*to_text) {
        return DB_ERROR_UNKNOWN;
    }
    if (value->type != DB_TYPE_TEXT) {
        return DB_ERROR_UNKNOWN;
    }

    *to_text = strdup(value->text);
    if (!*to_text) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

int db_value_to_enum_value(const db_value_t* value, int* to_int, const db_enum_t* enum_set) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (!to_int) {
        return DB_ERROR_UNKNOWN;
    }
    if (!enum_set) {
        return DB_ERROR_UNKNOWN;
    }

    if (value->type == DB_TYPE_ENUM) {
        while (enum_set->text) {
            if (enum_set->value == value->enum_value) {
                *to_int = enum_set->value;
                return DB_OK;
            }
            enum_set++;
        }
    }
    else if (value->type == DB_TYPE_TEXT) {
        while (enum_set->text) {
            if (!strcmp(enum_set->text, value->text)) {
                *to_int = enum_set->value;
                return DB_OK;
            }
            enum_set++;
        }
    }
    else if (value->type == DB_TYPE_INT32) {
        while (enum_set->text) {
            if (enum_set->value == value->int32) {
                *to_int = enum_set->value;
                return DB_OK;
            }
            enum_set++;
        }
    }
    return DB_ERROR_UNKNOWN;
}

int db_value_from_int32(db_value_t* value, db_type_int32_t from_int32) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (value->type != DB_TYPE_EMPTY) {
        return DB_ERROR_UNKNOWN;
    }

    value->int32 = from_int32;
    value->type = DB_TYPE_INT32;
    return DB_OK;
}

int db_value_from_uint32(db_value_t* value, db_type_uint32_t from_uint32) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (value->type != DB_TYPE_EMPTY) {
        return DB_ERROR_UNKNOWN;
    }

    value->uint32 = from_uint32;
    value->type = DB_TYPE_UINT32;
    return DB_OK;
}

int db_value_from_int64(db_value_t* value, db_type_int64_t from_int64) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (value->type != DB_TYPE_EMPTY) {
        return DB_ERROR_UNKNOWN;
    }

    value->int64 = from_int64;
    value->type = DB_TYPE_INT64;
    return DB_OK;
}

int db_value_from_uint64(db_value_t* value, db_type_uint64_t from_uint64) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (value->type != DB_TYPE_EMPTY) {
        return DB_ERROR_UNKNOWN;
    }

    value->uint64 = from_uint64;
    value->type = DB_TYPE_UINT64;
    return DB_OK;
}

int db_value_from_text(db_value_t* value, const char* from_text)
{
    ods_log_assert(from_text);
    return db_value_from_text2(value, from_text, strlen(from_text));
}

int db_value_from_text2(db_value_t* value, const char* from_text, size_t size)
{
    ods_log_assert(value);
    ods_log_assert(value->type == DB_TYPE_EMPTY);
    ods_log_assert(from_text);
    
    if (!size) {
        return DB_ERROR_UNKNOWN;
    }

    value->text = strndup(from_text, size);
    if (!value->text) {
        return DB_ERROR_UNKNOWN;
    }
    value->type = DB_TYPE_TEXT;
    return DB_OK;
}

int db_value_from_enum_value(db_value_t* value, int enum_value, const db_enum_t* enum_set)
{
    ods_log_assert(value);
    ods_log_assert(enum_set);
    
    if (value->type != DB_TYPE_EMPTY) {
        return DB_ERROR_UNKNOWN;
    }

    while (enum_set->text) {
        if (enum_set->value == enum_value) {
            value->enum_text = enum_set->text;
            value->enum_value = enum_set->value;
            value->type = DB_TYPE_ENUM;
            return DB_OK;
        }
        enum_set++;
    }
    return DB_ERROR_UNKNOWN;
}

/* DB VALUE SET */

db_value_set_t* db_value_set_new(size_t size)
{
    db_value_set_t* value_set;
    size_t i;

    if (size == 0 || size > 128) {
        return NULL;
    }
    value_set = (db_value_set_t*)calloc(1, sizeof(db_value_set_t));
    if (!value_set)
        return NULL;
    value_set->values = (db_value_t*)calloc(size, sizeof(db_value_t));
    if (!value_set->values) {
        free(value_set);
        return NULL;
    }
    value_set->size = size;
    for (i=0; i < size; i++) {
        value_set->values[i].type = DB_TYPE_EMPTY;
    }
    return value_set;
}

/* TODO: unit test */
db_value_set_t* db_value_set_new_copy(const db_value_set_t* from_value_set)
{
    db_value_set_t* value_set;
    size_t i;

    ods_log_assert(from_value_set);

    if (!from_value_set->values) {
        return NULL;
    }

    value_set = db_value_set_new(from_value_set->size);
    if (!value_set)
        return NULL;
    for (i=0; i < from_value_set->size; i++) {
        if (db_value_type(&from_value_set->values[i]) == DB_TYPE_EMPTY)
            continue;
        if (db_value_copy(&value_set->values[i], &from_value_set->values[i]) != DB_OK) {
            db_value_set_free(value_set);
            return NULL;
        }
    }
    return value_set;
}

void db_value_set_free(db_value_set_t* value_set)
{
    size_t i;
    
    if (value_set && value_set->values) {
        for (i=0; i < value_set->size; i++) {
            free(value_set->values[i].text);
        }
        free(value_set->values);
    }
    free(value_set);
}

size_t db_value_set_size(const db_value_set_t* value_set)
{
    ods_log_assert(value_set);
    return value_set->size;
}

const db_value_t* db_value_set_at(const db_value_set_t* value_set, size_t at)
{
    ods_log_assert(value_set);
    ods_log_assert(value_set->values);

    if (at >= value_set->size)
        return NULL;
    return &value_set->values[at];
}

db_value_t* db_value_set_get(db_value_set_t* value_set, size_t at)
{
    ods_log_assert(value_set);
    ods_log_assert(value_set->values);

    if (at >= value_set->size)
        return NULL;
    return &value_set->values[at];
}
