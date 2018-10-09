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

#include "db_object.h"
#include "db_error.h"


#include <stdlib.h>

/* DB OBJECT FIELD */



db_object_field_t* db_object_field_new(void) {
    db_object_field_t* object_field =
        (db_object_field_t*)calloc(1, sizeof(db_object_field_t));

    if (object_field) {
        object_field->type = DB_TYPE_EMPTY;
    }

    return object_field;
}

/* TODO: unit test */
db_object_field_t* db_object_field_new_copy(const db_object_field_t* from_object_field) {
    db_object_field_t* object_field;

    if (!from_object_field) {
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_copy(object_field, from_object_field))
    {
        db_object_field_free(object_field);
        return NULL;
    }

    return object_field;
}

void db_object_field_free(db_object_field_t* object_field) {
    if (object_field) {
        free(object_field);
    }
}

/* TODO: unit test */
int db_object_field_copy(db_object_field_t* object_field, const db_object_field_t* from_object_field) {
    if (!object_field) {
        return DB_ERROR_UNKNOWN;
    }
    if (!from_object_field) {
        return DB_ERROR_UNKNOWN;
    }
    if (object_field->next) {
        return DB_ERROR_UNKNOWN;
    }

    object_field->name = from_object_field->name;
    object_field->type = from_object_field->type;
    object_field->enum_set = from_object_field->enum_set;

    return DB_OK;
}

const char* db_object_field_name(const db_object_field_t* object_field) {
    if (!object_field) {
        return NULL;
    }

    return object_field->name;
}

db_type_t db_object_field_type(const db_object_field_t* object_field) {
    if (!object_field) {
        return DB_TYPE_EMPTY;
    }

    return object_field->type;
}

int db_object_field_set_name(db_object_field_t* object_field, const char* name) {
    if (!object_field) {
        return DB_ERROR_UNKNOWN;
    }
    if (!name) {
        return DB_ERROR_UNKNOWN;
    }

    object_field->name = name;
    return DB_OK;
}

int db_object_field_set_type(db_object_field_t* object_field, db_type_t type) {
    if (!object_field) {
        return DB_ERROR_UNKNOWN;
    }
    if (type == DB_TYPE_EMPTY) {
        return DB_ERROR_UNKNOWN;
    }

    object_field->type = type;
    return DB_OK;
}

int db_object_field_set_enum_set(db_object_field_t* object_field, const db_enum_t* enum_set) {
    if (!object_field) {
        return DB_ERROR_UNKNOWN;
    }
    if (object_field->type != DB_TYPE_ENUM) {
        return DB_ERROR_UNKNOWN;
    }

    object_field->enum_set = enum_set;
    return DB_OK;
}

int db_object_field_not_empty(const db_object_field_t* object_field) {
    if (!object_field) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object_field->name) {
        return DB_ERROR_UNKNOWN;
    }
    if (object_field->type == DB_TYPE_EMPTY) {
        return DB_ERROR_UNKNOWN;
    }
    if (object_field->type == DB_TYPE_ENUM && !object_field->enum_set) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const db_object_field_t* db_object_field_next(const db_object_field_t* object_field) {
    if (!object_field) {
        return NULL;
    }

    return object_field->next;
}

/* DB OBJECT FIELD LIST */



db_object_field_list_t* db_object_field_list_new(void) {
    db_object_field_list_t* object_field_list =
        (db_object_field_list_t*)calloc(1, sizeof(db_object_field_list_t));

    return object_field_list;
}

/* TODO: unit test */
db_object_field_list_t* db_object_field_list_new_copy(const db_object_field_list_t* from_object_field_list) {
    db_object_field_list_t* object_field_list;

    if (!from_object_field_list) {
        return NULL;
    }

    if (!(object_field_list = db_object_field_list_new())
        || db_object_field_list_copy(object_field_list, from_object_field_list))
    {
        db_object_field_list_free(object_field_list);
        return NULL;
    }

    return object_field_list;
}

void db_object_field_list_free(db_object_field_list_t* object_field_list) {
    if (object_field_list) {
        if (object_field_list->begin) {
            db_object_field_t* this = object_field_list->begin;
            db_object_field_t* next = NULL;

            while (this) {
                next = this->next;
                db_object_field_free(this);
                this = next;
            }
        }
        free(object_field_list);
    }
}

/* TODO: unit test */
int db_object_field_list_copy(db_object_field_list_t* object_field_list, const db_object_field_list_t* from_object_field_list) {
    db_object_field_t* object_field;
    db_object_field_t* object_field_copy;

    if (!object_field_list) {
        return DB_ERROR_UNKNOWN;
    }
    /*
     * TODO: Should we be able to copy into a object field list that already
     * contains data?
     */
    if (object_field_list->begin) {
        return DB_ERROR_UNKNOWN;
    }
    if (object_field_list->end) {
        return DB_ERROR_UNKNOWN;
    }
    if (object_field_list->size) {
        return DB_ERROR_UNKNOWN;
    }
    if (!from_object_field_list) {
        return DB_ERROR_UNKNOWN;
    }

    object_field = from_object_field_list->begin;
    while (object_field) {
        if (!(object_field_copy = db_object_field_new_copy(object_field))
            || db_object_field_list_add(object_field_list, object_field_copy))
        {
            return DB_ERROR_UNKNOWN;
        }

        object_field = object_field->next;
    }

    return DB_OK;
}

int db_object_field_list_add(db_object_field_list_t* object_field_list, db_object_field_t* object_field) {
    if (!object_field_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object_field) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_object_field_not_empty(object_field)) {
        return DB_ERROR_UNKNOWN;
    }
    if (object_field->next) {
        return DB_ERROR_UNKNOWN;
    }

    if (object_field_list->begin) {
        if (!object_field_list->end) {
            return DB_ERROR_UNKNOWN;
        }
        object_field_list->end->next = object_field;
        object_field_list->end = object_field;
    }
    else {
        object_field_list->begin = object_field;
        object_field_list->end = object_field;
    }
    object_field_list->size++;

    return DB_OK;
}

const db_object_field_t* db_object_field_list_begin(const db_object_field_list_t* object_field_list) {
    if (!object_field_list) {
        return NULL;
    }

    return object_field_list->begin;
}

size_t db_object_field_list_size(const db_object_field_list_t* object_field_list) {
    if (!object_field_list) {
        return 0;
    }

    return object_field_list->size;
}

/* DB OBJECT */



db_object_t* db_object_new(void) {
    db_object_t* object =
        (db_object_t*)calloc(1, sizeof(db_object_t));

    return object;
}

void db_object_free(db_object_t* object) {
    if (object) {
        if (object->object_field_list) {
            db_object_field_list_free(object->object_field_list);
        }
        free(object);
    }
}

const db_connection_t* db_object_connection(const db_object_t* object) {
    if (!object) {
        return NULL;
    }
    return object->connection;
}

const char* db_object_table(const db_object_t* object) {
    if (!object) {
        return NULL;
    }
    return object->table;
}

const db_object_field_list_t* db_object_object_field_list(const db_object_t* object) {
    if (!object) {
        return NULL;
    }
    return object->object_field_list;
}

int db_object_set_connection(db_object_t* object, const db_connection_t* connection) {
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!connection) {
        return DB_ERROR_UNKNOWN;
    }
    if (object->connection) {
        return DB_ERROR_UNKNOWN;
    }

    object->connection = connection;
    return DB_OK;
}

int db_object_set_table(db_object_t* object, const char* table) {
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!table) {
        return DB_ERROR_UNKNOWN;
    }
    if (object->table) {
        return DB_ERROR_UNKNOWN;
    }

    object->table = table;
    return DB_OK;
}

int db_object_set_primary_key_name(db_object_t* object, const char* primary_key_name) {
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!primary_key_name) {
        return DB_ERROR_UNKNOWN;
    }
    if (object->primary_key_name) {
        return DB_ERROR_UNKNOWN;
    }

    object->primary_key_name = primary_key_name;
    return DB_OK;
}

int db_object_set_object_field_list(db_object_t* object, db_object_field_list_t* object_field_list) {
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object_field_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (object->object_field_list) {
        return DB_ERROR_UNKNOWN;
    }

    object->object_field_list = object_field_list;
    return DB_OK;
}

int db_object_create(db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set) {
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value_set) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object->connection) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object->table) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object->primary_key_name) {
        return DB_ERROR_UNKNOWN;
    }
    int r;
    if (object_field_list) {
        r = db_connection_create(object->connection, object, object_field_list, value_set);
    } else {
        r = db_connection_create(object->connection, object, object->object_field_list, value_set);
    }
    if (!r) {
        r = db_connection_last_id(object->connection, &object->last_row_id);
    }
    return r;
}

db_result_list_t* db_object_read(const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
    if (!object) {
        return NULL;
    }
    if (!object->connection) {
        return NULL;
    }
    if (!object->table) {
        return NULL;
    }
    if (!object->primary_key_name) {
        return NULL;
    }

    return db_connection_read(object->connection, object, join_list, clause_list);
}

int db_object_update(const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list) {
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value_set) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object->connection) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object->table) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object->primary_key_name) {
        return DB_ERROR_UNKNOWN;
    }

    if (object_field_list) {
        return db_connection_update(object->connection, object, object_field_list, value_set, clause_list);
    }
    return db_connection_update(object->connection, object, object->object_field_list, value_set, clause_list);
}

int db_object_delete(const db_object_t* object, const db_clause_list_t* clause_list) {
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object->connection) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object->table) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object->primary_key_name) {
        return DB_ERROR_UNKNOWN;
    }

    return db_connection_delete(object->connection, object, clause_list);
}

int db_object_count(const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list, size_t* count) {
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!count) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object->connection) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object->table) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object->primary_key_name) {
        return DB_ERROR_UNKNOWN;
    }

    return db_connection_count(object->connection, object, join_list, clause_list, count);
}
