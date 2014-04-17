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

#include "nsec.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new nsec object.
 * \param[in] connection a db_connection_t pointer.
 * \return a nsec_t pointer or NULL on error.
 */
static db_object_t* __nsec_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "NSEC")
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

    if (db_object_set_object_field_list(object, object_field_list)) {
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    return object;
}

/* NSEC */

static mm_alloc_t __nsec_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(nsec_t));

nsec_t* nsec_new(const db_connection_t* connection) {
    nsec_t* nsec =
        (nsec_t*)mm_alloc_new0(&__nsec_alloc);

    if (nsec) {
        if (!(nsec->dbo = __nsec_new_object(connection))) {
            mm_alloc_delete(&__nsec_alloc, nsec);
            return NULL;
        }
    }

    return nsec;
}

void nsec_free(nsec_t* nsec) {
    if (nsec) {
        if (nsec->dbo) {
            db_object_free(nsec->dbo);
        }
        mm_alloc_delete(&__nsec_alloc, nsec);
    }
}

void nsec_reset(nsec_t* nsec) {
    if (nsec) {
        nsec->id = 0;
    }
}

int nsec_copy(nsec_t* nsec, const nsec_t* nsec_copy) {
    if (!nsec) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec_copy) {
        return DB_ERROR_UNKNOWN;
    }

    nsec->id = nsec_copy->id;
    return DB_OK;
}

int nsec_from_result(nsec_t* nsec, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!nsec) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    nsec_reset(nsec);
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 1
        || db_value_to_int32(db_value_set_at(value_set, 0), &(nsec->id)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int nsec_id(const nsec_t* nsec) {
    if (!nsec) {
        return 0;
    }

    return nsec->id;
}

int nsec_create(nsec_t* nsec) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!nsec) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (nsec->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(0))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(nsec->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int nsec_get_by_id(nsec_t* nsec, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!nsec) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    result_list = db_object_read(nsec->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (db_result_list_next(result_list)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }

            nsec_from_result(nsec, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int nsec_update(nsec_t* nsec) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!nsec) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
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

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), nsec->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(nsec->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int nsec_delete(nsec_t* nsec) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!nsec) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), nsec->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(nsec->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* NSEC LIST */

static mm_alloc_t __nsec_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(nsec_list_t));

nsec_list_t* nsec_list_new(const db_connection_t* connection) {
    nsec_list_t* nsec_list =
        (nsec_list_t*)mm_alloc_new0(&__nsec_list_alloc);

    if (nsec_list) {
        if (!(nsec_list->dbo = __nsec_new_object(connection))) {
            mm_alloc_delete(&__nsec_list_alloc, nsec_list);
            return NULL;
        }
    }

    return nsec_list;
}

void nsec_list_free(nsec_list_t* nsec_list) {
    if (nsec_list) {
        if (nsec_list->dbo) {
            db_object_free(nsec_list->dbo);
        }
        if (nsec_list->result_list) {
            db_result_list_free(nsec_list->result_list);
        }
        if (nsec_list->nsec) {
            nsec_free(nsec_list->nsec);
        }
        mm_alloc_delete(&__nsec_list_alloc, nsec_list);
    }
}

int nsec_list_get(nsec_list_t* nsec_list) {
    if (!nsec_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (nsec_list->result_list) {
        db_result_list_free(nsec_list->result_list);
    }
    if (!(nsec_list->result_list = db_object_read(nsec_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const nsec_t* nsec_list_begin(nsec_list_t* nsec_list) {
    const db_result_t* result;

    if (!nsec_list) {
        return NULL;
    }
    if (!nsec_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(nsec_list->result_list))) {
        return NULL;
    }
    if (!nsec_list->nsec) {
        if (!(nsec_list->nsec = nsec_new(db_object_connection(nsec_list->dbo)))) {
            return NULL;
        }
    }
    if (nsec_from_result(nsec_list->nsec, result)) {
        return NULL;
    }
    return nsec_list->nsec;
}

const nsec_t* nsec_list_next(nsec_list_t* nsec_list) {
    const db_result_t* result;

    if (!nsec_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(nsec_list->result_list))) {
        return NULL;
    }
    if (!nsec_list->nsec) {
        if (!(nsec_list->nsec = nsec_new(db_object_connection(nsec_list->dbo)))) {
            return NULL;
        }
    }
    if (nsec_from_result(nsec_list->nsec, result)) {
        return NULL;
    }
    return nsec_list->nsec;
}

