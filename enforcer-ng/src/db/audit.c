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

#include "audit.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new audit object.
 * \param[in] connection a db_connection_t pointer.
 * \return a audit_t pointer or NULL on error.
 */
static db_object_t* __audit_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "Audit")
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
        || db_object_field_set_name(object_field, "partial")
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

/* AUDIT */

static mm_alloc_t __audit_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(audit_t));

audit_t* audit_new(const db_connection_t* connection) {
    audit_t* audit =
        (audit_t*)mm_alloc_new0(&__audit_alloc);

    if (audit) {
        if (!(audit->dbo = __audit_new_object(connection))) {
            mm_alloc_delete(&__audit_alloc, audit);
            return NULL;
        }
    }

    return audit;
}

void audit_free(audit_t* audit) {
    if (audit) {
        if (audit->dbo) {
            db_object_free(audit->dbo);
        }
        mm_alloc_delete(&__audit_alloc, audit);
    }
}

void audit_reset(audit_t* audit) {
    if (audit) {
        audit->id = 0;
        audit->partial = 0;
    }
}

int audit_copy(audit_t* audit, const audit_t* audit_copy) {
    if (!audit) {
        return DB_ERROR_UNKNOWN;
    }
    if (!audit_copy) {
        return DB_ERROR_UNKNOWN;
    }

    audit->id = audit_copy->id;
    audit->partial = audit_copy->partial;
    return DB_OK;
}

int audit_from_result(audit_t* audit, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!audit) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 2
        || db_value_to_int32(db_value_set_at(value_set, 0), &(audit->id))
        || db_value_to_uint32(db_value_set_at(value_set, 1), &(audit->partial)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int audit_id(const audit_t* audit) {
    if (!audit) {
        return 0;
    }

    return audit->id;
}

unsigned int audit_partial(const audit_t* audit) {
    if (!audit) {
        return 0;
    }

    return audit->partial;
}

int audit_set_partial(audit_t* audit, unsigned int partial) {
    if (!audit) {
        return DB_ERROR_UNKNOWN;
    }

    audit->partial = partial;

    return DB_OK;
}

int audit_create(audit_t* audit) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!audit) {
        return DB_ERROR_UNKNOWN;
    }
    if (!audit->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (audit->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "partial")
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

    if (db_value_from_uint32(db_value_set_get(value_set, 0), audit->partial))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(audit->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int audit_get_by_id(audit_t* audit, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!audit) {
        return DB_ERROR_UNKNOWN;
    }
    if (!audit->dbo) {
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

    result_list = db_object_read(audit->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            audit_from_result(audit, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int audit_update(audit_t* audit) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!audit) {
        return DB_ERROR_UNKNOWN;
    }
    if (!audit->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!audit->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "partial")
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

    if (db_value_from_uint32(db_value_set_get(value_set, 0), audit->partial))
    {
        db_value_set_free(value_set);
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
        || db_value_from_int32(db_clause_get_value(clause), audit->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(audit->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int audit_delete(audit_t* audit) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!audit) {
        return DB_ERROR_UNKNOWN;
    }
    if (!audit->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!audit->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), audit->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(audit->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* AUDIT LIST */

static mm_alloc_t __audit_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(audit_list_t));

audit_list_t* audit_list_new(const db_connection_t* connection) {
    audit_list_t* audit_list =
        (audit_list_t*)mm_alloc_new0(&__audit_list_alloc);

    if (audit_list) {
        if (!(audit_list->dbo = __audit_new_object(connection))) {
            mm_alloc_delete(&__audit_list_alloc, audit_list);
            return NULL;
        }
    }

    return audit_list;
}

void audit_list_free(audit_list_t* audit_list) {
    if (audit_list) {
        if (audit_list->dbo) {
            db_object_free(audit_list->dbo);
        }
        if (audit_list->result_list) {
            db_result_list_free(audit_list->result_list);
        }
        if (audit_list->audit) {
            audit_free(audit_list->audit);
        }
        mm_alloc_delete(&__audit_list_alloc, audit_list);
    }
}

int audit_list_get(audit_list_t* audit_list) {
    if (!audit_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!audit_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (audit_list->result_list) {
        db_result_list_free(audit_list->result_list);
    }
    if (!(audit_list->result_list = db_object_read(audit_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const audit_t* audit_list_begin(audit_list_t* audit_list) {
    const db_result_t* result;

    if (!audit_list) {
        return NULL;
    }
    if (!audit_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(audit_list->result_list))) {
        return NULL;
    }
    if (!audit_list->audit) {
        if (!(audit_list->audit = audit_new(db_object_connection(audit_list->dbo)))) {
            return NULL;
        }
    }
    if (audit_from_result(audit_list->audit, result)) {
        return NULL;
    }
    return audit_list->audit;
}

const audit_t* audit_list_next(audit_list_t* audit_list) {
    const db_result_t* result;

    if (!audit_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(audit_list->result_list))) {
        return NULL;
    }
    if (!audit_list->audit) {
        if (!(audit_list->audit = audit_new(db_object_connection(audit_list->dbo)))) {
            return NULL;
        }
    }
    if (audit_from_result(audit_list->audit, result)) {
        return NULL;
    }
    return audit_list->audit;
}

