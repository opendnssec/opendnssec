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

#include "nsec3.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new nsec3 object.
 * \param[in] connection a db_connection_t pointer.
 * \return a nsec3_t pointer or NULL on error.
 */
static db_object_t* __nsec3_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "NSEC3")
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
        || db_object_field_set_name(object_field, "optout")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "resalt")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "algorithm")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "iterations")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "saltlength")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "salt")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "salt_last_change")
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

/* NSEC3 */

static mm_alloc_t __nsec3_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(nsec3_t));

nsec3_t* nsec3_new(const db_connection_t* connection) {
    nsec3_t* nsec3 =
        (nsec3_t*)mm_alloc_new0(&__nsec3_alloc);

    if (nsec3) {
        if (!(nsec3->dbo = __nsec3_new_object(connection))) {
            mm_alloc_delete(&__nsec3_alloc, nsec3);
            return NULL;
        }
    }

    return nsec3;
}

void nsec3_free(nsec3_t* nsec3) {
    if (nsec3) {
        if (nsec3->dbo) {
            db_object_free(nsec3->dbo);
        }
        if (nsec3->salt) {
            free(nsec3->salt);
        }
        mm_alloc_delete(&__nsec3_alloc, nsec3);
    }
}

void nsec3_reset(nsec3_t* nsec3) {
    if (nsec3) {
        nsec3->id = 0;
        nsec3->optout = 0;
        nsec3->ttl = 0;
        nsec3->resalt = 0;
        nsec3->algorithm = 0;
        nsec3->iterations = 0;
        nsec3->saltlength = 0;
        if (nsec3->salt) {
            free(nsec3->salt);
        }
        nsec3->salt = NULL;
        nsec3->salt_last_change = 0;
    }
}

int nsec3_copy(nsec3_t* nsec3, const nsec3_t* nsec3_copy) {
    char* salt_text = NULL;
    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec3_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (nsec3->salt) {
        if (!(salt_text = strdup(nsec3->salt))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    nsec3->id = nsec3_copy->id;
    nsec3->optout = nsec3_copy->optout;
    nsec3->ttl = nsec3_copy->ttl;
    nsec3->resalt = nsec3_copy->resalt;
    nsec3->algorithm = nsec3_copy->algorithm;
    nsec3->iterations = nsec3_copy->iterations;
    nsec3->saltlength = nsec3_copy->saltlength;
    if (nsec3->salt) {
        free(nsec3->salt);
    }
    nsec3->salt = salt_text;
    nsec3->salt_last_change = nsec3_copy->salt_last_change;
    return DB_OK;
}

int nsec3_from_result(nsec3_t* nsec3, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    if (nsec3->salt) {
        free(nsec3->salt);
    }
    nsec3->salt = NULL;
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 9
        || db_value_to_int32(db_value_set_at(value_set, 0), &(nsec3->id))
        || db_value_to_uint32(db_value_set_at(value_set, 1), &(nsec3->optout))
        || db_value_to_uint32(db_value_set_at(value_set, 2), &(nsec3->ttl))
        || db_value_to_uint32(db_value_set_at(value_set, 3), &(nsec3->resalt))
        || db_value_to_uint32(db_value_set_at(value_set, 4), &(nsec3->algorithm))
        || db_value_to_uint32(db_value_set_at(value_set, 5), &(nsec3->iterations))
        || db_value_to_uint32(db_value_set_at(value_set, 6), &(nsec3->saltlength))
        || db_value_to_text(db_value_set_at(value_set, 7), &(nsec3->salt))
        || db_value_to_uint32(db_value_set_at(value_set, 8), &(nsec3->salt_last_change)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int nsec3_id(const nsec3_t* nsec3) {
    if (!nsec3) {
        return 0;
    }

    return nsec3->id;
}

unsigned int nsec3_optout(const nsec3_t* nsec3) {
    if (!nsec3) {
        return 0;
    }

    return nsec3->optout;
}

unsigned int nsec3_ttl(const nsec3_t* nsec3) {
    if (!nsec3) {
        return 0;
    }

    return nsec3->ttl;
}

unsigned int nsec3_resalt(const nsec3_t* nsec3) {
    if (!nsec3) {
        return 0;
    }

    return nsec3->resalt;
}

unsigned int nsec3_algorithm(const nsec3_t* nsec3) {
    if (!nsec3) {
        return 0;
    }

    return nsec3->algorithm;
}

unsigned int nsec3_iterations(const nsec3_t* nsec3) {
    if (!nsec3) {
        return 0;
    }

    return nsec3->iterations;
}

unsigned int nsec3_saltlength(const nsec3_t* nsec3) {
    if (!nsec3) {
        return 0;
    }

    return nsec3->saltlength;
}

const char* nsec3_salt(const nsec3_t* nsec3) {
    if (!nsec3) {
        return NULL;
    }

    return nsec3->salt;
}

unsigned int nsec3_salt_last_change(const nsec3_t* nsec3) {
    if (!nsec3) {
        return 0;
    }

    return nsec3->salt_last_change;
}

int nsec3_set_optout(nsec3_t* nsec3, unsigned int optout) {
    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }

    nsec3->optout = optout;

    return DB_OK;
}

int nsec3_set_ttl(nsec3_t* nsec3, unsigned int ttl) {
    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }

    nsec3->ttl = ttl;

    return DB_OK;
}

int nsec3_set_resalt(nsec3_t* nsec3, unsigned int resalt) {
    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }

    nsec3->resalt = resalt;

    return DB_OK;
}

int nsec3_set_algorithm(nsec3_t* nsec3, unsigned int algorithm) {
    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }

    nsec3->algorithm = algorithm;

    return DB_OK;
}

int nsec3_set_iterations(nsec3_t* nsec3, unsigned int iterations) {
    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }

    nsec3->iterations = iterations;

    return DB_OK;
}

int nsec3_set_saltlength(nsec3_t* nsec3, unsigned int saltlength) {
    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }

    nsec3->saltlength = saltlength;

    return DB_OK;
}

int nsec3_set_salt(nsec3_t* nsec3, const char* salt_text) {
    char* new_salt;

    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }
    if (!salt_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_salt = strdup(salt_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (nsec3->salt) {
        free(nsec3->salt);
    }
    nsec3->salt = new_salt;

    return DB_OK;
}

int nsec3_set_salt_last_change(nsec3_t* nsec3, unsigned int salt_last_change) {
    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }

    nsec3->salt_last_change = salt_last_change;

    return DB_OK;
}

int nsec3_create(nsec3_t* nsec3) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec3->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (nsec3->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "optout")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "resalt")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "algorithm")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "iterations")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "saltlength")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "salt")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "salt_last_change")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(8))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_uint32(db_value_set_get(value_set, 0), nsec3->optout)
        || db_value_from_uint32(db_value_set_get(value_set, 1), nsec3->ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 2), nsec3->resalt)
        || db_value_from_uint32(db_value_set_get(value_set, 3), nsec3->algorithm)
        || db_value_from_uint32(db_value_set_get(value_set, 4), nsec3->iterations)
        || db_value_from_uint32(db_value_set_get(value_set, 5), nsec3->saltlength)
        || db_value_from_text(db_value_set_get(value_set, 6), nsec3->salt)
        || db_value_from_uint32(db_value_set_get(value_set, 7), nsec3->salt_last_change))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(nsec3->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int nsec3_get_by_id(nsec3_t* nsec3, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec3->dbo) {
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

    result_list = db_object_read(nsec3->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            nsec3_from_result(nsec3, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int nsec3_update(nsec3_t* nsec3) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec3->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec3->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "optout")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "resalt")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "algorithm")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "iterations")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "saltlength")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "salt")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "salt_last_change")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(8))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_uint32(db_value_set_get(value_set, 0), nsec3->optout)
        || db_value_from_uint32(db_value_set_get(value_set, 1), nsec3->ttl)
        || db_value_from_uint32(db_value_set_get(value_set, 2), nsec3->resalt)
        || db_value_from_uint32(db_value_set_get(value_set, 3), nsec3->algorithm)
        || db_value_from_uint32(db_value_set_get(value_set, 4), nsec3->iterations)
        || db_value_from_uint32(db_value_set_get(value_set, 5), nsec3->saltlength)
        || db_value_from_text(db_value_set_get(value_set, 6), nsec3->salt)
        || db_value_from_uint32(db_value_set_get(value_set, 7), nsec3->salt_last_change))
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
        || db_value_from_int32(db_clause_get_value(clause), nsec3->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(nsec3->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int nsec3_delete(nsec3_t* nsec3) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!nsec3) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec3->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec3->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), nsec3->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(nsec3->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* NSEC3 LIST */

static mm_alloc_t __nsec3_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(nsec3_list_t));

nsec3_list_t* nsec3_list_new(const db_connection_t* connection) {
    nsec3_list_t* nsec3_list =
        (nsec3_list_t*)mm_alloc_new0(&__nsec3_list_alloc);

    if (nsec3_list) {
        if (!(nsec3_list->dbo = __nsec3_new_object(connection))) {
            mm_alloc_delete(&__nsec3_list_alloc, nsec3_list);
            return NULL;
        }
    }

    return nsec3_list;
}

void nsec3_list_free(nsec3_list_t* nsec3_list) {
    if (nsec3_list) {
        if (nsec3_list->dbo) {
            db_object_free(nsec3_list->dbo);
        }
        if (nsec3_list->result_list) {
            db_result_list_free(nsec3_list->result_list);
        }
        if (nsec3_list->nsec3) {
            nsec3_free(nsec3_list->nsec3);
        }
        mm_alloc_delete(&__nsec3_list_alloc, nsec3_list);
    }
}

int nsec3_list_get(nsec3_list_t* nsec3_list) {
    if (!nsec3_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!nsec3_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (nsec3_list->result_list) {
        db_result_list_free(nsec3_list->result_list);
    }
    if (!(nsec3_list->result_list = db_object_read(nsec3_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const nsec3_t* nsec3_list_begin(nsec3_list_t* nsec3_list) {
    const db_result_t* result;

    if (!nsec3_list) {
        return NULL;
    }
    if (!nsec3_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(nsec3_list->result_list))) {
        return NULL;
    }
    if (!nsec3_list->nsec3) {
        if (!(nsec3_list->nsec3 = nsec3_new(db_object_connection(nsec3_list->dbo)))) {
            return NULL;
        }
    }
    if (nsec3_from_result(nsec3_list->nsec3, result)) {
        return NULL;
    }
    return nsec3_list->nsec3;
}

const nsec3_t* nsec3_list_next(nsec3_list_t* nsec3_list) {
    const db_result_t* result;

    if (!nsec3_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(nsec3_list->result_list))) {
        return NULL;
    }
    if (!nsec3_list->nsec3) {
        if (!(nsec3_list->nsec3 = nsec3_new(db_object_connection(nsec3_list->dbo)))) {
            return NULL;
        }
    }
    if (nsec3_from_result(nsec3_list->nsec3, result)) {
        return NULL;
    }
    return nsec3_list->nsec3;
}

