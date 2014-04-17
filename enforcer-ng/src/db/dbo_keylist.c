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

#include "dbo_keylist.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new dbo keylist object.
 * \param[in] connection a db_connection_t pointer.
 * \return a dbo_keylist_t pointer or NULL on error.
 */
static db_object_t* __dbo_keylist_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "KeyList")
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
        || db_object_field_set_name(object_field, "ttl")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "retiresafety")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "publishsafety")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zones_share_keys")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "purgeafter")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
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

/* DBO KEYLIST */

static mm_alloc_t __dbo_keylist_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(dbo_keylist_t));

dbo_keylist_t* dbo_keylist_new(const db_connection_t* connection) {
    dbo_keylist_t* dbo_keylist =
        (dbo_keylist_t*)mm_alloc_new0(&__dbo_keylist_alloc);

    if (dbo_keylist) {
        if (!(dbo_keylist->dbo = __dbo_keylist_new_object(connection))) {
            mm_alloc_delete(&__dbo_keylist_alloc, dbo_keylist);
            return NULL;
        }
    }

    return dbo_keylist;
}

void dbo_keylist_free(dbo_keylist_t* dbo_keylist) {
    if (dbo_keylist) {
        if (dbo_keylist->dbo) {
            db_object_free(dbo_keylist->dbo);
        }
        mm_alloc_delete(&__dbo_keylist_alloc, dbo_keylist);
    }
}

void dbo_keylist_reset(dbo_keylist_t* dbo_keylist) {
    if (dbo_keylist) {
        dbo_keylist->id = 0;
        dbo_keylist->ttl = 0;
        dbo_keylist->retiresafety = 0;
        dbo_keylist->publishsafety = 0;
        dbo_keylist->zones_share_keys = 0;
        dbo_keylist->purgeafter = 0;
    }
}

int dbo_keylist_copy(dbo_keylist_t* dbo_keylist, const dbo_keylist_t* dbo_keylist_copy) {
    if (!dbo_keylist) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_keylist_copy) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_keylist->id = dbo_keylist_copy->id;
    dbo_keylist->ttl = dbo_keylist_copy->ttl;
    dbo_keylist->retiresafety = dbo_keylist_copy->retiresafety;
    dbo_keylist->publishsafety = dbo_keylist_copy->publishsafety;
    dbo_keylist->zones_share_keys = dbo_keylist_copy->zones_share_keys;
    dbo_keylist->purgeafter = dbo_keylist_copy->purgeafter;
    return DB_OK;
}

int dbo_keylist_from_result(dbo_keylist_t* dbo_keylist, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!dbo_keylist) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_keylist_reset(dbo_keylist);
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 6
        || db_value_to_int32(db_value_set_at(value_set, 0), &(dbo_keylist->id))
        || db_value_to_int32(db_value_set_at(value_set, 1), &(dbo_keylist->ttl))
        || db_value_to_int32(db_value_set_at(value_set, 2), &(dbo_keylist->retiresafety))
        || db_value_to_int32(db_value_set_at(value_set, 3), &(dbo_keylist->publishsafety))
        || db_value_to_uint32(db_value_set_at(value_set, 4), &(dbo_keylist->zones_share_keys))
        || db_value_to_int32(db_value_set_at(value_set, 5), &(dbo_keylist->purgeafter)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int dbo_keylist_id(const dbo_keylist_t* dbo_keylist) {
    if (!dbo_keylist) {
        return 0;
    }

    return dbo_keylist->id;
}

int dbo_keylist_ttl(const dbo_keylist_t* dbo_keylist) {
    if (!dbo_keylist) {
        return 0;
    }

    return dbo_keylist->ttl;
}

int dbo_keylist_retiresafety(const dbo_keylist_t* dbo_keylist) {
    if (!dbo_keylist) {
        return 0;
    }

    return dbo_keylist->retiresafety;
}

int dbo_keylist_publishsafety(const dbo_keylist_t* dbo_keylist) {
    if (!dbo_keylist) {
        return 0;
    }

    return dbo_keylist->publishsafety;
}

unsigned int dbo_keylist_zones_share_keys(const dbo_keylist_t* dbo_keylist) {
    if (!dbo_keylist) {
        return 0;
    }

    return dbo_keylist->zones_share_keys;
}

int dbo_keylist_purgeafter(const dbo_keylist_t* dbo_keylist) {
    if (!dbo_keylist) {
        return 0;
    }

    return dbo_keylist->purgeafter;
}

int dbo_keylist_set_ttl(dbo_keylist_t* dbo_keylist, int ttl) {
    if (!dbo_keylist) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_keylist->ttl = ttl;

    return DB_OK;
}

int dbo_keylist_set_retiresafety(dbo_keylist_t* dbo_keylist, int retiresafety) {
    if (!dbo_keylist) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_keylist->retiresafety = retiresafety;

    return DB_OK;
}

int dbo_keylist_set_publishsafety(dbo_keylist_t* dbo_keylist, int publishsafety) {
    if (!dbo_keylist) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_keylist->publishsafety = publishsafety;

    return DB_OK;
}

int dbo_keylist_set_zones_share_keys(dbo_keylist_t* dbo_keylist, unsigned int zones_share_keys) {
    if (!dbo_keylist) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_keylist->zones_share_keys = zones_share_keys;

    return DB_OK;
}

int dbo_keylist_set_purgeafter(dbo_keylist_t* dbo_keylist, int purgeafter) {
    if (!dbo_keylist) {
        return DB_ERROR_UNKNOWN;
    }

    dbo_keylist->purgeafter = purgeafter;

    return DB_OK;
}

int dbo_keylist_create(dbo_keylist_t* dbo_keylist) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!dbo_keylist) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_keylist->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (dbo_keylist->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "retiresafety")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "publishsafety")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zones_share_keys")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "purgeafter")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(5))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_int32(db_value_set_get(value_set, 0), dbo_keylist->ttl)
        || db_value_from_int32(db_value_set_get(value_set, 1), dbo_keylist->retiresafety)
        || db_value_from_int32(db_value_set_get(value_set, 2), dbo_keylist->publishsafety)
        || db_value_from_uint32(db_value_set_get(value_set, 3), dbo_keylist->zones_share_keys)
        || db_value_from_int32(db_value_set_get(value_set, 4), dbo_keylist->purgeafter))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(dbo_keylist->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int dbo_keylist_get_by_id(dbo_keylist_t* dbo_keylist, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!dbo_keylist) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_keylist->dbo) {
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

    result_list = db_object_read(dbo_keylist->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (db_result_list_next(result_list)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }

            dbo_keylist_from_result(dbo_keylist, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int dbo_keylist_update(dbo_keylist_t* dbo_keylist) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!dbo_keylist) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_keylist->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_keylist->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "retiresafety")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "publishsafety")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zones_share_keys")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "purgeafter")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(5))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_int32(db_value_set_get(value_set, 0), dbo_keylist->ttl)
        || db_value_from_int32(db_value_set_get(value_set, 1), dbo_keylist->retiresafety)
        || db_value_from_int32(db_value_set_get(value_set, 2), dbo_keylist->publishsafety)
        || db_value_from_uint32(db_value_set_get(value_set, 3), dbo_keylist->zones_share_keys)
        || db_value_from_int32(db_value_set_get(value_set, 4), dbo_keylist->purgeafter))
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
        || db_value_from_int32(db_clause_get_value(clause), dbo_keylist->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(dbo_keylist->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int dbo_keylist_delete(dbo_keylist_t* dbo_keylist) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!dbo_keylist) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_keylist->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_keylist->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), dbo_keylist->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(dbo_keylist->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* DBO KEYLIST LIST */

static mm_alloc_t __dbo_keylist_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(dbo_keylist_list_t));

dbo_keylist_list_t* dbo_keylist_list_new(const db_connection_t* connection) {
    dbo_keylist_list_t* dbo_keylist_list =
        (dbo_keylist_list_t*)mm_alloc_new0(&__dbo_keylist_list_alloc);

    if (dbo_keylist_list) {
        if (!(dbo_keylist_list->dbo = __dbo_keylist_new_object(connection))) {
            mm_alloc_delete(&__dbo_keylist_list_alloc, dbo_keylist_list);
            return NULL;
        }
    }

    return dbo_keylist_list;
}

void dbo_keylist_list_free(dbo_keylist_list_t* dbo_keylist_list) {
    if (dbo_keylist_list) {
        if (dbo_keylist_list->dbo) {
            db_object_free(dbo_keylist_list->dbo);
        }
        if (dbo_keylist_list->result_list) {
            db_result_list_free(dbo_keylist_list->result_list);
        }
        if (dbo_keylist_list->dbo_keylist) {
            dbo_keylist_free(dbo_keylist_list->dbo_keylist);
        }
        mm_alloc_delete(&__dbo_keylist_list_alloc, dbo_keylist_list);
    }
}

int dbo_keylist_list_get(dbo_keylist_list_t* dbo_keylist_list) {
    if (!dbo_keylist_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!dbo_keylist_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (dbo_keylist_list->result_list) {
        db_result_list_free(dbo_keylist_list->result_list);
    }
    if (!(dbo_keylist_list->result_list = db_object_read(dbo_keylist_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const dbo_keylist_t* dbo_keylist_list_begin(dbo_keylist_list_t* dbo_keylist_list) {
    const db_result_t* result;

    if (!dbo_keylist_list) {
        return NULL;
    }
    if (!dbo_keylist_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(dbo_keylist_list->result_list))) {
        return NULL;
    }
    if (!dbo_keylist_list->dbo_keylist) {
        if (!(dbo_keylist_list->dbo_keylist = dbo_keylist_new(db_object_connection(dbo_keylist_list->dbo)))) {
            return NULL;
        }
    }
    if (dbo_keylist_from_result(dbo_keylist_list->dbo_keylist, result)) {
        return NULL;
    }
    return dbo_keylist_list->dbo_keylist;
}

const dbo_keylist_t* dbo_keylist_list_next(dbo_keylist_list_t* dbo_keylist_list) {
    const db_result_t* result;

    if (!dbo_keylist_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(dbo_keylist_list->result_list))) {
        return NULL;
    }
    if (!dbo_keylist_list->dbo_keylist) {
        if (!(dbo_keylist_list->dbo_keylist = dbo_keylist_new(db_object_connection(dbo_keylist_list->dbo)))) {
            return NULL;
        }
    }
    if (dbo_keylist_from_result(dbo_keylist_list->dbo_keylist, result)) {
        return NULL;
    }
    return dbo_keylist_list->dbo_keylist;
}

