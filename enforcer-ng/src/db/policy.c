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

#include "policy.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new policy object.
 * \param[in] connection a db_connection_t pointer.
 * \return a policy_t pointer or NULL on error.
 */
static db_object_t* __policy_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "Policy")
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
        || db_object_field_set_name(object_field, "name")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "description")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signatures")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denial")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keylist")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zone")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parent")
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

/* POLICY */

static mm_alloc_t __policy_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(policy_t));

policy_t* policy_new(const db_connection_t* connection) {
    policy_t* policy =
        (policy_t*)mm_alloc_new0(&__policy_alloc);

    if (policy) {
        if (!(policy->dbo = __policy_new_object(connection))) {
            mm_alloc_delete(&__policy_alloc, policy);
            return NULL;
        }
        db_value_reset(&(policy->id));
        db_value_reset(&(policy->signatures));
        db_value_reset(&(policy->denial));
        db_value_reset(&(policy->keylist));
        db_value_reset(&(policy->zone));
        db_value_reset(&(policy->parent));
    }

    return policy;
}

void policy_free(policy_t* policy) {
    if (policy) {
        if (policy->dbo) {
            db_object_free(policy->dbo);
        }
        db_value_reset(&(policy->id));
        if (policy->name) {
            free(policy->name);
        }
        if (policy->description) {
            free(policy->description);
        }
        db_value_reset(&(policy->signatures));
        db_value_reset(&(policy->denial));
        db_value_reset(&(policy->keylist));
        db_value_reset(&(policy->zone));
        db_value_reset(&(policy->parent));
        mm_alloc_delete(&__policy_alloc, policy);
    }
}

void policy_reset(policy_t* policy) {
    if (policy) {
        db_value_reset(&(policy->id));
        if (policy->name) {
            free(policy->name);
        }
        policy->name = NULL;
        if (policy->description) {
            free(policy->description);
        }
        policy->description = NULL;
        db_value_reset(&(policy->signatures));
        db_value_reset(&(policy->denial));
        db_value_reset(&(policy->keylist));
        db_value_reset(&(policy->zone));
        db_value_reset(&(policy->parent));
    }
}

int policy_copy(policy_t* policy, const policy_t* policy_copy) {
    char* name_text = NULL;
    char* description_text = NULL;
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy_copy->name) {
        if (!(name_text = strdup(policy_copy->name))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    if (policy_copy->description) {
        if (!(description_text = strdup(policy_copy->description))) {
            if (name_text) {
                free(name_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (db_value_copy(&(policy->id), &(policy_copy->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (policy->name) {
        free(policy->name);
    }
    policy->name = name_text;
    if (policy->description) {
        free(policy->description);
    }
    policy->description = description_text;
    if (db_value_copy(&(policy->signatures), &(policy_copy->signatures))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_copy(&(policy->denial), &(policy_copy->denial))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_copy(&(policy->keylist), &(policy_copy->keylist))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_copy(&(policy->zone), &(policy_copy->zone))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_copy(&(policy->parent), &(policy_copy->parent))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

int policy_from_result(policy_t* policy, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(policy->id));
    if (policy->name) {
        free(policy->name);
    }
    policy->name = NULL;
    if (policy->description) {
        free(policy->description);
    }
    policy->description = NULL;
    db_value_reset(&(policy->signatures));
    db_value_reset(&(policy->denial));
    db_value_reset(&(policy->keylist));
    db_value_reset(&(policy->zone));
    db_value_reset(&(policy->parent));
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 8
        || db_value_copy(&(policy->id), db_value_set_at(value_set, 0))
        || db_value_to_text(db_value_set_at(value_set, 1), &(policy->name))
        || db_value_to_text(db_value_set_at(value_set, 2), &(policy->description))
        || db_value_copy(&(policy->signatures), db_value_set_at(value_set, 3))
        || db_value_copy(&(policy->denial), db_value_set_at(value_set, 4))
        || db_value_copy(&(policy->keylist), db_value_set_at(value_set, 5))
        || db_value_copy(&(policy->zone), db_value_set_at(value_set, 6))
        || db_value_copy(&(policy->parent), db_value_set_at(value_set, 7)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

const db_value_t* policy_id(const policy_t* policy) {
    if (!policy) {
        return NULL;
    }

    return &(policy->id);
}

const char* policy_name(const policy_t* policy) {
    if (!policy) {
        return NULL;
    }

    return policy->name;
}

const char* policy_description(const policy_t* policy) {
    if (!policy) {
        return NULL;
    }

    return policy->description;
}

const db_value_t* policy_signatures(const policy_t* policy) {
    if (!policy) {
        return NULL;
    }

    return &(policy->signatures);
}

signatures_t* policy_get_signatures(const policy_t* policy) {
    signatures_t* signatures = NULL;
    
    if (!policy) {
        return NULL;
    }
    if (!policy->dbo) {
        return NULL;
    }
    if (db_value_not_empty(&(policy->signatures))) {
        return NULL;
    }
    
    if (!(signatures = signatures_new(db_object_connection(policy->dbo)))) {
        return NULL;
    }
    if (signatures_get_by_id(signatures, &(policy->signatures))) {
        signatures_free(signatures);
        return NULL;
    }

    return signatures;
}

const db_value_t* policy_denial(const policy_t* policy) {
    if (!policy) {
        return NULL;
    }

    return &(policy->denial);
}

denial_t* policy_get_denial(const policy_t* policy) {
    denial_t* denial = NULL;
    
    if (!policy) {
        return NULL;
    }
    if (!policy->dbo) {
        return NULL;
    }
    if (db_value_not_empty(&(policy->denial))) {
        return NULL;
    }
    
    if (!(denial = denial_new(db_object_connection(policy->dbo)))) {
        return NULL;
    }
    if (denial_get_by_id(denial, &(policy->denial))) {
        denial_free(denial);
        return NULL;
    }

    return denial;
}

const db_value_t* policy_keylist(const policy_t* policy) {
    if (!policy) {
        return NULL;
    }

    return &(policy->keylist);
}

dbo_keylist_t* policy_get_keylist(const policy_t* policy) {
    dbo_keylist_t* keylist = NULL;
    
    if (!policy) {
        return NULL;
    }
    if (!policy->dbo) {
        return NULL;
    }
    if (db_value_not_empty(&(policy->keylist))) {
        return NULL;
    }
    
    if (!(keylist = dbo_keylist_new(db_object_connection(policy->dbo)))) {
        return NULL;
    }
    if (dbo_keylist_get_by_id(keylist, &(policy->keylist))) {
        dbo_keylist_free(keylist);
        return NULL;
    }

    return keylist;
}

const db_value_t* policy_zone(const policy_t* policy) {
    if (!policy) {
        return NULL;
    }

    return &(policy->zone);
}

zone_t* policy_get_zone(const policy_t* policy) {
    zone_t* zone = NULL;
    
    if (!policy) {
        return NULL;
    }
    if (!policy->dbo) {
        return NULL;
    }
    if (db_value_not_empty(&(policy->zone))) {
        return NULL;
    }
    
    if (!(zone = zone_new(db_object_connection(policy->dbo)))) {
        return NULL;
    }
    if (zone_get_by_id(zone, &(policy->zone))) {
        zone_free(zone);
        return NULL;
    }

    return zone;
}

const db_value_t* policy_parent(const policy_t* policy) {
    if (!policy) {
        return NULL;
    }

    return &(policy->parent);
}

parent_t* policy_get_parent(const policy_t* policy) {
    parent_t* parent = NULL;
    
    if (!policy) {
        return NULL;
    }
    if (!policy->dbo) {
        return NULL;
    }
    if (db_value_not_empty(&(policy->parent))) {
        return NULL;
    }
    
    if (!(parent = parent_new(db_object_connection(policy->dbo)))) {
        return NULL;
    }
    if (parent_get_by_id(parent, &(policy->parent))) {
        parent_free(parent);
        return NULL;
    }

    return parent;
}

int policy_set_name(policy_t* policy, const char* name_text) {
    char* new_name;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!name_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_name = strdup(name_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy->name) {
        free(policy->name);
    }
    policy->name = new_name;

    return DB_OK;
}

int policy_set_description(policy_t* policy, const char* description_text) {
    char* new_description;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!description_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_description = strdup(description_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy->description) {
        free(policy->description);
    }
    policy->description = new_description;

    return DB_OK;
}

int policy_set_signatures(policy_t* policy, const db_value_t* signatures) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!signatures) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(signatures)) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(policy->signatures));
    if (db_value_copy(&(policy->signatures), signatures)) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int policy_set_denial(policy_t* policy, const db_value_t* denial) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!denial) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(denial)) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(policy->denial));
    if (db_value_copy(&(policy->denial), denial)) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int policy_set_keylist(policy_t* policy, const db_value_t* keylist) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!keylist) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(keylist)) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(policy->keylist));
    if (db_value_copy(&(policy->keylist), keylist)) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int policy_set_zone(policy_t* policy, const db_value_t* zone) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(zone)) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(policy->zone));
    if (db_value_copy(&(policy->zone), zone)) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int policy_set_parent(policy_t* policy, const db_value_t* parent) {
    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!parent) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(parent)) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(policy->parent));
    if (db_value_copy(&(policy->parent), parent)) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int policy_create(policy_t* policy) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!db_value_not_empty(&(policy->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->name) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->description) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->signatures))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->denial))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->keylist))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->zone))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->parent))) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "name")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "description")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signatures")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denial")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keylist")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zone")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parent")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(7))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_text(db_value_set_get(value_set, 0), policy->name)
        || db_value_from_text(db_value_set_get(value_set, 1), policy->description)
        || db_value_copy(db_value_set_get(value_set, 2), &(policy->signatures))
        || db_value_copy(db_value_set_get(value_set, 3), &(policy->denial))
        || db_value_copy(db_value_set_get(value_set, 4), &(policy->keylist))
        || db_value_copy(db_value_set_get(value_set, 5), &(policy->zone))
        || db_value_copy(db_value_set_get(value_set, 6), &(policy->parent)))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(policy->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int policy_get_by_id(policy_t* policy, const db_value_t* id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!id) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(id)) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    result_list = db_object_read(policy->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (policy_from_result(policy, result)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }
                
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int policy_update(policy_t* policy) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->name) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->description) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->signatures))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->denial))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->keylist))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->zone))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->parent))) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "name")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "description")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signatures")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "denial")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "keylist")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "zone")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "parent")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(7))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_text(db_value_set_get(value_set, 0), policy->name)
        || db_value_from_text(db_value_set_get(value_set, 1), policy->description)
        || db_value_copy(db_value_set_get(value_set, 2), &(policy->signatures))
        || db_value_copy(db_value_set_get(value_set, 3), &(policy->denial))
        || db_value_copy(db_value_set_get(value_set, 4), &(policy->keylist))
        || db_value_copy(db_value_set_get(value_set, 5), &(policy->zone))
        || db_value_copy(db_value_set_get(value_set, 6), &(policy->parent)))
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
        || db_value_copy(db_clause_get_value(clause), &(policy->id))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(policy->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int policy_delete(policy_t* policy) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!policy) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(policy->id))) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(policy->id))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(policy->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* POLICY LIST */

static mm_alloc_t __policy_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(policy_list_t));

policy_list_t* policy_list_new(const db_connection_t* connection) {
    policy_list_t* policy_list =
        (policy_list_t*)mm_alloc_new0(&__policy_list_alloc);

    if (policy_list) {
        if (!(policy_list->dbo = __policy_new_object(connection))) {
            mm_alloc_delete(&__policy_list_alloc, policy_list);
            return NULL;
        }
    }

    return policy_list;
}

void policy_list_free(policy_list_t* policy_list) {
    if (policy_list) {
        if (policy_list->dbo) {
            db_object_free(policy_list->dbo);
        }
        if (policy_list->result_list) {
            db_result_list_free(policy_list->result_list);
        }
        if (policy_list->policy) {
            policy_free(policy_list->policy);
        }
        mm_alloc_delete(&__policy_list_alloc, policy_list);
    }
}

int policy_list_get(policy_list_t* policy_list) {
    if (!policy_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (policy_list->result_list) {
        db_result_list_free(policy_list->result_list);
    }
    if (!(policy_list->result_list = db_object_read(policy_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const policy_t* policy_list_begin(policy_list_t* policy_list) {
    const db_result_t* result;

    if (!policy_list) {
        return NULL;
    }
    if (!policy_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(policy_list->result_list))) {
        return NULL;
    }
    if (!policy_list->policy) {
        if (!(policy_list->policy = policy_new(db_object_connection(policy_list->dbo)))) {
            return NULL;
        }
    }
    if (policy_from_result(policy_list->policy, result)) {
        return NULL;
    }
    return policy_list->policy;
}

const policy_t* policy_list_next(policy_list_t* policy_list) {
    const db_result_t* result;

    if (!policy_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(policy_list->result_list))) {
        return NULL;
    }
    if (!policy_list->policy) {
        if (!(policy_list->policy = policy_new(db_object_connection(policy_list->dbo)))) {
            return NULL;
        }
    }
    if (policy_from_result(policy_list->policy, result)) {
        return NULL;
    }
    return policy_list->policy;
}
