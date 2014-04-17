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

#include "enforcer_zone.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new enforcer zone object.
 * \param[in] connection a db_connection_t pointer.
 * \return a enforcer_zone_t pointer or NULL on error.
 */
static db_object_t* __enforcer_zone_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "EnforcerZone")
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
        || db_object_field_set_name(object_field, "policy")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signconf_needs_writing")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signconf_path")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_change")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl_end_ds")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl_end_dk")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl_end_rs")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "roll_ksk_now")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "roll_zsk_now")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "roll_csk_now")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "adapters")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_ksk_roll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_zsk_roll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_csk_roll")
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

/* ENFORCER ZONE */

static mm_alloc_t __enforcer_zone_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(enforcer_zone_t));

enforcer_zone_t* enforcer_zone_new(const db_connection_t* connection) {
    enforcer_zone_t* enforcer_zone =
        (enforcer_zone_t*)mm_alloc_new0(&__enforcer_zone_alloc);

    if (enforcer_zone) {
        if (!(enforcer_zone->dbo = __enforcer_zone_new_object(connection))) {
            mm_alloc_delete(&__enforcer_zone_alloc, enforcer_zone);
            return NULL;
        }
    }

    return enforcer_zone;
}

void enforcer_zone_free(enforcer_zone_t* enforcer_zone) {
    if (enforcer_zone) {
        if (enforcer_zone->dbo) {
            db_object_free(enforcer_zone->dbo);
        }
        if (enforcer_zone->name) {
            free(enforcer_zone->name);
        }
        if (enforcer_zone->policy) {
            free(enforcer_zone->policy);
        }
        if (enforcer_zone->signconf_path) {
            free(enforcer_zone->signconf_path);
        }
        mm_alloc_delete(&__enforcer_zone_alloc, enforcer_zone);
    }
}

void enforcer_zone_reset(enforcer_zone_t* enforcer_zone) {
    if (enforcer_zone) {
        enforcer_zone->id = 0;
        if (enforcer_zone->name) {
            free(enforcer_zone->name);
        }
        enforcer_zone->name = NULL;
        if (enforcer_zone->policy) {
            free(enforcer_zone->policy);
        }
        enforcer_zone->policy = NULL;
        enforcer_zone->signconf_needs_writing = 0;
        if (enforcer_zone->signconf_path) {
            free(enforcer_zone->signconf_path);
        }
        enforcer_zone->signconf_path = NULL;
        enforcer_zone->next_change = 0;
        enforcer_zone->ttl_end_ds = 0;
        enforcer_zone->ttl_end_dk = 0;
        enforcer_zone->ttl_end_rs = 0;
        enforcer_zone->roll_ksk_now = 0;
        enforcer_zone->roll_zsk_now = 0;
        enforcer_zone->roll_csk_now = 0;
        enforcer_zone->adapters = 0;
        enforcer_zone->next_ksk_roll = 0;
        enforcer_zone->next_zsk_roll = 0;
        enforcer_zone->next_csk_roll = 0;
    }
}

int enforcer_zone_copy(enforcer_zone_t* enforcer_zone, const enforcer_zone_t* enforcer_zone_copy) {
    char* name_text = NULL;
    char* policy_text = NULL;
    char* signconf_path_text = NULL;
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!enforcer_zone_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (enforcer_zone->name) {
        if (!(name_text = strdup(enforcer_zone->name))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    if (enforcer_zone->policy) {
        if (!(policy_text = strdup(enforcer_zone->policy))) {
            if (name_text) {
                free(name_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (enforcer_zone->signconf_path) {
        if (!(signconf_path_text = strdup(enforcer_zone->signconf_path))) {
            if (name_text) {
                free(name_text);
            }
            if (policy_text) {
                free(policy_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    enforcer_zone->id = enforcer_zone_copy->id;
    if (enforcer_zone->name) {
        free(enforcer_zone->name);
    }
    enforcer_zone->name = name_text;
    if (enforcer_zone->policy) {
        free(enforcer_zone->policy);
    }
    enforcer_zone->policy = policy_text;
    enforcer_zone->signconf_needs_writing = enforcer_zone_copy->signconf_needs_writing;
    if (enforcer_zone->signconf_path) {
        free(enforcer_zone->signconf_path);
    }
    enforcer_zone->signconf_path = signconf_path_text;
    enforcer_zone->next_change = enforcer_zone_copy->next_change;
    enforcer_zone->ttl_end_ds = enforcer_zone_copy->ttl_end_ds;
    enforcer_zone->ttl_end_dk = enforcer_zone_copy->ttl_end_dk;
    enforcer_zone->ttl_end_rs = enforcer_zone_copy->ttl_end_rs;
    enforcer_zone->roll_ksk_now = enforcer_zone_copy->roll_ksk_now;
    enforcer_zone->roll_zsk_now = enforcer_zone_copy->roll_zsk_now;
    enforcer_zone->roll_csk_now = enforcer_zone_copy->roll_csk_now;
    enforcer_zone->adapters = enforcer_zone_copy->adapters;
    enforcer_zone->next_ksk_roll = enforcer_zone_copy->next_ksk_roll;
    enforcer_zone->next_zsk_roll = enforcer_zone_copy->next_zsk_roll;
    enforcer_zone->next_csk_roll = enforcer_zone_copy->next_csk_roll;
    return DB_OK;
}

int enforcer_zone_from_result(enforcer_zone_t* enforcer_zone, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    if (enforcer_zone->name) {
        free(enforcer_zone->name);
    }
    enforcer_zone->name = NULL;
    if (enforcer_zone->policy) {
        free(enforcer_zone->policy);
    }
    enforcer_zone->policy = NULL;
    if (enforcer_zone->signconf_path) {
        free(enforcer_zone->signconf_path);
    }
    enforcer_zone->signconf_path = NULL;
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 16
        || db_value_to_int32(db_value_set_at(value_set, 0), &(enforcer_zone->id))
        || db_value_to_text(db_value_set_at(value_set, 1), &(enforcer_zone->name))
        || db_value_to_text(db_value_set_at(value_set, 2), &(enforcer_zone->policy))
        || db_value_to_uint32(db_value_set_at(value_set, 3), &(enforcer_zone->signconf_needs_writing))
        || db_value_to_text(db_value_set_at(value_set, 4), &(enforcer_zone->signconf_path))
        || db_value_to_uint32(db_value_set_at(value_set, 5), &(enforcer_zone->next_change))
        || db_value_to_uint32(db_value_set_at(value_set, 6), &(enforcer_zone->ttl_end_ds))
        || db_value_to_uint32(db_value_set_at(value_set, 7), &(enforcer_zone->ttl_end_dk))
        || db_value_to_uint32(db_value_set_at(value_set, 8), &(enforcer_zone->ttl_end_rs))
        || db_value_to_uint32(db_value_set_at(value_set, 9), &(enforcer_zone->roll_ksk_now))
        || db_value_to_uint32(db_value_set_at(value_set, 10), &(enforcer_zone->roll_zsk_now))
        || db_value_to_uint32(db_value_set_at(value_set, 11), &(enforcer_zone->roll_csk_now))
        || db_value_to_int32(db_value_set_at(value_set, 12), &(enforcer_zone->adapters))
        || db_value_to_uint32(db_value_set_at(value_set, 13), &(enforcer_zone->next_ksk_roll))
        || db_value_to_uint32(db_value_set_at(value_set, 14), &(enforcer_zone->next_zsk_roll))
        || db_value_to_uint32(db_value_set_at(value_set, 15), &(enforcer_zone->next_csk_roll)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int enforcer_zone_id(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->id;
}

const char* enforcer_zone_name(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return NULL;
    }

    return enforcer_zone->name;
}

const char* enforcer_zone_policy(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return NULL;
    }

    return enforcer_zone->policy;
}

unsigned int enforcer_zone_signconf_needs_writing(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->signconf_needs_writing;
}

const char* enforcer_zone_signconf_path(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return NULL;
    }

    return enforcer_zone->signconf_path;
}

unsigned int enforcer_zone_next_change(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->next_change;
}

unsigned int enforcer_zone_ttl_end_ds(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->ttl_end_ds;
}

unsigned int enforcer_zone_ttl_end_dk(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->ttl_end_dk;
}

unsigned int enforcer_zone_ttl_end_rs(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->ttl_end_rs;
}

unsigned int enforcer_zone_roll_ksk_now(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->roll_ksk_now;
}

unsigned int enforcer_zone_roll_zsk_now(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->roll_zsk_now;
}

unsigned int enforcer_zone_roll_csk_now(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->roll_csk_now;
}

int enforcer_zone_adapters(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->adapters;
}

unsigned int enforcer_zone_next_ksk_roll(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->next_ksk_roll;
}

unsigned int enforcer_zone_next_zsk_roll(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->next_zsk_roll;
}

unsigned int enforcer_zone_next_csk_roll(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return 0;
    }

    return enforcer_zone->next_csk_roll;
}

int enforcer_zone_set_name(enforcer_zone_t* enforcer_zone, const char* name_text) {
    char* new_name;

    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!name_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_name = strdup(name_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (enforcer_zone->name) {
        free(enforcer_zone->name);
    }
    enforcer_zone->name = new_name;

    return DB_OK;
}

int enforcer_zone_set_policy(enforcer_zone_t* enforcer_zone, const char* policy_text) {
    char* new_policy;

    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_policy = strdup(policy_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (enforcer_zone->policy) {
        free(enforcer_zone->policy);
    }
    enforcer_zone->policy = new_policy;

    return DB_OK;
}

int enforcer_zone_set_signconf_needs_writing(enforcer_zone_t* enforcer_zone, unsigned int signconf_needs_writing) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone->signconf_needs_writing = signconf_needs_writing;

    return DB_OK;
}

int enforcer_zone_set_signconf_path(enforcer_zone_t* enforcer_zone, const char* signconf_path_text) {
    char* new_signconf_path;

    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!signconf_path_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_signconf_path = strdup(signconf_path_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (enforcer_zone->signconf_path) {
        free(enforcer_zone->signconf_path);
    }
    enforcer_zone->signconf_path = new_signconf_path;

    return DB_OK;
}

int enforcer_zone_set_next_change(enforcer_zone_t* enforcer_zone, unsigned int next_change) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone->next_change = next_change;

    return DB_OK;
}

int enforcer_zone_set_ttl_end_ds(enforcer_zone_t* enforcer_zone, unsigned int ttl_end_ds) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone->ttl_end_ds = ttl_end_ds;

    return DB_OK;
}

int enforcer_zone_set_ttl_end_dk(enforcer_zone_t* enforcer_zone, unsigned int ttl_end_dk) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone->ttl_end_dk = ttl_end_dk;

    return DB_OK;
}

int enforcer_zone_set_ttl_end_rs(enforcer_zone_t* enforcer_zone, unsigned int ttl_end_rs) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone->ttl_end_rs = ttl_end_rs;

    return DB_OK;
}

int enforcer_zone_set_roll_ksk_now(enforcer_zone_t* enforcer_zone, unsigned int roll_ksk_now) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone->roll_ksk_now = roll_ksk_now;

    return DB_OK;
}

int enforcer_zone_set_roll_zsk_now(enforcer_zone_t* enforcer_zone, unsigned int roll_zsk_now) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone->roll_zsk_now = roll_zsk_now;

    return DB_OK;
}

int enforcer_zone_set_roll_csk_now(enforcer_zone_t* enforcer_zone, unsigned int roll_csk_now) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone->roll_csk_now = roll_csk_now;

    return DB_OK;
}

int enforcer_zone_set_adapters(enforcer_zone_t* enforcer_zone, int adapters) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone->adapters = adapters;

    return DB_OK;
}

int enforcer_zone_set_next_ksk_roll(enforcer_zone_t* enforcer_zone, unsigned int next_ksk_roll) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone->next_ksk_roll = next_ksk_roll;

    return DB_OK;
}

int enforcer_zone_set_next_zsk_roll(enforcer_zone_t* enforcer_zone, unsigned int next_zsk_roll) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone->next_zsk_roll = next_zsk_roll;

    return DB_OK;
}

int enforcer_zone_set_next_csk_roll(enforcer_zone_t* enforcer_zone, unsigned int next_csk_roll) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone->next_csk_roll = next_csk_roll;

    return DB_OK;
}

int enforcer_zone_create(enforcer_zone_t* enforcer_zone) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!enforcer_zone->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (enforcer_zone->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

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
        || db_object_field_set_name(object_field, "policy")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signconf_needs_writing")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signconf_path")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_change")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl_end_ds")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl_end_dk")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl_end_rs")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "roll_ksk_now")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "roll_zsk_now")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "roll_csk_now")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "adapters")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_ksk_roll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_zsk_roll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_csk_roll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(15))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_text(db_value_set_get(value_set, 0), enforcer_zone->name)
        || db_value_from_text(db_value_set_get(value_set, 1), enforcer_zone->policy)
        || db_value_from_uint32(db_value_set_get(value_set, 2), enforcer_zone->signconf_needs_writing)
        || db_value_from_text(db_value_set_get(value_set, 3), enforcer_zone->signconf_path)
        || db_value_from_uint32(db_value_set_get(value_set, 4), enforcer_zone->next_change)
        || db_value_from_uint32(db_value_set_get(value_set, 5), enforcer_zone->ttl_end_ds)
        || db_value_from_uint32(db_value_set_get(value_set, 6), enforcer_zone->ttl_end_dk)
        || db_value_from_uint32(db_value_set_get(value_set, 7), enforcer_zone->ttl_end_rs)
        || db_value_from_uint32(db_value_set_get(value_set, 8), enforcer_zone->roll_ksk_now)
        || db_value_from_uint32(db_value_set_get(value_set, 9), enforcer_zone->roll_zsk_now)
        || db_value_from_uint32(db_value_set_get(value_set, 10), enforcer_zone->roll_csk_now)
        || db_value_from_int32(db_value_set_get(value_set, 11), enforcer_zone->adapters)
        || db_value_from_uint32(db_value_set_get(value_set, 12), enforcer_zone->next_ksk_roll)
        || db_value_from_uint32(db_value_set_get(value_set, 13), enforcer_zone->next_zsk_roll)
        || db_value_from_uint32(db_value_set_get(value_set, 14), enforcer_zone->next_csk_roll))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(enforcer_zone->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int enforcer_zone_get_by_id(enforcer_zone_t* enforcer_zone, int id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!enforcer_zone->dbo) {
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

    result_list = db_object_read(enforcer_zone->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            if (db_result_list_next(result_list)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }

            enforcer_zone_from_result(enforcer_zone, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

int enforcer_zone_update(enforcer_zone_t* enforcer_zone) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!enforcer_zone->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!enforcer_zone->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

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
        || db_object_field_set_name(object_field, "policy")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signconf_needs_writing")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signconf_path")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_change")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl_end_ds")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl_end_dk")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl_end_rs")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "roll_ksk_now")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "roll_zsk_now")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "roll_csk_now")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "adapters")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_ksk_roll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_zsk_roll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_csk_roll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(15))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_text(db_value_set_get(value_set, 0), enforcer_zone->name)
        || db_value_from_text(db_value_set_get(value_set, 1), enforcer_zone->policy)
        || db_value_from_uint32(db_value_set_get(value_set, 2), enforcer_zone->signconf_needs_writing)
        || db_value_from_text(db_value_set_get(value_set, 3), enforcer_zone->signconf_path)
        || db_value_from_uint32(db_value_set_get(value_set, 4), enforcer_zone->next_change)
        || db_value_from_uint32(db_value_set_get(value_set, 5), enforcer_zone->ttl_end_ds)
        || db_value_from_uint32(db_value_set_get(value_set, 6), enforcer_zone->ttl_end_dk)
        || db_value_from_uint32(db_value_set_get(value_set, 7), enforcer_zone->ttl_end_rs)
        || db_value_from_uint32(db_value_set_get(value_set, 8), enforcer_zone->roll_ksk_now)
        || db_value_from_uint32(db_value_set_get(value_set, 9), enforcer_zone->roll_zsk_now)
        || db_value_from_uint32(db_value_set_get(value_set, 10), enforcer_zone->roll_csk_now)
        || db_value_from_int32(db_value_set_get(value_set, 11), enforcer_zone->adapters)
        || db_value_from_uint32(db_value_set_get(value_set, 12), enforcer_zone->next_ksk_roll)
        || db_value_from_uint32(db_value_set_get(value_set, 13), enforcer_zone->next_zsk_roll)
        || db_value_from_uint32(db_value_set_get(value_set, 14), enforcer_zone->next_csk_roll))
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
        || db_value_from_int32(db_clause_get_value(clause), enforcer_zone->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(enforcer_zone->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int enforcer_zone_delete(enforcer_zone_t* enforcer_zone) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!enforcer_zone->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!enforcer_zone->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), enforcer_zone->id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(enforcer_zone->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

/* ENFORCER ZONE LIST */

static mm_alloc_t __enforcer_zone_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(enforcer_zone_list_t));

enforcer_zone_list_t* enforcer_zone_list_new(const db_connection_t* connection) {
    enforcer_zone_list_t* enforcer_zone_list =
        (enforcer_zone_list_t*)mm_alloc_new0(&__enforcer_zone_list_alloc);

    if (enforcer_zone_list) {
        if (!(enforcer_zone_list->dbo = __enforcer_zone_new_object(connection))) {
            mm_alloc_delete(&__enforcer_zone_list_alloc, enforcer_zone_list);
            return NULL;
        }
    }

    return enforcer_zone_list;
}

void enforcer_zone_list_free(enforcer_zone_list_t* enforcer_zone_list) {
    if (enforcer_zone_list) {
        if (enforcer_zone_list->dbo) {
            db_object_free(enforcer_zone_list->dbo);
        }
        if (enforcer_zone_list->result_list) {
            db_result_list_free(enforcer_zone_list->result_list);
        }
        if (enforcer_zone_list->enforcer_zone) {
            enforcer_zone_free(enforcer_zone_list->enforcer_zone);
        }
        mm_alloc_delete(&__enforcer_zone_list_alloc, enforcer_zone_list);
    }
}

int enforcer_zone_list_get(enforcer_zone_list_t* enforcer_zone_list) {
    if (!enforcer_zone_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!enforcer_zone_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (enforcer_zone_list->result_list) {
        db_result_list_free(enforcer_zone_list->result_list);
    }
    if (!(enforcer_zone_list->result_list = db_object_read(enforcer_zone_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const enforcer_zone_t* enforcer_zone_list_begin(enforcer_zone_list_t* enforcer_zone_list) {
    const db_result_t* result;

    if (!enforcer_zone_list) {
        return NULL;
    }
    if (!enforcer_zone_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(enforcer_zone_list->result_list))) {
        return NULL;
    }
    if (!enforcer_zone_list->enforcer_zone) {
        if (!(enforcer_zone_list->enforcer_zone = enforcer_zone_new(db_object_connection(enforcer_zone_list->dbo)))) {
            return NULL;
        }
    }
    if (enforcer_zone_from_result(enforcer_zone_list->enforcer_zone, result)) {
        return NULL;
    }
    return enforcer_zone_list->enforcer_zone;
}

const enforcer_zone_t* enforcer_zone_list_next(enforcer_zone_list_t* enforcer_zone_list) {
    const db_result_t* result;

    if (!enforcer_zone_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(enforcer_zone_list->result_list))) {
        return NULL;
    }
    if (!enforcer_zone_list->enforcer_zone) {
        if (!(enforcer_zone_list->enforcer_zone = enforcer_zone_new(db_object_connection(enforcer_zone_list->dbo)))) {
            return NULL;
        }
    }
    if (enforcer_zone_from_result(enforcer_zone_list->enforcer_zone, result)) {
        return NULL;
    }
    return enforcer_zone_list->enforcer_zone;
}

