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

#include <stdlib.h>

db_object_t* __enforcer_zone_new_object(const db_connection_t* connection) {
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
        || db_object_field_set_type(object_field, DB_TYPE_STRING)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "policy")
        || db_object_field_set_type(object_field, DB_TYPE_STRING)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signconf_needs_writing")
        || db_object_field_set_type(object_field, DB_TYPE_INTEGER)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signconf_path")
        || db_object_field_set_type(object_field, DB_TYPE_STRING)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_change")
        || db_object_field_set_type(object_field, DB_TYPE_INTEGER)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl_end_ds")
        || db_object_field_set_type(object_field, DB_TYPE_INTEGER)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl_end_dk")
        || db_object_field_set_type(object_field, DB_TYPE_INTEGER)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttl_end_rs")
        || db_object_field_set_type(object_field, DB_TYPE_INTEGER)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "roll_ksk_now")
        || db_object_field_set_type(object_field, DB_TYPE_INTEGER)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "roll_zsk_now")
        || db_object_field_set_type(object_field, DB_TYPE_INTEGER)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "roll_csk_now")
        || db_object_field_set_type(object_field, DB_TYPE_INTEGER)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "adapters")
        || db_object_field_set_type(object_field, DB_TYPE_INTEGER)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_ksk_roll")
        || db_object_field_set_type(object_field, DB_TYPE_INTEGER)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_zsk_roll")
        || db_object_field_set_type(object_field, DB_TYPE_INTEGER)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "next_csk_roll")
        || db_object_field_set_type(object_field, DB_TYPE_INTEGER)
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

mm_alloc_t __enforcer_zone_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(enforcer_zone_t));

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

int enforcer_zone_from_result(enforcer_zone_t* enforcer_zone, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    enforcer_zone_reset(enforcer_zone);
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 16
        || db_value_to_int(db_value_set_get(value_set, 0), &(enforcer_zone->id))
        || db_value_to_string(db_value_set_get(value_set, 1), &(enforcer_zone->name))
        || db_value_to_string(db_value_set_get(value_set, 2), &(enforcer_zone->policy))
        || db_value_to_int(db_value_set_get(value_set, 3), &(enforcer_zone->signconf_needs_writing))
        || db_value_to_string(db_value_set_get(value_set, 4), &(enforcer_zone->signconf_path))
        || db_value_to_int(db_value_set_get(value_set, 5), &(enforcer_zone->next_change))
        || db_value_to_int(db_value_set_get(value_set, 6), &(enforcer_zone->ttl_end_ds))
        || db_value_to_int(db_value_set_get(value_set, 7), &(enforcer_zone->ttl_end_dk))
        || db_value_to_int(db_value_set_get(value_set, 8), &(enforcer_zone->ttl_end_rs))
        || db_value_to_int(db_value_set_get(value_set, 9), &(enforcer_zone->roll_ksk_now))
        || db_value_to_int(db_value_set_get(value_set, 10), &(enforcer_zone->roll_zsk_now))
        || db_value_to_int(db_value_set_get(value_set, 11), &(enforcer_zone->roll_csk_now))
        || db_value_to_int(db_value_set_get(value_set, 12), &(enforcer_zone->adapters))
        || db_value_to_int(db_value_set_get(value_set, 13), &(enforcer_zone->next_ksk_roll))
        || db_value_to_int(db_value_set_get(value_set, 14), &(enforcer_zone->next_zsk_roll))
        || db_value_to_int(db_value_set_get(value_set, 15), &(enforcer_zone->next_csk_roll)))
    {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

int enforcer_zone_id(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
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

int enforcer_zone_signconf_needs_writing(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    return enforcer_zone->signconf_needs_writing;
}

const char* enforcer_zone_signconf_path(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return NULL;
    }

    return enforcer_zone->signconf_path;
}

int enforcer_zone_next_change(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    return enforcer_zone->next_change;
}

int enforcer_zone_ttl_end_ds(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    return enforcer_zone->ttl_end_ds;
}

int enforcer_zone_ttl_end_dk(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    return enforcer_zone->ttl_end_dk;
}

int enforcer_zone_ttl_end_rs(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    return enforcer_zone->ttl_end_rs;
}

int enforcer_zone_roll_ksk_now(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    return enforcer_zone->roll_ksk_now;
}

int enforcer_zone_roll_zsk_now(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    return enforcer_zone->roll_zsk_now;
}

int enforcer_zone_roll_csk_now(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    return enforcer_zone->roll_csk_now;
}

int enforcer_zone_next_ksk_roll(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    return enforcer_zone->next_ksk_roll;
}

int enforcer_zone_next_zsk_roll(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    return enforcer_zone->next_zsk_roll;
}

int enforcer_zone_next_csk_roll(const enforcer_zone_t* enforcer_zone) {
    if (!enforcer_zone) {
        return DB_ERROR_UNKNOWN;
    }

    return enforcer_zone->next_csk_roll;
}

key_data_list_t* enforcer_zone_get_keys(const enforcer_zone_t* enforcer_zone) {
    key_data_list_t* key_data_list;

    if (!enforcer_zone) {
        return NULL;
    }
    if (!enforcer_zone->dbo) {
        return NULL;
    }
    if (!enforcer_zone->id) {
        return NULL;
    }

    key_data_list = key_data_list_new(db_object_connection(enforcer_zone->dbo));
    if (key_data_list) {
        if (key_data_list_get_by_enforcer_zone_id(key_data_list, enforcer_zone->id)) {
            key_data_list_free(key_data_list);
            return NULL;
        }
    }
    return key_data_list;
}

adapter_list_t* enforcer_zone_get_adapters(const enforcer_zone_t* enforcer_zone) {
    return NULL;
}

key_dependency_list_t* enforcer_zone_get_key_dependencies(const enforcer_zone_t* enforcer_zone) {
    return NULL;
}

/* ENFORCER ZONE LIST */

mm_alloc_t __enforcer_zone_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(enforcer_zone_list_t));

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
    if (!enforcer_zone_list) {
        return NULL;
    }
    if (!enforcer_zone_list->result_list) {
        return NULL;
    }

    if (!(enforcer_zone_list->result = db_result_list_begin(enforcer_zone_list->result_list))) {
        return NULL;
    }
    if (!enforcer_zone_list->enforcer_zone) {
        if (!(enforcer_zone_list->enforcer_zone = enforcer_zone_new(db_object_connection(enforcer_zone_list->dbo)))) {
            return NULL;
        }
    }
    if (enforcer_zone_from_result(enforcer_zone_list->enforcer_zone, enforcer_zone_list->result)) {
        return NULL;
    }
    return enforcer_zone_list->enforcer_zone;
}

const enforcer_zone_t* enforcer_zone_list_next(enforcer_zone_list_t* enforcer_zone_list) {
    if (!enforcer_zone_list) {
        return NULL;
    }
    if (!enforcer_zone_list->result) {
        return NULL;
    }

    if (!(enforcer_zone_list->result = db_result_next(enforcer_zone_list->result))) {
        return NULL;
    }
    if (!enforcer_zone_list->enforcer_zone) {
        if (!(enforcer_zone_list->enforcer_zone = enforcer_zone_new(db_object_connection(enforcer_zone_list->dbo)))) {
            return NULL;
        }
    }
    if (enforcer_zone_from_result(enforcer_zone_list->enforcer_zone, enforcer_zone_list->result)) {
        return NULL;
    }
    return enforcer_zone_list->enforcer_zone;
}
