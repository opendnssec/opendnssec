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

#include "zone.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/**
 * Create a new zone object.
 * \param[in] connection a db_connection_t pointer.
 * \return a zone_t pointer or NULL on error.
 */
static db_object_t* __zone_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "zone")
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
        || db_object_field_set_name(object_field, "rev")
        || db_object_field_set_type(object_field, DB_TYPE_REVISION)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "policyId")
        || db_object_field_set_type(object_field, DB_TYPE_ANY)
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
        || db_object_field_set_name(object_field, "signconfNeedsWriting")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signconfPath")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nextChange")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttlEndDs")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttlEndDk")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttlEndRs")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rollKskNow")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rollZskNow")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rollCskNow")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "inputAdapterType")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "inputAdapterUri")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "outputAdapterType")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "outputAdapterUri")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nextKskRoll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nextZskRoll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nextCskRoll")
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

/* ZONE */

static mm_alloc_t __zone_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(zone_t));

zone_t* zone_new(const db_connection_t* connection) {
    zone_t* zone =
        (zone_t*)mm_alloc_new0(&__zone_alloc);

    if (zone) {
        if (!(zone->dbo = __zone_new_object(connection))) {
            mm_alloc_delete(&__zone_alloc, zone);
            return NULL;
        }
        db_value_reset(&(zone->id));
        db_value_reset(&(zone->rev));
        db_value_reset(&(zone->policy_id));
        zone->input_adapter_type = strdup("File");
        zone->output_adapter_type = strdup("File");
    }

    return zone;
}

zone_t* zone_new_copy(const zone_t* zone) {
    zone_t* new_zone;

    if (!zone) {
        return NULL;
    }
    if (!zone->dbo) {
        return NULL;
    }

    if (!(new_zone = zone_new(db_object_connection(zone->dbo)))
        || zone_copy(new_zone, zone))
    {
        zone_free(new_zone);
        return NULL;
    }
    return new_zone;
}

void zone_free(zone_t* zone) {
    if (zone) {
        if (zone->dbo) {
            db_object_free(zone->dbo);
        }
        db_value_reset(&(zone->id));
        db_value_reset(&(zone->rev));
        db_value_reset(&(zone->policy_id));
        if (zone->name) {
            free(zone->name);
        }
        if (zone->signconf_path) {
            free(zone->signconf_path);
        }
        if (zone->input_adapter_type) {
            free(zone->input_adapter_type);
        }
        if (zone->input_adapter_uri) {
            free(zone->input_adapter_uri);
        }
        if (zone->output_adapter_type) {
            free(zone->output_adapter_type);
        }
        if (zone->output_adapter_uri) {
            free(zone->output_adapter_uri);
        }
        mm_alloc_delete(&__zone_alloc, zone);
    }
}

void zone_reset(zone_t* zone) {
    if (zone) {
        db_value_reset(&(zone->id));
        db_value_reset(&(zone->rev));
        db_value_reset(&(zone->policy_id));
        if (zone->name) {
            free(zone->name);
            zone->name = NULL;
        }
        zone->signconf_needs_writing = 0;
        if (zone->signconf_path) {
            free(zone->signconf_path);
            zone->signconf_path = NULL;
        }
        zone->next_change = 0;
        zone->ttl_end_ds = 0;
        zone->ttl_end_dk = 0;
        zone->ttl_end_rs = 0;
        zone->roll_ksk_now = 0;
        zone->roll_zsk_now = 0;
        zone->roll_csk_now = 0;
        if (zone->input_adapter_type) {
            free(zone->input_adapter_type);
        }
        zone->input_adapter_type = strdup("File");
        if (zone->input_adapter_uri) {
            free(zone->input_adapter_uri);
            zone->input_adapter_uri = NULL;
        }
        if (zone->output_adapter_type) {
            free(zone->output_adapter_type);
        }
        zone->output_adapter_type = strdup("File");
        if (zone->output_adapter_uri) {
            free(zone->output_adapter_uri);
            zone->output_adapter_uri = NULL;
        }
        zone->next_ksk_roll = 0;
        zone->next_zsk_roll = 0;
        zone->next_csk_roll = 0;
    }
}

int zone_copy(zone_t* zone, const zone_t* zone_copy) {
    char* name_text = NULL;
    char* signconf_path_text = NULL;
    char* input_adapter_type_text = NULL;
    char* input_adapter_uri_text = NULL;
    char* output_adapter_type_text = NULL;
    char* output_adapter_uri_text = NULL;
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone_copy) {
        return DB_ERROR_UNKNOWN;
    }

    if (zone_copy->name) {
        if (!(name_text = strdup(zone_copy->name))) {
            return DB_ERROR_UNKNOWN;
        }
    }
    if (zone_copy->signconf_path) {
        if (!(signconf_path_text = strdup(zone_copy->signconf_path))) {
            if (name_text) {
                free(name_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (zone_copy->input_adapter_type) {
        if (!(input_adapter_type_text = strdup(zone_copy->input_adapter_type))) {
            if (name_text) {
                free(name_text);
            }
            if (signconf_path_text) {
                free(signconf_path_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (zone_copy->input_adapter_uri) {
        if (!(input_adapter_uri_text = strdup(zone_copy->input_adapter_uri))) {
            if (name_text) {
                free(name_text);
            }
            if (signconf_path_text) {
                free(signconf_path_text);
            }
            if (input_adapter_type_text) {
                free(input_adapter_type_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (zone_copy->output_adapter_type) {
        if (!(output_adapter_type_text = strdup(zone_copy->output_adapter_type))) {
            if (name_text) {
                free(name_text);
            }
            if (signconf_path_text) {
                free(signconf_path_text);
            }
            if (input_adapter_type_text) {
                free(input_adapter_type_text);
            }
            if (input_adapter_uri_text) {
                free(input_adapter_uri_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (zone_copy->output_adapter_uri) {
        if (!(output_adapter_uri_text = strdup(zone_copy->output_adapter_uri))) {
            if (name_text) {
                free(name_text);
            }
            if (signconf_path_text) {
                free(signconf_path_text);
            }
            if (input_adapter_type_text) {
                free(input_adapter_type_text);
            }
            if (input_adapter_uri_text) {
                free(input_adapter_uri_text);
            }
            if (output_adapter_type_text) {
                free(output_adapter_type_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (db_value_copy(&(zone->id), &(zone_copy->id))) {
        if (name_text) {
            free(name_text);
        }
        if (signconf_path_text) {
            free(signconf_path_text);
        }
        if (input_adapter_type_text) {
            free(input_adapter_type_text);
        }
        if (input_adapter_uri_text) {
            free(input_adapter_uri_text);
        }
        if (output_adapter_type_text) {
            free(output_adapter_type_text);
        }
        if (output_adapter_uri_text) {
            free(output_adapter_uri_text);
        }
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_copy(&(zone->rev), &(zone_copy->rev))) {
        if (name_text) {
            free(name_text);
        }
        if (signconf_path_text) {
            free(signconf_path_text);
        }
        if (input_adapter_type_text) {
            free(input_adapter_type_text);
        }
        if (input_adapter_uri_text) {
            free(input_adapter_uri_text);
        }
        if (output_adapter_type_text) {
            free(output_adapter_type_text);
        }
        if (output_adapter_uri_text) {
            free(output_adapter_uri_text);
        }
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_copy(&(zone->policy_id), &(zone_copy->policy_id))) {
        if (name_text) {
            free(name_text);
        }
        if (signconf_path_text) {
            free(signconf_path_text);
        }
        if (input_adapter_type_text) {
            free(input_adapter_type_text);
        }
        if (input_adapter_uri_text) {
            free(input_adapter_uri_text);
        }
        if (output_adapter_type_text) {
            free(output_adapter_type_text);
        }
        if (output_adapter_uri_text) {
            free(output_adapter_uri_text);
        }
        return DB_ERROR_UNKNOWN;
    }
    if (zone->name) {
        free(zone->name);
    }
    zone->name = name_text;
    zone->signconf_needs_writing = zone_copy->signconf_needs_writing;
    if (zone->signconf_path) {
        free(zone->signconf_path);
    }
    zone->signconf_path = signconf_path_text;
    zone->next_change = zone_copy->next_change;
    zone->ttl_end_ds = zone_copy->ttl_end_ds;
    zone->ttl_end_dk = zone_copy->ttl_end_dk;
    zone->ttl_end_rs = zone_copy->ttl_end_rs;
    zone->roll_ksk_now = zone_copy->roll_ksk_now;
    zone->roll_zsk_now = zone_copy->roll_zsk_now;
    zone->roll_csk_now = zone_copy->roll_csk_now;
    if (zone->input_adapter_type) {
        free(zone->input_adapter_type);
    }
    zone->input_adapter_type = input_adapter_type_text;
    if (zone->input_adapter_uri) {
        free(zone->input_adapter_uri);
    }
    zone->input_adapter_uri = input_adapter_uri_text;
    if (zone->output_adapter_type) {
        free(zone->output_adapter_type);
    }
    zone->output_adapter_type = output_adapter_type_text;
    if (zone->output_adapter_uri) {
        free(zone->output_adapter_uri);
    }
    zone->output_adapter_uri = output_adapter_uri_text;
    zone->next_ksk_roll = zone_copy->next_ksk_roll;
    zone->next_zsk_roll = zone_copy->next_zsk_roll;
    zone->next_csk_roll = zone_copy->next_csk_roll;
    return DB_OK;
}

int zone_cmp(const zone_t* zone_a, const zone_t* zone_b) {
    int ret;

    if (!zone_a && !zone_b) {
        return 0;
    }
    if (!zone_a && zone_b) {
        return -1;
    }
    if (zone_a && !zone_b) {
        return 1;
    }

    ret = 0;
    db_value_cmp(&(zone_a->policy_id), &(zone_b->policy_id), &ret);
    if (ret) {
        return ret;
    }

    if (zone_a->name && zone_b->name) {
        if ((ret = strcmp(zone_a->name, zone_b->name))) {
            return ret;
        }
    }
    else {
        if (!zone_a->name && zone_b->name) {
            return -1;
        }
        if (zone_a->name && !zone_b->name) {
            return -1;
        }
    }

    if (zone_a->signconf_needs_writing != zone_b->signconf_needs_writing) {
        return zone_a->signconf_needs_writing < zone_b->signconf_needs_writing ? -1 : 1;
    }

    if (zone_a->signconf_path && zone_b->signconf_path) {
        if ((ret = strcmp(zone_a->signconf_path, zone_b->signconf_path))) {
            return ret;
        }
    }
    else {
        if (!zone_a->signconf_path && zone_b->signconf_path) {
            return -1;
        }
        if (zone_a->signconf_path && !zone_b->signconf_path) {
            return -1;
        }
    }

    if (zone_a->next_change != zone_b->next_change) {
        return zone_a->next_change < zone_b->next_change ? -1 : 1;
    }

    if (zone_a->ttl_end_ds != zone_b->ttl_end_ds) {
        return zone_a->ttl_end_ds < zone_b->ttl_end_ds ? -1 : 1;
    }

    if (zone_a->ttl_end_dk != zone_b->ttl_end_dk) {
        return zone_a->ttl_end_dk < zone_b->ttl_end_dk ? -1 : 1;
    }

    if (zone_a->ttl_end_rs != zone_b->ttl_end_rs) {
        return zone_a->ttl_end_rs < zone_b->ttl_end_rs ? -1 : 1;
    }

    if (zone_a->roll_ksk_now != zone_b->roll_ksk_now) {
        return zone_a->roll_ksk_now < zone_b->roll_ksk_now ? -1 : 1;
    }

    if (zone_a->roll_zsk_now != zone_b->roll_zsk_now) {
        return zone_a->roll_zsk_now < zone_b->roll_zsk_now ? -1 : 1;
    }

    if (zone_a->roll_csk_now != zone_b->roll_csk_now) {
        return zone_a->roll_csk_now < zone_b->roll_csk_now ? -1 : 1;
    }

    if (zone_a->input_adapter_type && zone_b->input_adapter_type) {
        if ((ret = strcmp(zone_a->input_adapter_type, zone_b->input_adapter_type))) {
            return ret;
        }
    }
    else {
        if (!zone_a->input_adapter_type && zone_b->input_adapter_type) {
            return -1;
        }
        if (zone_a->input_adapter_type && !zone_b->input_adapter_type) {
            return -1;
        }
    }

    if (zone_a->input_adapter_uri && zone_b->input_adapter_uri) {
        if ((ret = strcmp(zone_a->input_adapter_uri, zone_b->input_adapter_uri))) {
            return ret;
        }
    }
    else {
        if (!zone_a->input_adapter_uri && zone_b->input_adapter_uri) {
            return -1;
        }
        if (zone_a->input_adapter_uri && !zone_b->input_adapter_uri) {
            return -1;
        }
    }

    if (zone_a->output_adapter_type && zone_b->output_adapter_type) {
        if ((ret = strcmp(zone_a->output_adapter_type, zone_b->output_adapter_type))) {
            return ret;
        }
    }
    else {
        if (!zone_a->output_adapter_type && zone_b->output_adapter_type) {
            return -1;
        }
        if (zone_a->output_adapter_type && !zone_b->output_adapter_type) {
            return -1;
        }
    }

    if (zone_a->output_adapter_uri && zone_b->output_adapter_uri) {
        if ((ret = strcmp(zone_a->output_adapter_uri, zone_b->output_adapter_uri))) {
            return ret;
        }
    }
    else {
        if (!zone_a->output_adapter_uri && zone_b->output_adapter_uri) {
            return -1;
        }
        if (zone_a->output_adapter_uri && !zone_b->output_adapter_uri) {
            return -1;
        }
    }

    if (zone_a->next_ksk_roll != zone_b->next_ksk_roll) {
        return zone_a->next_ksk_roll < zone_b->next_ksk_roll ? -1 : 1;
    }

    if (zone_a->next_zsk_roll != zone_b->next_zsk_roll) {
        return zone_a->next_zsk_roll < zone_b->next_zsk_roll ? -1 : 1;
    }

    if (zone_a->next_csk_roll != zone_b->next_csk_roll) {
        return zone_a->next_csk_roll < zone_b->next_csk_roll ? -1 : 1;
    }
    return 0;
}

int zone_from_result(zone_t* zone, const db_result_t* result) {
    const db_value_set_t* value_set;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(zone->id));
    db_value_reset(&(zone->rev));
    db_value_reset(&(zone->policy_id));
    if (zone->name) {
        free(zone->name);
    }
    zone->name = NULL;
    if (zone->signconf_path) {
        free(zone->signconf_path);
    }
    zone->signconf_path = NULL;
    if (zone->input_adapter_type) {
        free(zone->input_adapter_type);
    }
    zone->input_adapter_type = NULL;
    if (zone->input_adapter_uri) {
        free(zone->input_adapter_uri);
    }
    zone->input_adapter_uri = NULL;
    if (zone->output_adapter_type) {
        free(zone->output_adapter_type);
    }
    zone->output_adapter_type = NULL;
    if (zone->output_adapter_uri) {
        free(zone->output_adapter_uri);
    }
    zone->output_adapter_uri = NULL;
    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 20
        || db_value_copy(&(zone->id), db_value_set_at(value_set, 0))
        || db_value_copy(&(zone->rev), db_value_set_at(value_set, 1))
        || db_value_copy(&(zone->policy_id), db_value_set_at(value_set, 2))
        || db_value_to_text(db_value_set_at(value_set, 3), &(zone->name))
        || db_value_to_uint32(db_value_set_at(value_set, 4), &(zone->signconf_needs_writing))
        || db_value_to_text(db_value_set_at(value_set, 5), &(zone->signconf_path))
        || db_value_to_int32(db_value_set_at(value_set, 6), &(zone->next_change))
        || db_value_to_uint32(db_value_set_at(value_set, 7), &(zone->ttl_end_ds))
        || db_value_to_uint32(db_value_set_at(value_set, 8), &(zone->ttl_end_dk))
        || db_value_to_uint32(db_value_set_at(value_set, 9), &(zone->ttl_end_rs))
        || db_value_to_uint32(db_value_set_at(value_set, 10), &(zone->roll_ksk_now))
        || db_value_to_uint32(db_value_set_at(value_set, 11), &(zone->roll_zsk_now))
        || db_value_to_uint32(db_value_set_at(value_set, 12), &(zone->roll_csk_now))
        || db_value_to_text(db_value_set_at(value_set, 13), &(zone->input_adapter_type))
        || db_value_to_text(db_value_set_at(value_set, 14), &(zone->input_adapter_uri))
        || db_value_to_text(db_value_set_at(value_set, 15), &(zone->output_adapter_type))
        || db_value_to_text(db_value_set_at(value_set, 16), &(zone->output_adapter_uri))
        || db_value_to_uint32(db_value_set_at(value_set, 17), &(zone->next_ksk_roll))
        || db_value_to_uint32(db_value_set_at(value_set, 18), &(zone->next_zsk_roll))
        || db_value_to_uint32(db_value_set_at(value_set, 19), &(zone->next_csk_roll)))
    {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

const db_value_t* zone_id(const zone_t* zone) {
    if (!zone) {
        return NULL;
    }

    return &(zone->id);
}

const db_value_t* zone_policy_id(const zone_t* zone) {
    if (!zone) {
        return NULL;
    }

    return &(zone->policy_id);
}

policy_t* zone_get_policy(const zone_t* zone) {
    policy_t* policy_id = NULL;

    if (!zone) {
        return NULL;
    }
    if (!zone->dbo) {
        return NULL;
    }
    if (db_value_not_empty(&(zone->policy_id))) {
        return NULL;
    }

    if (!(policy_id = policy_new(db_object_connection(zone->dbo)))) {
        return NULL;
    }
    if (policy_get_by_id(policy_id, &(zone->policy_id))) {
        policy_free(policy_id);
        return NULL;
    }

    return policy_id;
}

const char* zone_name(const zone_t* zone) {
    if (!zone) {
        return NULL;
    }

    return zone->name;
}

unsigned int zone_signconf_needs_writing(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->signconf_needs_writing;
}

const char* zone_signconf_path(const zone_t* zone) {
    if (!zone) {
        return NULL;
    }

    return zone->signconf_path;
}

int zone_next_change(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->next_change;
}

unsigned int zone_ttl_end_ds(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->ttl_end_ds;
}

unsigned int zone_ttl_end_dk(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->ttl_end_dk;
}

unsigned int zone_ttl_end_rs(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->ttl_end_rs;
}

unsigned int zone_roll_ksk_now(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->roll_ksk_now;
}

unsigned int zone_roll_zsk_now(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->roll_zsk_now;
}

unsigned int zone_roll_csk_now(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->roll_csk_now;
}

const char* zone_input_adapter_type(const zone_t* zone) {
    if (!zone) {
        return NULL;
    }

    return zone->input_adapter_type;
}

const char* zone_input_adapter_uri(const zone_t* zone) {
    if (!zone) {
        return NULL;
    }

    return zone->input_adapter_uri;
}

const char* zone_output_adapter_type(const zone_t* zone) {
    if (!zone) {
        return NULL;
    }

    return zone->output_adapter_type;
}

const char* zone_output_adapter_uri(const zone_t* zone) {
    if (!zone) {
        return NULL;
    }

    return zone->output_adapter_uri;
}

unsigned int zone_next_ksk_roll(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->next_ksk_roll;
}

unsigned int zone_next_zsk_roll(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->next_zsk_roll;
}

unsigned int zone_next_csk_roll(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->next_csk_roll;
}

int zone_set_policy_id(zone_t* zone, const db_value_t* policy_id) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_id) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(policy_id)) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(zone->policy_id));
    if (db_value_copy(&(zone->policy_id), policy_id)) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int zone_set_name(zone_t* zone, const char* name_text) {
    char* new_name;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!name_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_name = strdup(name_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (zone->name) {
        free(zone->name);
    }
    zone->name = new_name;

    return DB_OK;
}

int zone_set_signconf_needs_writing(zone_t* zone, unsigned int signconf_needs_writing) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->signconf_needs_writing = signconf_needs_writing;

    return DB_OK;
}

int zone_set_signconf_path(zone_t* zone, const char* signconf_path_text) {
    char* new_signconf_path;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!signconf_path_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_signconf_path = strdup(signconf_path_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (zone->signconf_path) {
        free(zone->signconf_path);
    }
    zone->signconf_path = new_signconf_path;

    return DB_OK;
}

int zone_set_next_change(zone_t* zone, int next_change) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->next_change = next_change;

    return DB_OK;
}

int zone_set_ttl_end_ds(zone_t* zone, unsigned int ttl_end_ds) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->ttl_end_ds = ttl_end_ds;

    return DB_OK;
}

int zone_set_ttl_end_dk(zone_t* zone, unsigned int ttl_end_dk) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->ttl_end_dk = ttl_end_dk;

    return DB_OK;
}

int zone_set_ttl_end_rs(zone_t* zone, unsigned int ttl_end_rs) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->ttl_end_rs = ttl_end_rs;

    return DB_OK;
}

int zone_set_roll_ksk_now(zone_t* zone, unsigned int roll_ksk_now) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->roll_ksk_now = roll_ksk_now;

    return DB_OK;
}

int zone_set_roll_zsk_now(zone_t* zone, unsigned int roll_zsk_now) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->roll_zsk_now = roll_zsk_now;

    return DB_OK;
}

int zone_set_roll_csk_now(zone_t* zone, unsigned int roll_csk_now) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->roll_csk_now = roll_csk_now;

    return DB_OK;
}

int zone_set_input_adapter_type(zone_t* zone, const char* input_adapter_type_text) {
    char* new_input_adapter_type;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!input_adapter_type_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_input_adapter_type = strdup(input_adapter_type_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (zone->input_adapter_type) {
        free(zone->input_adapter_type);
    }
    zone->input_adapter_type = new_input_adapter_type;

    return DB_OK;
}

int zone_set_input_adapter_uri(zone_t* zone, const char* input_adapter_uri_text) {
    char* new_input_adapter_uri;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!input_adapter_uri_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_input_adapter_uri = strdup(input_adapter_uri_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (zone->input_adapter_uri) {
        free(zone->input_adapter_uri);
    }
    zone->input_adapter_uri = new_input_adapter_uri;

    return DB_OK;
}

int zone_set_output_adapter_type(zone_t* zone, const char* output_adapter_type_text) {
    char* new_output_adapter_type;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!output_adapter_type_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_output_adapter_type = strdup(output_adapter_type_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (zone->output_adapter_type) {
        free(zone->output_adapter_type);
    }
    zone->output_adapter_type = new_output_adapter_type;

    return DB_OK;
}

int zone_set_output_adapter_uri(zone_t* zone, const char* output_adapter_uri_text) {
    char* new_output_adapter_uri;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!output_adapter_uri_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_output_adapter_uri = strdup(output_adapter_uri_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (zone->output_adapter_uri) {
        free(zone->output_adapter_uri);
    }
    zone->output_adapter_uri = new_output_adapter_uri;

    return DB_OK;
}

int zone_set_next_ksk_roll(zone_t* zone, unsigned int next_ksk_roll) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->next_ksk_roll = next_ksk_roll;

    return DB_OK;
}

int zone_set_next_zsk_roll(zone_t* zone, unsigned int next_zsk_roll) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->next_zsk_roll = next_zsk_roll;

    return DB_OK;
}

int zone_set_next_csk_roll(zone_t* zone, unsigned int next_csk_roll) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->next_csk_roll = next_csk_roll;

    return DB_OK;
}

db_clause_t* zone_policy_id_clause(db_clause_list_t* clause_list, const db_value_t* policy_id) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!policy_id) {
        return NULL;
    }
    if (db_value_not_empty(policy_id)) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "policyId")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_copy(db_clause_get_value(clause), policy_id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_name_clause(db_clause_list_t* clause_list, const char* name_text) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!name_text) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "name")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_text(db_clause_get_value(clause), name_text)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_signconf_needs_writing_clause(db_clause_list_t* clause_list, unsigned int signconf_needs_writing) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "signconfNeedsWriting")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), signconf_needs_writing)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_signconf_path_clause(db_clause_list_t* clause_list, const char* signconf_path_text) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!signconf_path_text) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "signconfPath")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_text(db_clause_get_value(clause), signconf_path_text)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_next_change_clause(db_clause_list_t* clause_list, int next_change) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "nextChange")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_int32(db_clause_get_value(clause), next_change)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_ttl_end_ds_clause(db_clause_list_t* clause_list, unsigned int ttl_end_ds) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "ttlEndDs")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), ttl_end_ds)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_ttl_end_dk_clause(db_clause_list_t* clause_list, unsigned int ttl_end_dk) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "ttlEndDk")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), ttl_end_dk)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_ttl_end_rs_clause(db_clause_list_t* clause_list, unsigned int ttl_end_rs) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "ttlEndRs")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), ttl_end_rs)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_roll_ksk_now_clause(db_clause_list_t* clause_list, unsigned int roll_ksk_now) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "rollKskNow")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), roll_ksk_now)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_roll_zsk_now_clause(db_clause_list_t* clause_list, unsigned int roll_zsk_now) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "rollZskNow")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), roll_zsk_now)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_roll_csk_now_clause(db_clause_list_t* clause_list, unsigned int roll_csk_now) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "rollCskNow")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), roll_csk_now)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_input_adapter_type_clause(db_clause_list_t* clause_list, const char* input_adapter_type_text) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!input_adapter_type_text) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "inputAdapterType")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_text(db_clause_get_value(clause), input_adapter_type_text)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_input_adapter_uri_clause(db_clause_list_t* clause_list, const char* input_adapter_uri_text) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!input_adapter_uri_text) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "inputAdapterUri")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_text(db_clause_get_value(clause), input_adapter_uri_text)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_output_adapter_type_clause(db_clause_list_t* clause_list, const char* output_adapter_type_text) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!output_adapter_type_text) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "outputAdapterType")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_text(db_clause_get_value(clause), output_adapter_type_text)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_output_adapter_uri_clause(db_clause_list_t* clause_list, const char* output_adapter_uri_text) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!output_adapter_uri_text) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "outputAdapterUri")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_text(db_clause_get_value(clause), output_adapter_uri_text)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_next_ksk_roll_clause(db_clause_list_t* clause_list, unsigned int next_ksk_roll) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "nextKskRoll")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), next_ksk_roll)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_next_zsk_roll_clause(db_clause_list_t* clause_list, unsigned int next_zsk_roll) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "nextZskRoll")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), next_zsk_roll)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

db_clause_t* zone_next_csk_roll_clause(db_clause_list_t* clause_list, unsigned int next_csk_roll) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "nextCskRoll")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_uint32(db_clause_get_value(clause), next_csk_roll)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

int zone_create(zone_t* zone) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!db_value_not_empty(&(zone->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (!db_value_not_empty(&(zone->rev))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(zone->policy_id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->name) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->signconf_path) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->input_adapter_type) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->input_adapter_uri) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->output_adapter_type) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->output_adapter_uri) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "policyId")
        || db_object_field_set_type(object_field, DB_TYPE_ANY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
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
        || db_object_field_set_name(object_field, "signconfNeedsWriting")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signconfPath")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nextChange")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttlEndDs")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttlEndDk")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttlEndRs")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rollKskNow")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rollZskNow")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rollCskNow")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "inputAdapterType")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "inputAdapterUri")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "outputAdapterType")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "outputAdapterUri")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nextKskRoll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nextZskRoll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nextCskRoll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(18))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_copy(db_value_set_get(value_set, 0), &(zone->policy_id))
        || db_value_from_text(db_value_set_get(value_set, 1), zone->name)
        || db_value_from_uint32(db_value_set_get(value_set, 2), zone->signconf_needs_writing)
        || db_value_from_text(db_value_set_get(value_set, 3), zone->signconf_path)
        || db_value_from_int32(db_value_set_get(value_set, 4), zone->next_change)
        || db_value_from_uint32(db_value_set_get(value_set, 5), zone->ttl_end_ds)
        || db_value_from_uint32(db_value_set_get(value_set, 6), zone->ttl_end_dk)
        || db_value_from_uint32(db_value_set_get(value_set, 7), zone->ttl_end_rs)
        || db_value_from_uint32(db_value_set_get(value_set, 8), zone->roll_ksk_now)
        || db_value_from_uint32(db_value_set_get(value_set, 9), zone->roll_zsk_now)
        || db_value_from_uint32(db_value_set_get(value_set, 10), zone->roll_csk_now)
        || db_value_from_text(db_value_set_get(value_set, 11), zone->input_adapter_type)
        || db_value_from_text(db_value_set_get(value_set, 12), zone->input_adapter_uri)
        || db_value_from_text(db_value_set_get(value_set, 13), zone->output_adapter_type)
        || db_value_from_text(db_value_set_get(value_set, 14), zone->output_adapter_uri)
        || db_value_from_uint32(db_value_set_get(value_set, 15), zone->next_ksk_roll)
        || db_value_from_uint32(db_value_set_get(value_set, 16), zone->next_zsk_roll)
        || db_value_from_uint32(db_value_set_get(value_set, 17), zone->next_csk_roll))
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_create(zone->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

int zone_get_by_id(zone_t* zone, const db_value_t* id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->dbo) {
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

    result_list = db_object_read(zone->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_next(result_list);
        if (result) {
            if (zone_from_result(zone, result)) {
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

zone_t* zone_new_get_by_id(const db_connection_t* connection, const db_value_t* id) {
    zone_t* zone;

    if (!connection) {
        return NULL;
    }
    if (!id) {
        return NULL;
    }
    if (db_value_not_empty(id)) {
        return NULL;
    }

    if (!(zone = zone_new(connection))
        || zone_get_by_id(zone, id))
    {
        zone_free(zone);
        return NULL;
    }

    return zone;
}

int zone_get_by_name(zone_t* zone, const char* name) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!name) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "name")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_text(db_clause_get_value(clause), name)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    result_list = db_object_read(zone->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_next(result_list);
        if (result) {
            if (zone_from_result(zone, result)) {
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

zone_t* zone_new_get_by_name(const db_connection_t* connection, const char* name) {
    zone_t* zone;

    if (!connection) {
        return NULL;
    }
    if (!name) {
        return NULL;
    }

    if (!(zone = zone_new(connection))
        || zone_get_by_name(zone, name))
    {
        zone_free(zone);
        return NULL;
    }

    return zone;
}

int zone_update(zone_t* zone) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(zone->id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(zone->rev))) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(zone->policy_id))) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->name) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->signconf_path) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->input_adapter_type) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->input_adapter_uri) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->output_adapter_type) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->output_adapter_uri) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "policyId")
        || db_object_field_set_type(object_field, DB_TYPE_ANY)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
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
        || db_object_field_set_name(object_field, "signconfNeedsWriting")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "signconfPath")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nextChange")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttlEndDs")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttlEndDk")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "ttlEndRs")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rollKskNow")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rollZskNow")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "rollCskNow")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "inputAdapterType")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "inputAdapterUri")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "outputAdapterType")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "outputAdapterUri")
        || db_object_field_set_type(object_field, DB_TYPE_TEXT)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nextKskRoll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nextZskRoll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "nextCskRoll")
        || db_object_field_set_type(object_field, DB_TYPE_UINT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(18))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_copy(db_value_set_get(value_set, 0), &(zone->policy_id))
        || db_value_from_text(db_value_set_get(value_set, 1), zone->name)
        || db_value_from_uint32(db_value_set_get(value_set, 2), zone->signconf_needs_writing)
        || db_value_from_text(db_value_set_get(value_set, 3), zone->signconf_path)
        || db_value_from_int32(db_value_set_get(value_set, 4), zone->next_change)
        || db_value_from_uint32(db_value_set_get(value_set, 5), zone->ttl_end_ds)
        || db_value_from_uint32(db_value_set_get(value_set, 6), zone->ttl_end_dk)
        || db_value_from_uint32(db_value_set_get(value_set, 7), zone->ttl_end_rs)
        || db_value_from_uint32(db_value_set_get(value_set, 8), zone->roll_ksk_now)
        || db_value_from_uint32(db_value_set_get(value_set, 9), zone->roll_zsk_now)
        || db_value_from_uint32(db_value_set_get(value_set, 10), zone->roll_csk_now)
        || db_value_from_text(db_value_set_get(value_set, 11), zone->input_adapter_type)
        || db_value_from_text(db_value_set_get(value_set, 12), zone->input_adapter_uri)
        || db_value_from_text(db_value_set_get(value_set, 13), zone->output_adapter_type)
        || db_value_from_text(db_value_set_get(value_set, 14), zone->output_adapter_uri)
        || db_value_from_uint32(db_value_set_get(value_set, 15), zone->next_ksk_roll)
        || db_value_from_uint32(db_value_set_get(value_set, 16), zone->next_zsk_roll)
        || db_value_from_uint32(db_value_set_get(value_set, 17), zone->next_csk_roll))
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
        || db_value_copy(db_clause_get_value(clause), &(zone->id))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "rev")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(zone->rev))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_update(zone->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int zone_delete(zone_t* zone) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(zone->id))) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(zone->id))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "rev")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(zone->rev))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    ret = db_object_delete(zone->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

int zone_count(zone_t* zone, db_clause_list_t* clause_list, size_t* count) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!count) {
        return DB_ERROR_UNKNOWN;
    }

    return db_object_count(zone->dbo, NULL, clause_list, count);
}

/* ZONE LIST */

static mm_alloc_t __zone_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(zone_list_t));

zone_list_t* zone_list_new(const db_connection_t* connection) {
    zone_list_t* zone_list =
        (zone_list_t*)mm_alloc_new0(&__zone_list_alloc);

    if (zone_list) {
        if (!(zone_list->dbo = __zone_new_object(connection))) {
            mm_alloc_delete(&__zone_list_alloc, zone_list);
            return NULL;
        }
    }

    return zone_list;
}

void zone_list_free(zone_list_t* zone_list) {
    if (zone_list) {
        if (zone_list->dbo) {
            db_object_free(zone_list->dbo);
        }
        if (zone_list->result_list) {
            db_result_list_free(zone_list->result_list);
        }
        if (zone_list->zone) {
            zone_free(zone_list->zone);
        }
        mm_alloc_delete(&__zone_list_alloc, zone_list);
    }
}

int zone_list_get(zone_list_t* zone_list) {
    if (!zone_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (zone_list->result_list) {
        db_result_list_free(zone_list->result_list);
    }
    if (!(zone_list->result_list = db_object_read(zone_list->dbo, NULL, NULL))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

zone_list_t* zone_list_new_get(const db_connection_t* connection) {
    zone_list_t* zone_list;

    if (!connection) {
        return NULL;
    }

    if (!(zone_list = zone_list_new(connection))
        || zone_list_get(zone_list))
    {
        zone_list_free(zone_list);
        return NULL;
    }

    return zone_list;
}

int zone_list_get_by_clauses(zone_list_t* zone_list, const db_clause_list_t* clause_list) {
    if (!zone_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!clause_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (zone_list->result_list) {
        db_result_list_free(zone_list->result_list);
    }
    if (!(zone_list->result_list = db_object_read(zone_list->dbo, NULL, clause_list))) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

zone_list_t* zone_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list) {
    zone_list_t* zone_list;

    if (!connection) {
        return NULL;
    }
    if (!clause_list) {
        return NULL;
    }

    if (!(zone_list = zone_list_new(connection))
        || zone_list_get_by_clauses(zone_list, clause_list))
    {
        zone_list_free(zone_list);
        return NULL;
    }

    return zone_list;
}

int zone_list_get_by_policy_id(zone_list_t* zone_list, const db_value_t* policy_id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;

    if (!zone_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!policy_id) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(policy_id)) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "policyId")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), policy_id)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    if (zone_list->result_list) {
        db_result_list_free(zone_list->result_list);
    }
    if (!(zone_list->result_list = db_object_read(zone_list->dbo, NULL, clause_list))) {
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    db_clause_list_free(clause_list);
    return DB_OK;
}

zone_list_t* zone_list_new_get_by_policy_id(const db_connection_t* connection, const db_value_t* policy_id) {
    zone_list_t* zone_list;

    if (!connection) {
        return NULL;
    }
    if (!policy_id) {
        return NULL;
    }
    if (db_value_not_empty(policy_id)) {
        return NULL;
    }

    if (!(zone_list = zone_list_new(connection))
        || zone_list_get_by_policy_id(zone_list, policy_id))
    {
        zone_list_free(zone_list);
        return NULL;
    }

    return zone_list;
}

const zone_t* zone_list_begin(zone_list_t* zone_list) {
    const db_result_t* result;

    if (!zone_list) {
        return NULL;
    }
    if (!zone_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(zone_list->result_list))) {
        return NULL;
    }
    if (!zone_list->zone) {
        if (!(zone_list->zone = zone_new(db_object_connection(zone_list->dbo)))) {
            return NULL;
        }
    }
    if (zone_from_result(zone_list->zone, result)) {
        return NULL;
    }
    return zone_list->zone;
}

zone_t* zone_list_get_begin(zone_list_t* zone_list) {
    const db_result_t* result;
    zone_t* zone;

    if (!zone_list) {
        return NULL;
    }
    if (!zone_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(zone_list->result_list))) {
        return NULL;
    }
    if (!(zone = zone_new(db_object_connection(zone_list->dbo)))) {
        return NULL;
    }
    if (zone_from_result(zone, result)) {
        zone_free(zone);
        return NULL;
    }
    return zone;
}

const zone_t* zone_list_next(zone_list_t* zone_list) {
    const db_result_t* result;

    if (!zone_list) {
        return NULL;
    }
    if (!zone_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(zone_list->result_list))) {
        return NULL;
    }
    if (!zone_list->zone) {
        if (!(zone_list->zone = zone_new(db_object_connection(zone_list->dbo)))) {
            return NULL;
        }
    }
    if (zone_from_result(zone_list->zone, result)) {
        return NULL;
    }
    return zone_list->zone;
}

zone_t* zone_list_get_next(zone_list_t* zone_list) {
    const db_result_t* result;
    zone_t* zone;

    if (!zone_list) {
        return NULL;
    }
    if (!zone_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(zone_list->result_list))) {
        return NULL;
    }
    if (!(zone = zone_new(db_object_connection(zone_list->dbo)))) {
        return NULL;
    }
    if (zone_from_result(zone, result)) {
        zone_free(zone);
        return NULL;
    }
    return zone;
}

int zone_list_fetch_all(zone_list_t* zone_list) {
    if (!zone_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone_list->result_list) {
        return DB_ERROR_UNKNOWN;
    }

    return db_result_list_fetch_all(zone_list->result_list);
}

size_t zone_list_size(zone_list_t* zone_list) {
    if (!zone_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone_list->result_list) {
        return DB_ERROR_UNKNOWN;
    }

    return db_result_list_size(zone_list->result_list);
}
