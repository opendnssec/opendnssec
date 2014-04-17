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

static const db_enum_t __enum_set_serial[] = {
    { "counter", (zone_serial_t)ZONE_SERIAL_COUNTER },
    { "datecounter", (zone_serial_t)ZONE_SERIAL_DATECOUNTER },
    { "unixtime", (zone_serial_t)ZONE_SERIAL_UNIXTIME },
    { "keep", (zone_serial_t)ZONE_SERIAL_KEEP },
    { NULL, 0 }
};

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
        || db_object_set_table(object, "Zone")
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
        || db_object_field_set_name(object_field, "propagationdelay")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
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
        || db_object_field_set_name(object_field, "min")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "serial")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_serial)
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
        zone->serial = ZONE_SERIAL_INVALID;
    }

    return zone;
}

void zone_free(zone_t* zone) {
    if (zone) {
        if (zone->dbo) {
            db_object_free(zone->dbo);
        }
        mm_alloc_delete(&__zone_alloc, zone);
    }
}

void zone_reset(zone_t* zone) {
    if (zone) {
        zone->id = 0;
        zone->propagationdelay = 0;
        zone->ttl = 0;
        zone->min = 0;
        zone->serial = ZONE_SERIAL_INVALID;
    }
}

int zone_copy(zone_t* zone, const zone_t* zone_copy) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone_copy) {
        return DB_ERROR_UNKNOWN;
    }

    zone->id = zone_copy->id;
    zone->propagationdelay = zone_copy->propagationdelay;
    zone->ttl = zone_copy->ttl;
    zone->min = zone_copy->min;
    zone->serial = zone_copy->serial;
    return DB_OK;
}

int zone_from_result(zone_t* zone, const db_result_t* result) {
    const db_value_set_t* value_set;
    int serial;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != 5
        || db_value_to_int32(db_value_set_at(value_set, 0), &(zone->id))
        || db_value_to_int32(db_value_set_at(value_set, 1), &(zone->propagationdelay))
        || db_value_to_int32(db_value_set_at(value_set, 2), &(zone->ttl))
        || db_value_to_int32(db_value_set_at(value_set, 3), &(zone->min))
        || db_value_to_enum_value(db_value_set_at(value_set, 4), &serial, __enum_set_serial))
    {
        return DB_ERROR_UNKNOWN;
    }

    if (serial == (zone_serial_t)ZONE_SERIAL_COUNTER) {
        zone->serial = ZONE_SERIAL_COUNTER;
    }
    if (serial == (zone_serial_t)ZONE_SERIAL_DATECOUNTER) {
        zone->serial = ZONE_SERIAL_DATECOUNTER;
    }
    if (serial == (zone_serial_t)ZONE_SERIAL_UNIXTIME) {
        zone->serial = ZONE_SERIAL_UNIXTIME;
    }
    if (serial == (zone_serial_t)ZONE_SERIAL_KEEP) {
        zone->serial = ZONE_SERIAL_KEEP;
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int zone_id(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->id;
}

int zone_propagationdelay(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->propagationdelay;
}

int zone_ttl(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->ttl;
}

int zone_min(const zone_t* zone) {
    if (!zone) {
        return 0;
    }

    return zone->min;
}

zone_serial_t zone_serial(const zone_t* zone) {
    if (!zone) {
        return ZONE_SERIAL_INVALID;
    }

    return zone->serial;
}

const char* zone_serial_text(const zone_t* zone) {
    const db_enum_t* enum_set = __enum_set_serial;

    if (!zone) {
        return NULL;
    }

    while (enum_set->text) {
        if (enum_set->value == zone->serial) {
            return enum_set->text;
        }
        enum_set++;
    }
    return NULL;
}

int zone_set_propagationdelay(zone_t* zone, int propagationdelay) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->propagationdelay = propagationdelay;

    return DB_OK;
}

int zone_set_ttl(zone_t* zone, int ttl) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->ttl = ttl;

    return DB_OK;
}

int zone_set_min(zone_t* zone, int min) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->min = min;

    return DB_OK;
}

int zone_set_serial(zone_t* zone, zone_serial_t serial) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    zone->serial = serial;

    return DB_OK;
}

int zone_set_serial_text(zone_t* zone, const char* serial) {
    const db_enum_t* enum_set = __enum_set_serial;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }

    while (enum_set->text) {
        if (!strcmp(enum_set->text, serial)) {
            zone->serial = enum_set->value;
            return DB_OK;
        }
        enum_set++;
    }
    return DB_ERROR_UNKNOWN;
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
    if (zone->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "propagationdelay")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
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
        || db_object_field_set_name(object_field, "min")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "serial")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_serial)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(4))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_int32(db_value_set_get(value_set, 0), zone->propagationdelay)
        || db_value_from_int32(db_value_set_get(value_set, 1), zone->ttl)
        || db_value_from_int32(db_value_set_get(value_set, 2), zone->min)
        || db_value_from_enum_value(db_value_set_get(value_set, 3), zone->serial, __enum_set_serial))
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

int zone_get_by_id(zone_t* zone, int id) {
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

    result_list = db_object_read(zone->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            zone_from_result(zone, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
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
    if (!zone->id) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: validate content */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "propagationdelay")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
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
        || db_object_field_set_name(object_field, "min")
        || db_object_field_set_type(object_field, DB_TYPE_INT32)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "serial")
        || db_object_field_set_type(object_field, DB_TYPE_ENUM)
        || db_object_field_set_enum_set(object_field, __enum_set_serial)
        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(value_set = db_value_set_new(4))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_int32(db_value_set_get(value_set, 0), zone->propagationdelay)
        || db_value_from_int32(db_value_set_get(value_set, 1), zone->ttl)
        || db_value_from_int32(db_value_set_get(value_set, 2), zone->min)
        || db_value_from_enum_value(db_value_set_get(value_set, 3), zone->serial, __enum_set_serial))
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
        || db_value_from_int32(db_clause_get_value(clause), zone->id)
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
    if (!zone->id) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_int32(db_clause_get_value(clause), zone->id)
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

const zone_t* zone_list_next(zone_list_t* zone_list) {
    const db_result_t* result;

    if (!zone_list) {
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

