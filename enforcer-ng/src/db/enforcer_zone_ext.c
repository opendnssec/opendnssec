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

key_data_list_t* enforcer_zone_get_keys(const enforcer_zone_t* enforcer_zone) {
    key_data_list_t* key_data_list;

    if (!enforcer_zone) {
        return NULL;
    }
    if (!enforcer_zone->dbo) {
        return NULL;
    }
    if (db_value_not_empty(&(enforcer_zone->id))) {
        return NULL;
    }

    key_data_list = key_data_list_new(db_object_connection(enforcer_zone->dbo));
    if (key_data_list) {
        if (key_data_list_get_by_enforcer_zone_id(key_data_list, &(enforcer_zone->id))) {
            key_data_list_free(key_data_list);
            return NULL;
        }
    }
    return key_data_list;
}

adapters_t* enforcer_zone_get_adapters(const enforcer_zone_t* enforcer_zone) {
    db_value_t* id = NULL;
    adapters_t* adapters = NULL;

    if (!enforcer_zone) {
        return NULL;
    }
    if (!enforcer_zone->dbo) {
        return NULL;
    }

    if (!(id = db_value_new())) {
        return NULL;
    }
    if (db_value_from_int32(id, enforcer_zone->adapters)) {
        db_value_free(id);
        return NULL;
    }
    if ((adapters = adapters_new(db_object_connection(enforcer_zone->dbo)))) {
        if (adapters_get_by_id(adapters, id)) {
            adapters_free(adapters);
            db_value_free(id);
            return NULL;
        }
    }
    db_value_free(id);

    return adapters;
}

key_dependency_list_t* enforcer_zone_get_key_dependencies(const enforcer_zone_t* enforcer_zone) {
    /* TODO: this */
    return NULL;
}

int enforcer_zone_get_by_name(enforcer_zone_t* enforcer_zone, const char* name) {
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

    result_list = db_object_read(enforcer_zone->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_begin(result_list);
        if (result) {
            enforcer_zone_from_result(enforcer_zone, result);
            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}
