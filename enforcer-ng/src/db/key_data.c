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

#include "key_data.h"

#include <stdlib.h>

db_object_t* __key_data_new_object(const db_connection_t* connection) {
	db_object_field_list_t* object_field_list;
	db_object_field_t* object_field;
	db_object_t* object;

	if (!(object = db_object_new())
		|| db_object_set_connection(object, connection)
		|| db_object_set_table(object, "KeyData")
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
		|| db_object_field_set_name(object_field, "locator")
		|| db_object_field_set_type(object_field, DB_TYPE_STRING)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "algorithm")
		|| db_object_field_set_type(object_field, DB_TYPE_INTEGER)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "inception")
		|| db_object_field_set_type(object_field, DB_TYPE_INTEGER)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "role")
		|| db_object_field_set_type(object_field, DB_TYPE_STRING)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "introducing")
		|| db_object_field_set_type(object_field, DB_TYPE_INTEGER)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "shouldrevoke")
		|| db_object_field_set_type(object_field, DB_TYPE_INTEGER)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "standby")
		|| db_object_field_set_type(object_field, DB_TYPE_INTEGER)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "active_zsk")
		|| db_object_field_set_type(object_field, DB_TYPE_INTEGER)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "publish")
		|| db_object_field_set_type(object_field, DB_TYPE_INTEGER)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "active_ksk")
		|| db_object_field_set_type(object_field, DB_TYPE_INTEGER)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "ds_at_parent")
		|| db_object_field_set_type(object_field, DB_TYPE_STRING)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "keytag")
		|| db_object_field_set_type(object_field, DB_TYPE_INTEGER)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "ds")
		|| db_object_field_set_type(object_field, DB_TYPE_INTEGER)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "rrsig")
		|| db_object_field_set_type(object_field, DB_TYPE_INTEGER)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "dnskey")
		|| db_object_field_set_type(object_field, DB_TYPE_INTEGER)
		|| db_object_field_list_add(object_field_list, object_field))
	{
		db_object_field_free(object_field);
		db_object_field_list_free(object_field_list);
		db_object_free(object);
		return NULL;
	}

	if (!(object_field = db_object_field_new())
		|| db_object_field_set_name(object_field, "rrsigdnskey")
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

key_data_t* key_data_new(const db_connection_t* connection) {
	key_data_t* key_data =
		(key_data_t*)calloc(1, sizeof(key_data_t));

	if (key_data) {
		if (!(key_data->dbo = __key_data_new_object(connection))) {
			free(key_data);
			return NULL;
		}
	}

	return key_data;
}

void key_data_free(key_data_t* key_data) {
	if (key_data) {
		if (key_data->dbo) {
			db_object_free(key_data->dbo);
		}
		if (key_data->locator) {
			free(key_data->locator);
		}
		if (key_data->role) {
			free(key_data->role);
		}
	    key_data->introducing = 1;
		free(key_data);
	}
}

void key_data_reset(key_data_t* key_data) {
	if (key_data) {
		key_data->id = 0;
		if (key_data->locator) {
			free(key_data->locator);
		}
		key_data->locator = NULL;
		key_data->algorithm = 0;
		key_data->inception = 0;
		if (key_data->role) {
			free(key_data->role);
		}
		key_data->role = NULL;
	    key_data->introducing = 1;
	    key_data->shouldrevoke = 0;
	    key_data->standby = 0;
	    key_data->active_zsk = 0;
	    key_data->publish = 0;
	    key_data->active_ksk = 0;
		if (key_data->ds_at_parent) {
			free(key_data->ds_at_parent);
		}
		key_data->ds_at_parent = NULL;
	    key_data->keytag = 0;
		key_data->ds = 0;
		key_data->rrsig = 0;
		key_data->dnskey = 0;
		key_data->rrsigdnskey = 0;
	}
}

int key_data_from_result(key_data_t* key_data, const db_result_t* result) {
	const db_value_set_t* value_set;

	if (!key_data) {
		return 1;
	}
	if (!result) {
		return 1;
	}

	key_data_reset(key_data);
	if (!(value_set = db_result_value_set(result))
		|| db_value_set_size(value_set) != 17
		|| db_value_to_int(db_value_set_get(value_set, 0), &(key_data->id))
		|| db_value_to_string(db_value_set_get(value_set, 1), &(key_data->locator))
		|| db_value_to_int(db_value_set_get(value_set, 2), &(key_data->algorithm))
		|| db_value_to_int(db_value_set_get(value_set, 3), &(key_data->inception))
		|| db_value_to_string(db_value_set_get(value_set, 4), &(key_data->role))
		|| db_value_to_int(db_value_set_get(value_set, 5), &(key_data->introducing))
		|| db_value_to_int(db_value_set_get(value_set, 6), &(key_data->shouldrevoke))
		|| db_value_to_int(db_value_set_get(value_set, 7), &(key_data->standby))
		|| db_value_to_int(db_value_set_get(value_set, 8), &(key_data->active_zsk))
		|| db_value_to_int(db_value_set_get(value_set, 9), &(key_data->publish))
		|| db_value_to_int(db_value_set_get(value_set, 10), &(key_data->active_ksk))
		|| db_value_to_string(db_value_set_get(value_set, 11), &(key_data->ds_at_parent))
		|| db_value_to_int(db_value_set_get(value_set, 12), &(key_data->keytag))
		|| db_value_to_int(db_value_set_get(value_set, 13), &(key_data->ds))
		|| db_value_to_int(db_value_set_get(value_set, 14), &(key_data->rrsig))
		|| db_value_to_int(db_value_set_get(value_set, 15), &(key_data->dnskey))
		|| db_value_to_int(db_value_set_get(value_set, 16), &(key_data->rrsigdnskey)))
	{
		return 1;
	}
	return 0;
}

int key_data_id(const key_data_t* key_data) {
	if (!key_data) {
		return 1;
	}

	return key_data->id;
}

const char* key_data_locator(const key_data_t* key_data) {
	if (!key_data) {
		return NULL;
	}

	return key_data->locator;
}

int key_data_algorithm(const key_data_t* key_data) {
	if (!key_data) {
		return NULL;
	}

	return key_data->algorithm;
}

int key_data_inception(const key_data_t* key_data) {
	if (!key_data) {
		return 1;
	}

	return key_data->inception;
}

const char* key_data_role(const key_data_t* key_data) {
	if (!key_data) {
		return NULL;
	}

	return key_data->role;
}

int key_data_introducing(const key_data_t* key_data) {
	if (!key_data) {
		return 1;
	}

	return key_data->introducing;
}

int key_data_shouldrevoke(const key_data_t* key_data) {
	if (!key_data) {
		return 1;
	}

	return key_data->shouldrevoke;
}

int key_data_standby(const key_data_t* key_data) {
	if (!key_data) {
		return 1;
	}

	return key_data->standby;
}

int key_data_active_zsk(const key_data_t* key_data) {
	if (!key_data) {
		return 1;
	}

	return key_data->active_zsk;
}

int key_data_publish(const key_data_t* key_data) {
	if (!key_data) {
		return 1;
	}

	return key_data->publish;
}

int key_data_active_ksk(const key_data_t* key_data) {
	if (!key_data) {
		return 1;
	}

	return key_data->active_ksk;
}

const char* key_data_ds_at_parent(const key_data_t* key_data) {
	if (!key_data) {
		return 1;
	}
	if (!key_data->ds_at_parent) {
		return "unsubmitted";
	}

	return key_data->ds_at_parent;
}

key_state_t* key_data_ds(const key_data_t* key_data) {
	return NULL;
}

key_state_t* key_data_rrsig(const key_data_t* key_data) {
	return NULL;
}

key_state_t* key_data_dnskey(const key_data_t* key_data) {
	return NULL;
}

key_state_t* key_data_rrsigdnskey(const key_data_t* key_data) {
	return NULL;
}

/* ENFORCER ZONE LIST */

key_data_list_t* key_data_list_new(const db_connection_t* connection) {
	key_data_list_t* key_data_list =
		(key_data_list_t*)calloc(1, sizeof(key_data_list_t));

	if (key_data_list) {
		if (!(key_data_list->dbo = __key_data_new_object(connection))) {
			free(key_data_list);
			return NULL;
		}
	}

	return key_data_list;
}

void key_data_list_free(key_data_list_t* key_data_list) {
	if (key_data_list) {
		if (key_data_list->dbo) {
			db_object_free(key_data_list->dbo);
		}
		if (key_data_list->result_list) {
			db_result_list_free(key_data_list->result_list);
		}
		if (key_data_list->key_data) {
			key_data_free(key_data_list->key_data);
		}
		free(key_data_list);
	}
}

int key_data_list_get_by_enforcer_zone_id(key_data_list_t* key_data_list, int enforcer_zone_id) {
	db_join_list_t* join_list;
	db_join_t* join;
	db_clause_list_t* clause_list;
	db_clause_t* clause;

	if (!key_data_list) {
		return 1;
	}

	if (!(join_list = db_join_list_new())) {
		return 1;
	}
	if (!(join = db_join_new())
		|| db_join_set_from_table(join, "KeyData")
		|| db_join_set_from_field(join, "id")
		|| db_join_set_to_table(join, "EnforcerZone_keys")
		|| db_join_set_to_field(join, "child_id")
		|| db_join_list_add(join_list, join))
	{
		db_join_free(join);
		db_join_list_free(join_list);
		return 1;
	}

	if (!(clause_list = db_clause_list_new())) {
		db_join_free(join);
		db_join_list_free(join_list);
		return 1;
	}
	if (!(clause = db_clause_new())
		|| db_clause_set_table(clause, "EnforcerZone_keys")
		|| db_clause_set_field(clause, "parent_id")
		|| db_clause_set_type(clause, DB_CLAUSE_EQUAL)
		|| db_clause_set_value_type(clause, DB_TYPE_INTEGER)
		|| db_clause_set_value(clause, &enforcer_zone_id)
		|| db_clause_list_add(clause_list, clause))
	{
		db_join_free(join);
		db_join_list_free(join_list);
		db_clause_free(clause);
		db_clause_list_free(clause_list);
		return 1;
	}

	if (key_data_list->result_list) {
		db_result_list_free(key_data_list->result_list);
	}

	key_data_list->result_list = db_object_read(key_data_list->dbo, join_list, clause_list);
	db_join_free(join);
	db_join_list_free(join_list);
	db_clause_free(clause);
	db_clause_list_free(clause_list);

	if (!key_data_list->result_list) {
		return 1;
	}
	return 0;
}

const key_data_t* key_data_list_begin(key_data_list_t* key_data_list) {
	if (!key_data_list) {
		return NULL;
	}
	if (!key_data_list->result_list) {
		return NULL;
	}

	if (!(key_data_list->result = db_result_list_begin(key_data_list->result_list))) {
		return NULL;
	}
	if (!key_data_list->key_data) {
		if (!(key_data_list->key_data = key_data_new(db_object_connection(key_data_list->dbo)))) {
			return NULL;
		}
	}
	if (key_data_from_result(key_data_list->key_data, key_data_list->result)) {
		return NULL;
	}
	return key_data_list->key_data;
}

const key_data_t* key_data_list_next(key_data_list_t* key_data_list) {
	if (!key_data_list) {
		return NULL;
	}
	if (!key_data_list->result) {
		return NULL;
	}

	if (!(key_data_list->result = db_result_next(key_data_list->result))) {
		return NULL;
	}
	if (!key_data_list->key_data) {
		if (!(key_data_list->key_data = key_data_new(db_object_connection(key_data_list->dbo)))) {
			return NULL;
		}
	}
	if (key_data_from_result(key_data_list->key_data, key_data_list->result)) {
		return NULL;
	}
	return key_data_list->key_data;
}
