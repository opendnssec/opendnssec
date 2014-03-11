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

#include "db_configuration.h"
#include "db_backend.h"
#include "db_connection.h"
#include "db_object.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
	db_object_t* dbo;
	int id;
	char* name;
} test_t;

test_t* test_new(const db_connection_t* connection) {
	db_object_field_list_t* object_field_list;
	db_object_field_t* object_field;
	test_t* test =
		(test_t*)calloc(1, sizeof(test_t));

	if (test) {
		if (!(test->dbo = db_object_new())) {
			free(test);
			return NULL;
		}
		db_object_set_connection(test->dbo, connection);
		db_object_set_table(test->dbo, "test");
		db_object_set_primary_key_name(test->dbo, "id");

		object_field_list = db_object_field_list_new();
		object_field = db_object_field_new();
		db_object_field_set_name(object_field, "id");
		db_object_field_set_type(object_field, DB_TYPE_PRIMARY_KEY);
		db_object_field_list_add(object_field_list, object_field);
		object_field = db_object_field_new();
		db_object_field_set_name(object_field, "name");
		db_object_field_set_type(object_field, DB_TYPE_STRING);
		db_object_field_list_add(object_field_list, object_field);
		db_object_set_object_field_list(test->dbo, object_field_list);
	}

	return test;
}

void test_free(test_t* test) {
	if (test) {
		if (test->dbo) {
			db_object_free(test->dbo);
		}
		if (test->name) {
			free(test->name);
		}
		free(test);
	}
}

int test_id(const test_t* test) {
	if (!test) {
		return 0;
	}

	return test->id;
}

const char* test_name(const test_t* test) {
	if (!test) {
		return NULL;
	}

	return test->name;
}

int test_set_name(test_t* test, const char* name) {
	char* new_name;

	if (!test) {
		return 1;
	}

	if (!(new_name = strdup(name))) {
		return 1;
	}

	if (test->name) {
		free(test->name);
	}
	test->name = new_name;
	return 0;
}

int test_get_by_id(test_t* test, int id) {
	db_clause_list_t* clause_list;
	db_clause_t* clause;
	db_result_list_t* result_list;
	const db_result_t* result;

	if (!test) {
		return 1;
	}
	if (!id) {
		return 1;
	}

	test->id = 0;
	if (test->name) {
		free(test->name);
	}
	test->name = NULL;

	if (!(clause_list = db_clause_list_new())) {
		return 1;
	}
	if (!(clause = db_clause_new())
		|| db_clause_set_field(clause, "id")
		|| db_clause_set_type(clause, DB_CLAUSE_EQUAL)
		|| db_clause_set_value_type(clause, DB_TYPE_INTEGER)
		|| db_clause_set_value(clause, &id)
		|| db_clause_list_add(clause_list, clause))
	{
		db_clause_free(clause);
		db_clause_list_free(clause_list);
		return 1;
	}

	result_list = db_object_read(test->dbo, NULL, clause_list);
	if (result_list) {
		result = db_result_list_begin(result_list);
		if (db_result_next(result)) {
			db_result_list_free(result_list);
			db_clause_list_free(clause_list);
			return 1;
		}

		if (result) {
			const db_value_set_t* value_set = db_result_value_set(result);

			if (!value_set
				|| db_value_set_size(value_set) != 2
				|| db_value_to_int(db_value_set_get(value_set, 0), &(test->id))
				|| db_value_to_string(db_value_set_get(value_set, 1), &(test->name)))
			{
				db_result_list_free(result_list);
				db_clause_list_free(clause_list);
				return 1;
			}
		}
	}

	db_result_list_free(result_list);
	db_clause_list_free(clause_list);
	return 0;
}

int main(void) {
	db_configuration_list_t* configuration_list;
	db_configuration_t* configuration;
	db_connection_t* connection;
	test_t* test;
	int ret;

	db_backend_factory_init();

	configuration_list = db_configuration_list_new();
	configuration = db_configuration_new();
	db_configuration_set_name(configuration, "backend");
	db_configuration_set_value(configuration, "sqlite");
	db_configuration_list_add(configuration_list, configuration);
	configuration = db_configuration_new();
	db_configuration_set_name(configuration, "file");
	db_configuration_set_value(configuration, "test.db");
	db_configuration_list_add(configuration_list, configuration);

	connection = db_connection_new();
	if ((ret = db_connection_set_configuration_list(connection, configuration_list))) {
		printf("db_connection_set_configuration_list %d\n", ret);
	}
	if ((ret = db_connection_setup(connection))) {
		printf("db_connection_setup %d\n", ret);
	}
	if ((ret = db_connection_connect(connection))) {
		printf("db_connection_connect %d\n", ret);
	}

	test = test_new(connection);
	if (!test_get_by_id(test, 1)) {
		printf("%d %s\n", test_id(test), test_name(test));
	}
	test_free(test);

	db_connection_free(connection);
	db_backend_factory_end();
	return 0;
}
