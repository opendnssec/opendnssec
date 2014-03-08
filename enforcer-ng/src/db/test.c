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
	unsigned int id;
	char* name;
} test_t;

test_t* test_new(const db_connection_t* connection) {
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

int __test_db_object_query(void* test, const char* name, db_type_t type, void* value) {
	if (!test) {
		return 1;
	}
	if (!name) {
		return 1;
	}

	if (!strcmp(name, "id")) {
		if (type != DB_TYPE_INTEGER) {
			return 1;
		}
		((test_t*)test)->id = *((unsigned int *)value);
		return 0;
	}
	else if (!strcmp(name, "name")) {
		if (type != DB_TYPE_STRING) {
			return 1;
		}
		return test_set_name((test_t*)test, name);
	}
	return 1;
}

int test_get_by_id(test_t* test, unsigned int id) {
	db_clause_list_t* clause_list;
	db_clause_t* clause;

	if (!test) {
		return 1;
	}
	if (!id) {
		return 1;
	}

	clause_list = db_clause_list_new();
	clause = db_clause_new();
	db_clause_set_field(clause, "test_id");
	db_clause_set_type(clause, DB_CLAUSE_EQUAL);
	db_clause_list_add(clause_list, clause);

	db_object_read(test->dbo, clause_list);
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
	if (test_get_by_id(test, 1)) {
	}

	db_connection_free(connection);
	db_backend_factory_end();
	return 0;
}
