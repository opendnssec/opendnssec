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

/*
 * Define the test structure
 *  - We need to create a db_object_t to describe this object
 *  - We got a primary key colum called id
 *  - We got a varchar colum called name
 */
typedef struct {
	db_object_t* dbo;
	int id;
	char* name;
} test_t;

/*
 * Create a new test structure
 * - We require a connection object at creation
 * - We setup the database object description (this will be done statically in
 *   later version of the database layer)
 */
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

		/*
		 * Setup the db_object_t
		 * - Connect it to a connection
		 * - Set the table name
		 * - Set the primary key field name (this may be changed later since we
		 *   set a db_object_field_t to DB_TYPE_PRIMARY_KEY)
		 */
		if (db_object_set_connection(test->dbo, connection)
			|| db_object_set_table(test->dbo, "test")
			|| db_object_set_primary_key_name(test->dbo, "id"))
		{
			db_object_free(test->dbo);
			free(test);
			return NULL;
		}

		/*
		 * Create a new db_object_field_list for storing all database field
		 * definitions in
		 */
		if (!(object_field_list = db_object_field_list_new())) {
			db_object_free(test->dbo);
			free(test);
			return NULL;
		}

		/*
		 * Create the definition of column id
		 * - Create a new db_object_field_t
		 * - Set the field name
		 * - Set the field type
		 * - Add it to the object field list
		 */
		if (!(object_field = db_object_field_new())
			|| db_object_field_set_name(object_field, "id")
			|| db_object_field_set_type(object_field, DB_TYPE_PRIMARY_KEY)
			|| db_object_field_list_add(object_field_list, object_field))
		{
			db_object_field_free(object_field);
			db_object_field_list_free(object_field_list);
			db_object_free(test->dbo);
			free(test);
			return NULL;
		}

		/*
		 * Create the definition of column name
		 * - Create a new db_object_field_t
		 * - Set the field name
		 * - Set the field type
		 * - Add it to the object field list
		 */
		if (!(object_field = db_object_field_new())
			|| db_object_field_set_name(object_field, "name")
			|| db_object_field_set_type(object_field, DB_TYPE_STRING)
			|| db_object_field_list_add(object_field_list, object_field))
		{
			db_object_field_free(object_field);
			db_object_field_list_free(object_field_list);
			db_object_free(test->dbo);
			free(test);
			return NULL;
		}

		/*
		 * Add the object field list to the db_object_t
		 */
		if (db_object_set_object_field_list(test->dbo, object_field_list)) {
			db_object_field_list_free(object_field_list);
			db_object_free(test->dbo);
			free(test);
			return NULL;
		}
	}

	return test;
}

/*
 * Free the test object
 */
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

/*
 * Return the test object id or 0 if not set
 */
int test_id(const test_t* test) {
	if (!test) {
		return 0;
	}

	return test->id;
}

/*
 * Return the test object name or NULL if not set
 */
const char* test_name(const test_t* test) {
	if (!test) {
		return NULL;
	}

	return test->name;
}

/*
 * Get a test object by an id
 * - Create a clause list and add a clause for the id
 * - Do a database read
 * - Check the result and that we only got one row back
 * - Retrieve the values from the result and set it in the test object
 */
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

	/*
	 * Clear the test object from the previous values if any
	 */
	test->id = 0;
	if (test->name) {
		free(test->name);
	}
	test->name = NULL;

	/*
	 * Create the clause list and add the clause for id
	 */
	if (!(clause_list = db_clause_list_new())) {
		return 1;
	}
	if (!(clause = db_clause_new())
		|| db_clause_set_field(clause, "id")
		|| db_clause_set_type(clause, DB_CLAUSE_EQUAL)
		|| db_value_from_int(db_clause_value(clause), id)
		|| db_clause_list_add(clause_list, clause))
	{
		db_clause_free(clause);
		db_clause_list_free(clause_list);
		return 1;
	}

	/*
	 * Do a database read, check the result and set the test object values
	 */
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

/*
 * Get a test object by id
 * - Setup the configuration
 * - Connect to the database
 * - Create a test object and get by id
 */
int main(void) {
	db_configuration_list_t* configuration_list;
	db_configuration_t* configuration;
	db_connection_t* connection;
	test_t* test;
	int ret;

	/*
	 * Setup the configuration for the connection
	 */
	if (!(configuration_list = db_configuration_list_new()) {
		fprintf(STDERR, "db_configuraiton_list_new failed\n");
		return 1;
	}
	if (!(configuration = db_configuration_new())
		|| db_configuration_set_name(configuration, "backend")
		|| db_configuration_set_value(configuration, "sqlite")
		|| db_configuration_list_add(configuration_list, configuration))
	{
		db_configuration_free(configuration);
		db_configuration_list_free(configuration_list);
		fprintf(STDERR, "setup configuration backend failed\n");
		return 1;
	}
	if (!(configuration = db_configuration_new())
		|| db_configuration_set_name(configuration, "file")
		|| db_configuration_set_value(configuration, "test.db")
		|| db_configuration_list_add(configuration_list, configuration))
	{
		db_configuration_free(configuration);
		db_configuration_list_free(configuration_list);
		fprintf(STDERR, "setup configuration file failed\n");
		return 1;
	}

	/*
	 * Connect to the database
	 */
	if (!(connection = db_connection_new())
		|| db_connection_set_configuration_list(connection, configuration_list)
		|| db_connection_setup(connection)
		|| db_connection_connect(connection))
	{
		db_connection_free(connection);
		db_configuration_list_free(configuration_list);
		fprintf(STDERR, "database connection failed\n");
		return 1;
	}

	/*
	 * Create a test object and get by id
	 */
	if (!(test = test_new(connection))
		|| test_get_by_id(test, 1))
	{
		test_free(test);
		db_connection_free(connection);
		db_configuration_list_free(configuration_list);
		fprintf(STDERR, "test get by id failed\n");
		return 1;
	}

	printf("test object %d name %s\n", test_id(test), test_name(test));

	test_free(test);
	db_connection_free(connection);
	db_configuration_list_free(configuration_list);
	return 0;
}
