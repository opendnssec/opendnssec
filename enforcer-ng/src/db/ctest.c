#include "db_configuration.h"
#include "db_backend.h"
#include "db_connection.h"
#include "db_object.h"

#include <stdlib.h>
#include <string.h>

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

int __test_db_object_query(void* test, const char* name, db_value_t type, void* value) {
	if (!test) {
		return 1;
	}
	if (!name) {
		return 1;
	}

	if (!strcmp(name, "id")) {
		if (type != DB_VALUE_INTEGER) {
			return 1;
		}
		((test_t*)test)->id = *((unsigned int *)value);
		return 0;
	}
	else if (!strcmp(name, "name")) {
		if (type != DB_VALUE_STRING) {
			return 1;
		}
		return test_set_name((test_t*)test, name);
	}
	return 1;
}

int test_get_by_id(test_t* test, unsigned int id) {
	if (!test) {
		return 1;
	}
	if (!id) {
		return 1;
	}

	return db_object_query(test->dbo, __test_db_object_query, test);
}

int main(void) {
	db_configuration_list_t* configuration_list;
	db_configuration_t* configuration;
	db_connection_t* connection;
	test_t* test;

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
	db_connection_set_configuration_list(connection, configuration_list);

	test = test_new(connection);
	if (test_get_by_id(test, 1)) {
	}

	db_connection_free(connection);
	db_backend_factory_end();
	return 0;
}
