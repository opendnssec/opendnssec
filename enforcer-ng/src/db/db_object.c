#include "db_object.h"

#include <stdlib.h>

db_object_t* db_object_new(void) {
	db_object_t* object =
		(db_object_t*)calloc(1, sizeof(db_object_t));

	return object;
}

void db_object_free(db_object_t* object) {
	if (object) {
		free(object);
	}
}

int db_object_set_connection(db_object_t* object, const db_connection_t* connection) {
	if (!object) {
		return 1;
	}
	if (!connection) {
		return 1;
	}
	if (object->connection) {
		return 1;
	}

	object->connection = connection;
	return 0;
}

int db_object_set_table(db_object_t* object, const char* table) {
	if (!object) {
		return 1;
	}
	if (!table) {
		return 1;
	}
	if (object->table) {
		return 1;
	}

	object->table = table;
	return 0;
}

int db_object_set_primary_key_name(db_object_t* object, const char* primary_key_name) {
	if (!object) {
		return 1;
	}
	if (!primary_key_name) {
		return 1;
	}
	if (object->primary_key_name) {
		return 1;
	}

	object->primary_key_name = primary_key_name;
	return 0;
}

db_result_list_t* db_object_query(db_object_t* object) {
	if (!object) {
		return NULL;
	}
	if (!object->connection) {
		return NULL;
	}
	if (!object->table) {
		return NULL;
	}
	if (!object->primary_key_name) {
		return NULL;
	}

	return db_connection_query(object->connection, object);
}
