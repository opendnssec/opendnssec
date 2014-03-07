#include "db_connection.h"

#include <stdlib.h>

db_connection_t* db_connection_new(void) {
	db_connection_t* connection =
		(db_connection_t*)calloc(1, sizeof(db_connection_t));

	return connection;
}

void db_connection_free(db_connection_t* connection) {
	if (connection) {
		if (connection->configuration_list) {
			db_configuration_list_free(connection->configuration_list);
		}
		if (connection->backend) {
			db_backend_free(connection->backend);
		}
		free(connection);
	}
}

int db_connection_set_configuration_list(db_connection_t* connection, db_configuration_list_t* configuration_list) {
	if (!connection) {
		return 1;
	}
	if (connection->configuration_list) {
		return 1;
	}

	connection->configuration_list = configuration_list;
	return 0;
}

db_result_list_t* db_connection_query(const db_connection_t* connection, const db_object_t* object) {
	if (!connection) {
		return NULL;
	}
	if (!connection->backend) {
		return NULL;
	}

	return db_backend_query(connection->backend, object);
}
