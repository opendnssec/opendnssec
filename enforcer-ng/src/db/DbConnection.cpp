#include "db/DbConnection.h"
#include "db/DbBackendFactory.h"

DbConnection::DbConnection(db_configuration_t& configuration) {
	db_configuration_t::iterator backend_iterator = configuration.find("backend");
	if (backend_iterator == configuration.end()) {
		throw new DbConnectionException("Connection configuration is missing backend");
	}

	DbBackendFactory db_backend_factory;
	backend = db_backend_factory.createBackend(backend_iterator->second);
}
