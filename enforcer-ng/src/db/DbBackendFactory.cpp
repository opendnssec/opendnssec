#include "db/DbBackendFactory.h"
#include "db/DbBackendMySQL.h"
#include "db/DbBackendSQLite.h"

DbBackend* DbBackendFactory::createBackend(const std::string& name) {
	if (name == "MySQL") {
		return new DbBackendMySQL();
	}
	if (name == "SQLite") {
		return new DbBackendSQLite();
	}

	throw new DbBackendFactoryException("Backend " + name + " is not supported");
}
