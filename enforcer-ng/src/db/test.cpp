#include "db/DbConnectionFactory.h"
#include "db/DbObject.h"

class test : public DbObject {
};

int main(void) {
	db_configuration_t configuration;
	configuration.insert(db_configuration_pair_t("backend", "SQLite"));
	configuration.insert(db_configuration_pair_t("file", "./test.db"));

	DbConnectionFactory db_connection_factory;
	db_connection_factory.registerConnection("test", configuration);

	DbConnection* connection = db_connection_factory.createConnection("test");
	delete connection;

	return 0;
}
