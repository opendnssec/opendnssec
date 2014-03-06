#include <db/DbConnectionFactory.h>

void DbConnectionFactory::registerConnection(const std::string& name, const db_connection_configuration_t& configuration) {
	std::pair<db_connection_t::iterator, bool> ret;
	ret = connections.insert(std::pair<std::string, db_connection_configuration_t>(name, configuration));
	if (ret.second == false) {
		throw new DbConnectionFactoryException("Connection " + name + " already exists");
	}
}

void DbConnectionFactory::unregisterConnection(const std::string& name) {
	db_connection_t::iterator i = connections.find(name);
	if (i == connections.end()) {
		throw new DbConnectionFactoryException("Connection " + name + " does not exist");
	}
	connections.erase(i);
}

const DbConnection* DbConnectionFactory::createConnection(const std::string& name) {
	db_connection_t::iterator i = connections.find(name);
	if (i == connections.end()) {
		throw new DbConnectionFactoryException("Connection " + name + " does not exist");
	}
	return new DbConnection(i->second);
}
