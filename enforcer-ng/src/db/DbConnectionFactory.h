#ifndef __db_DbConnectionFactory_H
#define __db_DbConnectionFactory_H

#include "db/DbConnection.h"

#include <map>
#include <string>
#include <stdexcept>

class DbConnectionFactoryException : public std::runtime_error {
public:
	DbConnectionFactoryException(const std::string& message)
		: std::runtime_error(message) {};
};

typedef std::map<std::string, db_connection_configuration_t> db_connection_t;

class DbConnectionFactory {
	db_connection_t connections;

public:
	void registerConnection(const std::string& name, const db_connection_configuration_t& configuration);
	void unregisterConnection(const std::string& name);
	const DbConnection* createConnection(const std::string& name);
};

#endif
