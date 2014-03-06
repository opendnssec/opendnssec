#ifndef __db_DbConnection_H
#define __db_DbConnection_H

#include "db/DbBackend.h"

#include <string>
#include <stdexcept>
#include <map>

typedef std::map<std::string, std::string> db_connection_configuration_t;

class DbConnectionException : public std::runtime_error {
public:
	DbConnectionException(const std::string& message)
		: std::runtime_error(message) {};
};

class DbConnection {
	DbBackend* backend;

public:
	DbConnection(db_connection_configuration_t& configuration);
};

#endif
