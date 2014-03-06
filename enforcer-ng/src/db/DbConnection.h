#ifndef __db_DbConnection_H
#define __db_DbConnection_H

#include "db/DbConfiguration.h"
#include "db/DbBackend.h"

#include <string>
#include <stdexcept>

class DbConnectionException : public std::runtime_error {
public:
	DbConnectionException(const std::string& message)
		: std::runtime_error(message) {};
};

class DbConnection {
	DbBackend* backend;

public:
	DbConnection(db_configuration_t& configuration);
};

#endif
