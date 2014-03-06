#ifndef __db_DbBackendFactory_H
#define __db_DbBackendFactory_H

#include "db/DbBackend.h"

#include <string>
#include <stdexcept>

class DbBackendFactoryException : public std::runtime_error {
public:
	DbBackendFactoryException(const std::string& message)
		: std::runtime_error(message) {};
};

class DbBackendFactory {
public:
	const DbBackend* createBackend(const std::string& name);
};

#endif
