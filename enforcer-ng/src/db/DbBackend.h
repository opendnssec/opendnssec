#ifndef __db_DbBackend_H
#define __db_DbBackend_H

#include "db/DbConfiguration.h"

#include <string>
#include <stdexcept>

class DbBackendException : public std::runtime_error {
public:
	DbBackendException(const std::string& message)
		: std::runtime_error(message) {};
};

class DbBackend {
public:
	virtual void configure(db_configuration_t& configuration);
	virtual void connect(void);
	virtual void disconnect(void);
};

#endif
