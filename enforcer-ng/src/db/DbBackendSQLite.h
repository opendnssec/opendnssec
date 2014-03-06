#ifndef __db_DbBackendSQLite_H
#define __db_DbBackendSQLite_H

#include "db/DbBackend.h"

class DbBackendSQLite : public DbBackend {
public:
	DbBackendSQLite();
	~DbBackendSQLite();
	void configure(db_configuration_t& configuration);
	void connect(void);
	void disconnect(void);
};

#endif
