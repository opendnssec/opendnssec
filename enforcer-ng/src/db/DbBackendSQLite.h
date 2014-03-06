#ifndef __db_DbBackendSQLite_H
#define __db_DbBackendSQLite_H

#include "db/DbBackend.h"

class DbBackendSQLite : public DbBackend {
public:
	DbBackendSQLite();
	~DbBackendSQLite();
};

#endif
