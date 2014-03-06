#ifndef __db_DbBackendMySQL_H
#define __db_DbBackendMySQL_H

#include "db/DbBackend.h"

class DbBackendMySQL : public DbBackend {
public:
	DbBackendMySQL();
	~DbBackendMySQL();
};

#endif
