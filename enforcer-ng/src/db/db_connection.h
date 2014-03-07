#ifndef __db_connection_h
#define __db_connection_h

typedef struct db_connection db_connection_t;

#include "db_configuration.h"
#include "db_backend.h"
#include "db_result.h"
#include "db_object.h"

typedef struct db_connection {
	db_configuration_list_t* configuration_list;
	db_backend_t* backend;
} db_connection_t;

db_connection_t* db_connection_new(void);
void db_connection_free(db_connection_t*);
int db_connection_set_configuration_list(db_connection_t*, db_configuration_list_t*);
db_result_list_t* db_connection_query(const db_connection_t*, const db_object_t*);

#endif
