#ifndef __db_object_h
#define __db_object_h

typedef struct db_object db_object_t;

#include "db_connection.h"
#include "db_result.h"

typedef struct db_object {
	const db_connection_t* connection;
	const char* table;
	const char* primary_key_name;
} db_object_t;

db_object_t* db_object_new(void);
void db_object_free(db_object_t*);
int db_object_set_connection(db_object_t*, const db_connection_t*);
int db_object_set_table(db_object_t*, const char*);
int db_object_set_primary_key_name(db_object_t*, const char*);
db_result_list_t* db_object_query(db_object_t*);

#endif
