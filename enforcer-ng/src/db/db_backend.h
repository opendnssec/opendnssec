#ifndef __db_backend_h
#define __db_backend_h

typedef struct db_backend_handle db_backend_handle_t;
typedef struct db_backend db_backend_t;
typedef struct db_backend_list db_backend_list_t;

#include "db_configuration.h"
#include "db_result.h"
#include "db_object.h"

typedef struct db_backend_handle db_backend_handle_t;
typedef int (*db_backend_handle_connect_t)(db_backend_handle_t*, const db_configuration_list_t*);
typedef int (*db_backend_handle_disconnect_t)(db_backend_handle_t*);
typedef db_result_list_t* (*db_backend_handle_query_t)(const db_backend_handle_t*, const db_object_t*);
typedef struct db_backend_handle {
	void* data;
	db_backend_handle_connect_t connect;
	db_backend_handle_disconnect_t disconnect;
	db_backend_handle_query_t query;
} db_backend_handle_t;

db_backend_handle_t* db_backend_handle_new(void);
void db_backend_handle_free(db_backend_handle_t*);
db_backend_handle_connect_t db_backend_handle_connect(db_backend_handle_t*);
db_backend_handle_disconnect_t db_backend_handle_disconnect(db_backend_handle_t*);
db_backend_handle_query_t db_backend_handle_query(db_backend_handle_t*);
int db_backend_handle_set_connect(db_backend_handle_t*, db_backend_handle_connect_t);
int db_backend_handle_set_disconnect(db_backend_handle_t*, db_backend_handle_disconnect_t);
int db_backend_handle_set_query(db_backend_handle_t*, db_backend_handle_query_t);
int db_backend_handle_not_empty(db_backend_handle_t*);

typedef struct db_backend {
	db_backend_t* next;
	char* name;
	db_backend_handle_t* handle;
} db_backend_t;

db_backend_t* db_backend_new(void);
void db_backend_free(db_backend_t*);
const char* db_backend_name(db_backend_t*);
const db_backend_handle_t* db_backend_handle(db_backend_t*);
int db_backend_set_name(db_backend_t*, const char*);
int db_backend_set_handle(db_backend_t*, db_backend_handle_t*);
int db_backend_not_empty(db_backend_t*);
db_result_list_t* db_backend_query(const db_backend_t*, const db_object_t*);

typedef struct db_backend_list {
	db_backend_t* begin;
} db_backend_list_t;

db_backend_list_t* db_backend_list_new(void);
void db_backend_list_free(db_backend_list_t*);
int db_backend_list_add(db_backend_list_t*, db_backend_t*);
const db_backend_t* db_backend_list_find(db_backend_list_t*, const char*);

int db_backend_factory_init(void);
void db_backend_factory_end(void);
const db_backend_t* db_backend_factory_get_backend(const char*);

#endif
