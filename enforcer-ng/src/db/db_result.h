#ifndef __db_result_h
#define __db_result_h

typedef struct db_result_header db_result_header_t;
typedef struct db_result db_result_t;
typedef struct db_result_list db_result_list_t;

#include "db_type.h"

#include <stdlib.h>

typedef struct db_result_header {
	char** header;
	size_t size;
} db_result_header_t;

db_result_header_t* db_result_header_new(char**, size_t);
void db_result_header_free(db_result_header_t*);

typedef struct db_result {
	db_result_t* next;
	db_type_t type;
	void* value;
} db_result_t;

db_result_t* db_result_new(void);
void db_result_free(db_result_t*);
db_type_t db_result_type(db_result_t*);
void* db_result_value(db_result_t*);
int db_result_set_type(db_result_t*, db_type_t);
int db_result_set_value(db_result_t*, void*);
int db_result_not_empty(db_result_t*);

typedef struct db_result_list {
	db_result_header_t* header;
	db_result_t* begin;
	db_result_t* cursor;
} db_result_list_t;

db_result_list_t* db_result_list_new(void);
void db_result_list_free(db_result_list_t*);
int db_result_list_add(db_result_list_t*, db_result_t*);
const db_result_t* db_result_list_first(db_result_list_t*);
const db_result_t* db_result_list_next(db_result_list_t*);

#endif
