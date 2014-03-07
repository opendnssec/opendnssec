#ifndef __db_result_h
#define __db_result_h

#include "db_value.h"

typedef struct db_result db_result_t;
typedef struct db_result {
	db_result_t* next;
	db_value_t type;
	void* value;
} db_result_t;

typedef struct {
	unsigned int count;
	char* name[];
} db_result_header_t;

typedef struct {
	db_result_header_t* header;
	db_result_t* begin;
} db_result_list_t;

#endif
