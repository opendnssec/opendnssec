#ifndef __db_configuration_h
#define __db_configuration_h

typedef struct db_configuration db_configuration_t;
typedef struct db_configuration {
	db_configuration_t* next;
	char* name;
	char* value;
} db_configuration_t;

db_configuration_t* db_configuration_new(void);
void db_configuration_free(db_configuration_t*);
const char* db_configuration_name(db_configuration_t*);
const char* db_configuration_value(db_configuration_t*);
int db_configuration_set_name(db_configuration_t*, const char*);
int db_configuration_set_value(db_configuration_t*, const char*);
int db_configuration_not_empty(db_configuration_t*);

typedef struct {
	db_configuration_t* begin;
} db_configuration_list_t;

db_configuration_list_t* db_configuration_list_new(void);
void db_configuration_list_free(db_configuration_list_t*);
int db_configuration_list_add(db_configuration_list_t*, db_configuration_t*);
const db_configuration_t* db_configuration_list_find(db_configuration_list_t*, const char*);

#endif
