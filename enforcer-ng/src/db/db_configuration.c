#include "db_configuration.h"

#include <stdlib.h>
#include <string.h>

/* DB CONFIGURATION */

db_configuration_t* db_configuration_new(void) {
	db_configuration_t* configuration =
		(db_configuration_t*)calloc(1, sizeof(db_configuration_t));

	return configuration;
}

void db_configuration_free(db_configuration_t* configuration) {
	if (configuration) {
		if (configuration->name) {
			free(configuration->name);
		}
		if (configuration->value) {
			free(configuration->value);
		}
		free(configuration);
	}
}

const char* db_configuration_name(db_configuration_t* configuration) {
	if (!configuration) {
		return NULL;
	}

	return configuration->name;
}

const char* db_configuration_value(db_configuration_t* configuration) {
	if (!configuration) {
		return NULL;
	}

	return configuration->value;
}

int db_configuration_set_name(db_configuration_t* configuration, const char* name) {
	char* new_name;

	if (!configuration) {
		return 1;
	}

	if (!(new_name = strdup(name))) {
		return 1;
	}

	if (configuration->name) {
		free(configuration->name);
	}
	configuration->name = new_name;
	return 0;
}

int db_configuration_set_value(db_configuration_t* configuration, const char* value) {
	char* new_value;

	if (!configuration) {
		return 1;
	}

	if (!(new_value = strdup(value))) {
		return 1;
	}

	if (configuration->value) {
		free(configuration->value);
	}
	configuration->value = new_value;
	return 0;
}

int db_configuration_not_empty(db_configuration_t* configuration) {
	if (!configuration) {
		return 1;
	}
	if (!configuration->name) {
		return 1;
	}
	if (!configuration->value) {
		return 1;
	}
	return 0;
}

/* DB CONFIGURATION LIST */

db_configuration_list_t* db_configuration_list_new(void) {
	db_configuration_list_t* configuration_list =
		(db_configuration_list_t*)calloc(1, sizeof(db_configuration_list_t));

	return configuration_list;
}

void db_configuration_list_free(db_configuration_list_t* configuration_list) {
	if (configuration_list) {
		if (configuration_list->begin) {
			db_configuration_t* this = configuration_list->begin;
			db_configuration_t* next = NULL;

			while (this) {
				next = this->next;
				db_configuration_free(this);
				this = next;
			}
		}
		free(configuration_list);
	}
}

int db_configuration_list_add(db_configuration_list_t* configuration_list, db_configuration_t* configuration) {
	if (!configuration_list) {
		return 1;
	}
	if (!configuration) {
		return 1;
	}
	if (db_configuration_not_empty(configuration)) {
		return 1;
	}

	if (configuration_list->begin) {
		configuration->next = configuration_list->begin;
	}
	configuration_list->begin = configuration;

	return 0;
}

const db_configuration_t* db_configuration_list_find(db_configuration_list_t* configuration_list, const char* name) {
	db_configuration_t* configuration;

	if (!configuration_list) {
		return NULL;
	}
	if (!name) {
		return NULL;
	}

	configuration = configuration_list->begin;
	while (configuration) {
		if (db_configuration_not_empty(configuration)) {
			return NULL;
		}
		if (!strcmp(configuration->name, name)) {
			break;
		}
	}

	return configuration;
}
