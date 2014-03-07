#include "db_result.h"

/* DB RESULT HEADER */

db_result_header_t* db_result_header_new(char** header, size_t size) {
	db_result_header_t* result_header =
		(db_result_header_t*)calloc(1, sizeof(db_result_header_t));

	if (result_header) {
		result_header->header = header;
		result_header->size = size;
	}

	return result_header;
}

void db_result_header_free(db_result_header_t* result_header) {
	if (result_header) {
		if (result_header->header) {
			if (result_header->size) {
				int i;
				for (i=0; i<result_header->size; i++) {
					free(result_header->header[i]);
				}
			}
			free(result_header->header);
		}
		free(result_header);
	}
}

/* DB RESULT */

db_result_t* db_result_new(void) {
	db_result_t* result =
		(db_result_t*)calloc(1, sizeof(db_result_t));

	if (result) {
		result->type = DB_TYPE_UNKNOWN;
	}

	return result;
}

void db_result_free(db_result_t* result) {
	if (result) {
		if (result->value) {
			free(result->value);
		}
		free(result);
	}
}

db_type_t db_result_type(db_result_t* result) {
	if (!result) {
		return DB_TYPE_UNKNOWN;
	}

	return result->type;
}

void* db_result_value(db_result_t* result) {
	if (!result) {
		return NULL;
	}

	return result->value;
}

int db_result_set_type(db_result_t* result, db_type_t type) {
	if (!result) {
		return 1;
	}
	if (result->type == DB_TYPE_UNKNOWN) {
		return 1;
	}

	result->type = type;
	return 0;
}

int db_result_set_value(db_result_t* result, void* value) {
	if (!result) {
		return 1;
	}
	if (result->value) {
		return 1;
	}

	result->value = value;
	return 0;
}

int db_result_not_empty(db_result_t* result) {
	if (!result) {
		return 1;
	}
	if (result->type == DB_TYPE_UNKNOWN) {
		return 1;
	}
	if (result->value) {
		return 1;
	}

	return 0;
}

/* DB RESULT LIST */

db_result_list_t* db_result_list_new(void) {
	db_result_list_t* result_list =
		(db_result_list_t*)calloc(1, sizeof(db_result_list_t));

	return result_list;
}

void db_result_list_free(db_result_list_t* result_list) {
	if (result_list) {
		if (result_list->begin) {
			db_result_t* this = result_list->begin;
			db_result_t* next = NULL;

			while (this) {
				next = this->next;
				db_result_free(this);
				this = next;
			}
		}
		free(result_list);
	}
}

int db_result_list_add(db_result_list_t* result_list, db_result_t* result) {
	if (!result_list) {
		return 1;
	}
	if (!result) {
		return 1;
	}
	if (db_result_not_empty(result)) {
		return 1;
	}

	if (result_list->begin) {
		result->next = result_list->begin;
	}
	result_list->begin = result;

	return 0;
}

const db_result_t* db_result_list_first(db_result_list_t* result_list) {
	if (!result_list) {
		return NULL;
	}

	result_list->cursor = result_list->begin;
	return result_list->cursor;
}

const db_result_t* db_result_list_next(db_result_list_t* result_list) {
	if (!result_list) {
		return NULL;
	}

	if (!result_list->cursor) {
		result_list->cursor = result_list->begin;
	}
	result_list->cursor = result_list->cursor->next;
	return result_list->cursor;
}
