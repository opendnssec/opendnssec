/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "db_object.h"

#include <stdlib.h>

/* DB OBJECT FIELD */

db_object_field_t* db_object_field_new(void) {
	db_object_field_t* object_field =
		(db_object_field_t*)calloc(1, sizeof(db_object_field_t));

	if (object_field) {
		object_field->type = DB_TYPE_UNKNOWN;
	}

	return object_field;
}

void db_object_field_free(db_object_field_t* object_field) {
	if (object_field) {
		free(object_field);
	}
}

const char* db_object_field_name(const db_object_field_t* object_field) {
	if (!object_field) {
		return NULL;
	}

	return object_field->name;
}

db_type_t db_object_field_type(const db_object_field_t* object_field) {
	if (!object_field) {
		return DB_TYPE_UNKNOWN;
	}

	return object_field->type;
}

int db_object_field_set_name(db_object_field_t* object_field, const char* name) {
	if (!object_field) {
		return 1;
	}
	if (!name) {
		return 1;
	}

	object_field->name = name;
	return 0;
}

int db_object_field_set_type(db_object_field_t* object_field, db_type_t type) {
	if (!object_field) {
		return 1;
	}
	if (type == DB_TYPE_UNKNOWN) {
		return 1;
	}

	object_field->type = type;
	return 0;
}

int db_object_field_not_empty(const db_object_field_t* object_field) {
	if (!object_field) {
		return 1;
	}
	if (!object_field->name) {
		return 1;
	}
	if (object_field->type == DB_TYPE_UNKNOWN) {
		return 1;
	}
	return 0;
}

const db_object_field_t* db_object_field_next(const db_object_field_t* object_field) {
	if (!object_field) {
		return NULL;
	}

	return object_field->next;
}

/* DB OBJECT FIELD LIST */

db_object_field_list_t* db_object_field_list_new(void) {
	db_object_field_list_t* object_field_list =
		(db_object_field_list_t*)calloc(1, sizeof(db_object_field_list_t));

	return object_field_list;
}

void db_object_field_list_free(db_object_field_list_t* object_field_list) {
	if (object_field_list) {
		if (object_field_list->begin) {
			db_object_field_t* this = object_field_list->begin;
			db_object_field_t* next = NULL;

			while (this) {
				next = this->next;
				db_object_field_free(this);
				this = next;
			}
		}
		free(object_field_list);
	}
}

int db_object_field_list_add(db_object_field_list_t* object_field_list, db_object_field_t* object_field) {
	if (!object_field_list) {
		return 1;
	}
	if (!object_field) {
		return 1;
	}
	if (db_object_field_not_empty(object_field)) {
		return 1;
	}
	if (object_field->next) {
		return 1;
	}

	if (object_field_list->begin) {
		if (!object_field_list->end) {
			return 1;
		}
		object_field_list->end->next = object_field;
		object_field_list->end = object_field;
	}
	else {
		object_field_list->begin = object_field;
		object_field_list->end = object_field;
	}

	return 0;
}

const db_object_field_t* db_object_field_list_begin(const db_object_field_list_t* object_field_list) {
	if (!object_field_list) {
		return NULL;
	}

	return object_field_list->begin;
}

/* DB OBJECT */

db_object_t* db_object_new(void) {
	db_object_t* object =
		(db_object_t*)calloc(1, sizeof(db_object_t));

	return object;
}

void db_object_free(db_object_t* object) {
	if (object) {
		if (object->object_field_list) {
			db_object_field_list_free(object->object_field_list);
		}
		free(object);
	}
}

const db_connection_t* db_object_connection(const db_object_t* object) {
	if (!object) {
		return NULL;
	}
	return object->connection;
}

const char* db_object_table(const db_object_t* object) {
	if (!object) {
		return NULL;
	}
	return object->table;
}

const char* db_object_primary_key_name(const db_object_t* object) {
	if (!object) {
		return NULL;
	}
	return object->primary_key_name;
}

const db_object_field_list_t* db_object_object_field_list(const db_object_t* object) {
	if (!object) {
		return NULL;
	}
	return object->object_field_list;
}

int db_object_set_connection(db_object_t* object, const db_connection_t* connection) {
	if (!object) {
		return 1;
	}
	if (!connection) {
		return 1;
	}
	if (object->connection) {
		return 1;
	}

	object->connection = connection;
	return 0;
}

int db_object_set_table(db_object_t* object, const char* table) {
	if (!object) {
		return 1;
	}
	if (!table) {
		return 1;
	}
	if (object->table) {
		return 1;
	}

	object->table = table;
	return 0;
}

int db_object_set_primary_key_name(db_object_t* object, const char* primary_key_name) {
	if (!object) {
		return 1;
	}
	if (!primary_key_name) {
		return 1;
	}
	if (object->primary_key_name) {
		return 1;
	}

	object->primary_key_name = primary_key_name;
	return 0;
}

int db_object_set_object_field_list(db_object_t* object, db_object_field_list_t* object_field_list) {
	if (!object) {
		return 1;
	}
	if (!object_field_list) {
		return 1;
	}
	if (object->object_field_list) {
		return 1;
	}

	object->object_field_list = object_field_list;
	return 0;
}

db_result_list_t* db_object_read(const db_object_t* object, const db_clause_list_t* clause_list) {
	if (!object) {
		return NULL;
	}
	if (!clause_list) {
		return NULL;
	}
	if (!object->connection) {
		return NULL;
	}
	if (!object->table) {
		return NULL;
	}
	if (!object->primary_key_name) {
		return NULL;
	}

	return db_connection_read(object->connection, object, clause_list);
}
