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

#include "db_value.h"

#include <string.h>

/* DB VALUE */

db_value_t* db_value_new() {
	db_value_t* value =
		(db_value_t*)calloc(1, sizeof(db_value_t));

	if (value) {
		value->type = DB_TYPE_UNKNOWN;
	}

	return value;
}

void db_value_free(db_value_t* value) {
	if (value) {
		if (value->data) {
			free(value->data);
		}
		free(value);
	}
}

void db_value_reset(db_value_t* value) {
	if (value) {
		if (value->data) {
			free(value->data);
		}
		value->data = NULL;
		value->type = DB_TYPE_UNKNOWN;
	}
}

db_type_t db_value_type(const db_value_t* value) {
	if (!value) {
		return DB_TYPE_UNKNOWN;
	}

	return value->type;
}

const void* db_value_data(const db_value_t* value) {
	if (!value) {
		return NULL;
	}

	return value->data;
}

int db_value_set_type(db_value_t* value, db_type_t type) {
	if (!value) {
		return 1;
	}
	if (type != DB_TYPE_UNKNOWN) {
		return 1;
	}

	value->type = type;
	return 0;
}

int db_value_set_data(db_value_t* value, void* data) {
	if (!value) {
		return 1;
	}
	if (!data) {
		return 1;
	}

	value->data = data;
	return 0;
}

int db_value_not_empty(const db_value_t* value) {
	if (!value) {
		return 1;
	}
	if (value->type == DB_TYPE_UNKNOWN) {
		return 1;
	}
	/* TODO: Shouldnt we be able to be null?
	if (!value->data) {
		return 1;
	}
	*/
	return 0;
}

int db_value_to_int(const db_value_t* value, int* to_int) {
	if (!value) {
		return 1;
	}
	if (!to_int) {
		return 1;
	}
	if (value->type != DB_TYPE_INTEGER) {
		return 1;
	}

	*to_int = *(int*)(value->data);
	return 0;
}

int db_value_to_string(const db_value_t* value, char** to_string) {
	if (!value) {
		return 1;
	}
	if (!to_string) {
		return 1;
	}
	if (value->type != DB_TYPE_STRING) {
		return 1;
	}

	*to_string = strdup((char*)value->data);
	if (!*to_string) {
		return 1;
	}
	return 0;
}

int db_value_from_int(db_value_t* value, int from_int) {
	if (!value) {
		return 1;
	}
	if (db_value_not_empty(value)) {
		return 1;
	}

	/* TODO: store it inside the void* if fit */
	value->data = (void*)calloc(1, sizeof(int));
	if (!value->data) {
		return 1;
	}
	*(int*)(value->data) = from_int;
	value->type = DB_TYPE_INTEGER;
	return 0;
}

int db_value_from_string(db_value_t* value, const char* from_string) {
	if (!value) {
		return 1;
	}
	if (db_value_not_empty(value)) {
		return 1;
	}

	value->data = (void*)strdup(from_string);
	if (!value->data) {
		return 1;
	}
	value->type = DB_TYPE_STRING;
	return 0;
}

/* DB VALUE SET */

db_value_set_t* db_value_set_new(size_t size) {
	db_value_set_t* value_set;

	if (size < 1) {
		return NULL;
	}

	value_set = (db_value_set_t*)calloc(1, sizeof(db_value_set_t));
	if (value_set) {
		value_set->values = (db_value_t*)calloc(size, sizeof(db_value_t));
		if (!value_set->values) {
			free(value_set);
			return NULL;
		}
	}

	return value_set;
}

void db_value_set_free(db_value_set_t* value_set) {
	if (value_set) {
		size_t i;
		for (i=0; i<value_set->size; i++) {
			db_value_reset(&value_set->values[i]);
		}
		free(value_set->values);
		free(value_set);
	}
}

db_value_t* db_value_set_get(db_value_set_t* value_set, size_t at) {
	if (!value_set) {
		return NULL;
	}
	if (!value_set->values) {
		return NULL;
	}
	if (at < 0) {
		return NULL;
	}
	if (!(at < value_set->size)) {
		return NULL;
	}

	return &value_set->values[at];
}
