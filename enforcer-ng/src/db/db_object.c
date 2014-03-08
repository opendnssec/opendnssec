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

db_object_t* db_object_new(void) {
	db_object_t* object =
		(db_object_t*)calloc(1, sizeof(db_object_t));

	return object;
}

void db_object_free(db_object_t* object) {
	if (object) {
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
