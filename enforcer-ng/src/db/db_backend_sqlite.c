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

#include "db_backend_sqlite.h"

#include <stdlib.h>
#include <sqlite3.h>
#include <stdio.h>

int __sqlite3_initialized = 0;

typedef struct db_backend_sqlite {
	sqlite3* db;
} db_backend_sqlite_t;

int db_backend_sqlite_initialize(void* data) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

	if (!backend_sqlite) {
		return 1;
	}

	if (!__sqlite3_initialized) {
		int ret = sqlite3_initialize();
		if (ret != SQLITE_OK) {
			return 1;
		}
		__sqlite3_initialized = 1;
	}
	return 0;
}

int db_backend_sqlite_shutdown(void* data) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

	if (!backend_sqlite) {
		return 1;
	}

	if (__sqlite3_initialized) {
		int ret = sqlite3_shutdown();
		if (ret != SQLITE_OK) {
			return 1;
		}
		__sqlite3_initialized = 0;
	}
	return 0;
}

int db_backend_sqlite_connect(void* data, const db_configuration_list_t* configuration_list) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;
	const db_configuration_t* file;
	int ret;

	if (!__sqlite3_initialized) {
		return 1;
	}
	if (!backend_sqlite) {
		return 1;
	}
	if (backend_sqlite->db) {
		return 1;
	}
	if (!configuration_list) {
		return 1;
	}

	if (!(file = db_configuration_list_find(configuration_list, "file"))) {
		return 1;
	}

	ret = sqlite3_open_v2(
		db_configuration_value(file),
		&(backend_sqlite->db),
		SQLITE_OPEN_READWRITE
		| SQLITE_OPEN_CREATE
		| SQLITE_OPEN_FULLMUTEX,
		NULL);
	if (ret != SQLITE_OK) {
		return 1;
	}
	return 0;
}

int db_backend_sqlite_disconnect(void* data) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;
	int ret;

	if (!__sqlite3_initialized) {
		return 1;
	}
	if (!backend_sqlite) {
		return 1;
	}
	if (!backend_sqlite->db) {
		return 1;
	}

	ret = sqlite3_close(backend_sqlite->db);
	if (ret != SQLITE_OK) {
		return 1;
	}
	backend_sqlite->db = NULL;
	return 0;
}

int db_backend_sqlite_create(void* data, const db_object_t* object) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

	if (!__sqlite3_initialized) {
		return 1;
	}
	if (!backend_sqlite) {
		return 1;
	}

	return 1;
}

db_result_list_t* db_backend_sqlite_read(void* data, const db_object_t* object, const db_clause_list_t* clause_list) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

	printf("sqlite read %p %p\n", object, clause_list);

	if (!__sqlite3_initialized) {
		return NULL;
	}
	if (!backend_sqlite) {
		return NULL;
	}
	if (!object) {
		return NULL;
	}
	if (!clause_list) {
		return NULL;
	}

	printf("  %s\n", db_object_table(object));

	return NULL;
}

int db_backend_sqlite_update(void* data, const db_object_t* object) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

	if (!__sqlite3_initialized) {
		return 1;
	}
	if (!backend_sqlite) {
		return 1;
	}

	return 1;
}

int db_backend_sqlite_delete(void* data, const db_object_t* object) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

	if (!__sqlite3_initialized) {
		return 1;
	}
	if (!backend_sqlite) {
		return 1;
	}

	return 1;
}

db_backend_handle_t* db_backend_sqlite_new_handle(void) {
	db_backend_handle_t* backend_handle;
	db_backend_sqlite_t* backend_sqlite =
		(db_backend_sqlite_t*)calloc(1, sizeof(db_backend_sqlite_t));

	if (backend_sqlite && (backend_handle = db_backend_handle_new())) {
		if (db_backend_handle_set_data(backend_handle, (void*)backend_sqlite)
			|| db_backend_handle_set_initialize(backend_handle, db_backend_sqlite_initialize)
			|| db_backend_handle_set_shutdown(backend_handle, db_backend_sqlite_shutdown)
			|| db_backend_handle_set_connect(backend_handle, db_backend_sqlite_connect)
			|| db_backend_handle_set_disconnect(backend_handle, db_backend_sqlite_disconnect)
			|| db_backend_handle_set_create(backend_handle, db_backend_sqlite_create)
			|| db_backend_handle_set_read(backend_handle, db_backend_sqlite_read)
			|| db_backend_handle_set_update(backend_handle, db_backend_sqlite_update)
			|| db_backend_handle_set_delete(backend_handle, db_backend_sqlite_delete))
		{
			db_backend_handle_free(backend_handle);
			free(backend_sqlite);
			return NULL;
		}
	}
	return backend_handle;
}
