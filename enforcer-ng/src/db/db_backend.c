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

#include "db_backend.h"
#include "db_backend_sqlite.h"

#include <stdlib.h>
#include <string.h>

/* DB BACKEND HANDLE */

db_backend_handle_t* db_backend_handle_new(void) {
	db_backend_handle_t* backend_handle =
		(db_backend_handle_t*)calloc(1, sizeof(db_backend_handle_t));

	return backend_handle;
}

void db_backend_handle_free(db_backend_handle_t* backend_handle) {
	if (backend_handle) {
		if (backend_handle->disconnect) {
			(*backend_handle->disconnect)(backend_handle);
		}
		if (backend_handle->free) {
			(*backend_handle->free)(backend_handle);
		}
		free(backend_handle);
	}
}

int db_backend_handle_initialize(const db_backend_handle_t* backend_handle) {
	if (!backend_handle) {
		return 1;
	}
	if (!backend_handle->initialize) {
		return 1;
	}

	return backend_handle->initialize((void*)backend_handle->data);
}

int db_backend_handle_shutdown(const db_backend_handle_t* backend_handle) {
	if (!backend_handle) {
		return 1;
	}
	if (!backend_handle->shutdown) {
		return 1;
	}

	return backend_handle->shutdown((void*)backend_handle->data);
}

int db_backend_handle_connect(const db_backend_handle_t* backend_handle, const db_configuration_list_t* configuration_list) {
	if (!backend_handle) {
		return 1;
	}
	if (!backend_handle->connect) {
		return 1;
	}

	return backend_handle->connect((void*)backend_handle->data, configuration_list);
}

int db_backend_handle_disconnect(const db_backend_handle_t* backend_handle) {
	if (!backend_handle) {
		return 1;
	}
	if (!backend_handle->disconnect) {
		return 1;
	}

	return backend_handle->disconnect((void*)backend_handle->data);
}

int db_backend_handle_create(const db_backend_handle_t* backend_handle, const db_object_t* object) {
	if (!backend_handle) {
		return 1;
	}
	if (!backend_handle->create) {
		return 1;
	}

	return backend_handle->create((void*)backend_handle->data, object);
}

db_result_list_t* db_backend_handle_read(const db_backend_handle_t* backend_handle, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
	if (!backend_handle) {
		return NULL;
	}
	if (!object) {
		return NULL;
	}
	if (!backend_handle->read) {
		return NULL;
	}

	return backend_handle->read((void*)backend_handle->data, object, join_list, clause_list);
}

int db_backend_handle_update(const db_backend_handle_t* backend_handle, const db_object_t* object) {
	if (!backend_handle) {
		return 1;
	}
	if (!backend_handle->update) {
		return 1;
	}

	return backend_handle->update((void*)backend_handle->data, object);
}

int db_backend_handle_delete(const db_backend_handle_t* backend_handle, const db_object_t* object) {
	if (!backend_handle) {
		return 1;
	}
	if (!backend_handle->delete) {
		return 1;
	}

	return backend_handle->delete((void*)backend_handle->data, object);
}

const void* db_backend_handle_data(const db_backend_handle_t* backend_handle) {
	if (!backend_handle) {
		return NULL;
	}

	return backend_handle->data;
}

int db_backend_handle_set_initialize(db_backend_handle_t* backend_handle, db_backend_handle_initialize_t initialize) {
	if (!backend_handle) {
		return 1;
	}

	backend_handle->initialize = initialize;
	return 0;
}

int db_backend_handle_set_shutdown(db_backend_handle_t* backend_handle, db_backend_handle_shutdown_t shutdown) {
	if (!backend_handle) {
		return 1;
	}

	backend_handle->shutdown = shutdown;
	return 0;
}

int db_backend_handle_set_connect(db_backend_handle_t* backend_handle, db_backend_handle_connect_t connect) {
	if (!backend_handle) {
		return 1;
	}

	backend_handle->connect = connect;
	return 0;
}

int db_backend_handle_set_disconnect(db_backend_handle_t* backend_handle, db_backend_handle_disconnect_t disconnect) {
	if (!backend_handle) {
		return 1;
	}

	backend_handle->disconnect = disconnect;
	return 0;
}

int db_backend_handle_set_create(db_backend_handle_t* backend_handle, db_backend_handle_create_t create) {
	if (!backend_handle) {
		return 1;
	}

	backend_handle->create = create;
	return 0;
}

int db_backend_handle_set_read(db_backend_handle_t* backend_handle, db_backend_handle_read_t read) {
	if (!backend_handle) {
		return 1;
	}

	backend_handle->read = read;
	return 0;
}

int db_backend_handle_set_update(db_backend_handle_t* backend_handle, db_backend_handle_update_t update) {
	if (!backend_handle) {
		return 1;
	}

	backend_handle->update = update;
	return 0;
}

int db_backend_handle_set_delete(db_backend_handle_t* backend_handle, db_backend_handle_delete_t delete) {
	if (!backend_handle) {
		return 1;
	}

	backend_handle->delete = delete;
	return 0;
}

int db_backend_handle_set_data(db_backend_handle_t* backend_handle, void* data) {
	if (!backend_handle) {
		return 1;
	}
	if (backend_handle->data) {
		return 1;
	}

	backend_handle->data = data;
	return 0;
}

int db_backend_handle_not_empty(const db_backend_handle_t* backend_handle) {
	if (!backend_handle) {
		return 1;
	}
	if (!backend_handle->initialize) {
		return 1;
	}
	if (!backend_handle->shutdown) {
		return 1;
	}
	if (!backend_handle->connect) {
		return 1;
	}
	if (!backend_handle->disconnect) {
		return 1;
	}
	if (!backend_handle->create) {
		return 1;
	}
	if (!backend_handle->read) {
		return 1;
	}
	if (!backend_handle->update) {
		return 1;
	}
	if (!backend_handle->delete) {
		return 1;
	}
	return 0;
}

/* DB BACKEND */

db_backend_t* db_backend_new(void) {
	db_backend_t* backend =
		(db_backend_t*)calloc(1, sizeof(db_backend_t));

	return backend;
}

void db_backend_free(db_backend_t* backend) {
	if (backend) {
		if (backend->name) {
			free(backend->name);
		}
		if (backend->handle) {
			db_backend_handle_free(backend->handle);
		}
		free(backend);
	}
}

const char* db_backend_name(const db_backend_t* backend) {
	if (!backend) {
		return NULL;
	}

	return backend->name;
}

const db_backend_handle_t* db_backend_handle(const db_backend_t* backend) {
	if (!backend) {
		return NULL;
	}

	return backend->handle;
}

int db_backend_set_name(db_backend_t* backend, const char* name) {
	char* new_name;

	if (!backend) {
		return 1;
	}

	if (!(new_name = strdup(name))) {
		return 1;
	}

	if (backend->name) {
		free(backend->name);
	}
	backend->name = new_name;
	return 0;
}

int db_backend_set_handle(db_backend_t* backend, db_backend_handle_t* handle) {
	if (!backend) {
		return 1;
	}
	if (backend->handle) {
		return 1;
	}

	backend->handle = handle;
	return 0;
}

int db_backend_not_empty(const db_backend_t* backend) {
	if (!backend) {
		return 1;
	}
	if (!backend->name) {
		return 1;
	}
	if (!backend->handle) {
		return 1;
	}
	return 0;
}

int db_backend_initialize(const db_backend_t* backend) {
	if (!backend) {
		return 1;
	}
	if (!backend->handle) {
		return 1;
	}

	return db_backend_handle_initialize(backend->handle);
}

int db_backend_shutdown(const db_backend_t* backend) {
	if (!backend) {
		return 1;
	}
	if (!backend->handle) {
		return 1;
	}

	return db_backend_handle_shutdown(backend->handle);
}

int db_backend_connect(const db_backend_t* backend, const db_configuration_list_t* configuration_list) {
	if (!backend) {
		return 1;
	}
	if (!configuration_list) {
		return 1;
	}
	if (!backend->handle) {
		return 1;
	}

	return db_backend_handle_connect(backend->handle, configuration_list);
}

int db_backend_disconnect(const db_backend_t* backend) {
	if (!backend) {
		return 1;
	}
	if (!backend->handle) {
		return 1;
	}

	return db_backend_handle_disconnect(backend->handle);
}

int db_backend_create(const db_backend_t* backend, const db_object_t* object) {
	if (!backend) {
		return 1;
	}
	if (!backend->handle) {
		return 1;
	}

	return db_backend_handle_create(backend->handle, object);
}

db_result_list_t* db_backend_read(const db_backend_t* backend, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
	if (!backend) {
		return NULL;
	}
	if (!object) {
		return NULL;
	}
	if (!backend->handle) {
		return NULL;
	}

	return db_backend_handle_read(backend->handle, object, join_list, clause_list);
}

int db_backend_update(const db_backend_t* backend, const db_object_t* object) {
	if (!backend) {
		return 1;
	}
	if (!backend->handle) {
		return 1;
	}

	return db_backend_handle_update(backend->handle, object);
}

int db_backend_delete(const db_backend_t* backend, const db_object_t* object) {
	if (!backend) {
		return 1;
	}
	if (!backend->handle) {
		return 1;
	}

	return db_backend_handle_delete(backend->handle, object);
}

/* DB BACKEND LIST */

db_backend_list_t* db_backend_list_new(void) {
	db_backend_list_t* backend_list =
		(db_backend_list_t*)calloc(1, sizeof(db_backend_list_t));

	return backend_list;
}

void db_backend_list_free(db_backend_list_t* backend_list) {
	if (backend_list) {
		if (backend_list->begin) {
			db_backend_t* this = backend_list->begin;
			db_backend_t* next = NULL;

			while (this) {
				next = this->next;
				db_backend_free(this);
				this = next;
			}
		}
		free(backend_list);
	}
}

void db_backend_list_free_shutdown(db_backend_list_t* backend_list) {
	if (backend_list) {
		if (backend_list->begin) {
			db_backend_t* this = backend_list->begin;
			db_backend_t* next = NULL;

			while (this) {
				next = this->next;
				db_backend_shutdown(this);
				db_backend_free(this);
				this = next;
			}
		}
		free(backend_list);
	}
}

int db_backend_list_add(db_backend_list_t* backend_list, db_backend_t* backend) {
	if (!backend_list) {
		return 1;
	}
	if (!backend) {
		return 1;
	}
	if (db_backend_not_empty(backend)) {
		return 1;
	}
	if (backend->next) {
		return 1;
	}

	if (backend_list->begin) {
		if (!backend_list->end) {
			return 1;
		}
		backend_list->end->next = backend;
		backend_list->end = backend;
	}
	else {
		backend_list->begin = backend;
		backend_list->end = backend;
	}

	return 0;
}

const db_backend_t* db_backend_list_find(const db_backend_list_t* backend_list, const char* name) {
	db_backend_t* backend;

	if (!backend_list) {
		return NULL;
	}
	if (!name) {
		return NULL;
	}

	backend = backend_list->begin;
	while (backend) {
		if (db_backend_not_empty(backend)) {
			return NULL;
		}
		if (!strcmp(backend->name, name)) {
			break;
		}
		backend = backend->next;
	}

	return backend;
}

/* DB BACKEND FACTORY */
db_backend_list_t* __backend_list = NULL;

/* TODO:
 * backend factory does not need a list
 * create new backend handle when requested
 * handle initialize and shutdown outside of backend handle
 */

int db_backend_factory_init(void) {
	db_backend_t* backend;

	if (!__backend_list) {
		if (!(__backend_list = db_backend_list_new())) {
			return 1;
		}

		if (!(backend = db_backend_new())) {
			db_backend_factory_end();
			return 1;
		}

		if (db_backend_set_name(backend, "sqlite")
			|| db_backend_set_handle(backend, db_backend_sqlite_new_handle())
			|| db_backend_initialize(backend)
			|| db_backend_list_add(__backend_list, backend))
		{
			db_backend_free(backend);
			db_backend_factory_end();
			return 1;
		}
	}
	return 0;
}

void db_backend_factory_end(void) {
	if (__backend_list) {
		db_backend_list_free_shutdown(__backend_list);
		__backend_list = NULL;
	}
}

const db_backend_t* db_backend_factory_get_backend(const char* name) {
	db_backend_t* backend;

	if (!__backend_list) {
		return NULL;
	}
	if (!name) {
		return NULL;
	}

	backend = __backend_list->begin;
	while (backend) {
		if (db_backend_not_empty(backend)) {
			return NULL;
		}
		if (!strcmp(backend->name, name)) {
			break;
		}
	}

	return backend;
}
