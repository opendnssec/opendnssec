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
		free(backend_handle);
	}
}

int __db_backend_handle_connect(db_backend_handle_t* backend_handle, const db_configuration_list_t* configuration_list) {
	return 1;
}

db_backend_handle_connect_t db_backend_handle_connect(db_backend_handle_t* backend_handle) {
	if (!backend_handle) {
		return __db_backend_handle_connect;
	}
	if (!backend_handle->connect) {
		return __db_backend_handle_connect;
	}

	return backend_handle->connect;
}

int __db_backend_handle_disconnect(db_backend_handle_t* backend_handle) {
	return 1;
}

db_backend_handle_disconnect_t db_backend_handle_disconnect(db_backend_handle_t* backend_handle) {
	if (!backend_handle) {
		return __db_backend_handle_disconnect;
	}
	if (!backend_handle->disconnect) {
		return __db_backend_handle_disconnect;
	}

	return backend_handle->disconnect;
}

int db_backend_handle_set_connect(db_backend_handle_t* backend_handle, db_backend_handle_connect_t new_connect) {
	if (!backend_handle) {
		return 1;
	}

	backend_handle->connect = new_connect;
	return 0;
}

int db_backend_handle_set_disconnect(db_backend_handle_t* backend_handle, db_backend_handle_disconnect_t new_disconnect) {
	if (!backend_handle) {
		return 1;
	}

	backend_handle->disconnect = new_disconnect;
	return 0;
}

int db_backend_handle_not_empty(db_backend_handle_t* backend_handle) {
	if (!backend_handle) {
		return 1;
	}
	if (!backend_handle->connect) {
		return 1;
	}
	if (!backend_handle->disconnect) {
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

const char* db_backend_name(db_backend_t* backend) {
	if (!backend) {
		return NULL;
	}

	return backend->name;
}

const db_backend_handle_t* db_backend_handle(db_backend_t* backend) {
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

int db_backend_set_handle(db_backend_t* backend, db_backend_handle_t* new_handle) {
	if (!backend) {
		return 1;
	}
	if (backend->handle) {
		return 1;
	}

	backend->handle = new_handle;
	return 0;
}

int db_backend_not_empty(db_backend_t* backend) {
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

db_result_list_t* db_backend_query(db_backend_t* backend, db_object_t* object) {
	if (!backend) {
		return 1;
	}
	if (!backend->handle) {
		return 1;
	}

	return backend->handle->query(backend->handle, object);
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

	if (backend_list->begin) {
		backend->next = backend_list->begin;
	}
	backend_list->begin = backend;

	return 0;
}

const db_backend_t* db_backend_list_find(db_backend_list_t* backend_list, const char* name) {
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
	}

	return backend;
}

/* DB BACKEND FACTORY */
db_backend_list_t* __backend_list = NULL;

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
		db_backend_list_free(__backend_list);
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
