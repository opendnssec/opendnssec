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

#include "shared/log.h"

#include <stdlib.h>
#include <sqlite3.h>
#include <stdio.h>
#include <unistd.h>

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

int db_backend_sqlite_create(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

	if (!__sqlite3_initialized) {
		return 1;
	}
	if (!backend_sqlite) {
		return 1;
	}

	return 1;
}

db_result_list_t* db_backend_sqlite_read(void* data, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;
	const db_object_field_t* object_field;
	const db_clause_t* clause;
	const db_join_t* join;
	char sql[4*1024];
	char* sqlp;
	int ret, left, bind, first, fields;
	sqlite3_stmt *statement;
	db_result_list_t* result_list;
	db_result_t* result;
	db_value_set_t* value_set = NULL;

	if (!__sqlite3_initialized) {
		return NULL;
	}
	if (!backend_sqlite) {
		return NULL;
	}
	if (!object) {
		return NULL;
	}

	left = sizeof(sql);
	sqlp = sql;

	if ((ret = snprintf(sqlp, left, "SELECT")) >= left) {
		return NULL;
	}
	sqlp += ret;
	left -= ret;

	object_field = db_object_field_list_begin(db_object_object_field_list(object));
	first = 1;
	fields = 0;
	while (object_field) {
		if (first) {
			if ((ret = snprintf(sqlp, left, " %s.%s", db_object_table(object), db_object_field_name(object_field))) >= left) {
				return NULL;
			}
			first = 0;
		}
		else {
			if ((ret = snprintf(sqlp, left, ", %s.%s", db_object_table(object), db_object_field_name(object_field))) >= left) {
				return NULL;
			}
		}
		sqlp += ret;
		left -= ret;

		object_field = db_object_field_next(object_field);
		fields++;
	}

	if ((ret = snprintf(sqlp, left, " FROM %s", db_object_table(object))) >= left) {
		return NULL;
	}
	sqlp += ret;
	left -= ret;

	if (join_list) {
		join = db_join_list_begin(join_list);
		while (join) {
			if ((ret = snprintf(sqlp, left, " INNER JOIN %s ON %s.%s = %s.%s",
				db_join_to_table(join),
				db_join_to_table(join),
				db_join_to_field(join),
				db_join_from_table(join),
				db_join_from_field(join))) >= left)
			{
				return NULL;
			}
			sqlp += ret;
			left -= ret;
			join = db_join_next(join);
		}
	}

	if (clause_list) {
		clause = db_clause_list_begin(clause_list);
		first = 1;

		if (clause) {
			if ((ret = snprintf(sqlp, left, " WHERE")) >= left) {
				return NULL;
			}
			sqlp += ret;
			left -= ret;
		}

		while (clause) {
			if (first) {
				first = 0;
			}
			else {
			    switch (db_clause_operator(clause)) {
			    case DB_CLAUSE_OPERATOR_AND:
                    if ((ret = snprintf(sqlp, left, " AND")) >= left) {
                        return NULL;
                    }
                    sqlp += ret;
                    left -= ret;
                    break;

			    case DB_CLAUSE_OPERATOR_OR:
	                if ((ret = snprintf(sqlp, left, " OR")) >= left) {
	                    return NULL;
	                }
	                sqlp += ret;
	                left -= ret;
	                break;

			    default:
			        return NULL;
			    }
			}
			switch (db_clause_type(clause)) {
			case DB_CLAUSE_EQ:
				switch (db_clause_value_type(clause)) {
				case DB_TYPE_PRIMARY_KEY:
				case DB_TYPE_INTEGER:
					if ((ret = snprintf(sqlp, left, " %s.%s = ?",
						(db_clause_table(clause) ? db_clause_table(clause) : db_object_table(object)),
						db_clause_field(clause))) >= left)
					{
						return NULL;
					}
					sqlp += ret;
					left -= ret;
					break;

				default:
					return NULL;
				}
				break;

			default:
				return NULL;
			}
			clause = db_clause_next(clause);
		}
	}

	ret = sqlite3_prepare_v2(backend_sqlite->db,
		sql,
		sizeof(sql),
		&statement,
		NULL);
	if (ret != SQLITE_OK) {
	    ods_log_info("DB SQL %s", sql);
		ods_log_info("DB Err %d\n", ret);
		return NULL;
	}

	if (clause_list) {
		clause = db_clause_list_begin(clause_list);
		bind = 1;
		while (clause) {
			switch (db_clause_type(clause)) {
			case DB_CLAUSE_EQ:
				switch (db_clause_value_type(clause)) {
				case DB_TYPE_PRIMARY_KEY:
				case DB_TYPE_INTEGER:
					int value;
					if (db_value_to_int(db_clause_get_value(clause), &value)) {
						sqlite3_finalize(statement);
						return NULL;
					}
					ret = sqlite3_bind_int(statement, bind++, value);
					if (ret != SQLITE_OK) {
						sqlite3_finalize(statement);
						return NULL;
					}
					break;

				default:
					sqlite3_finalize(statement);
					return NULL;
				}
				break;

			default:
				sqlite3_finalize(statement);
				return NULL;
			}
			clause = db_clause_next(clause);
		}
	}

	if (!(result_list = db_result_list_new())) {
		sqlite3_finalize(statement);
		return NULL;
	}
	ret = sqlite3_step(statement);
	while (ret == SQLITE_ROW || ret == SQLITE_BUSY) {
		if (ret == SQLITE_BUSY) {
			usleep(100);
			ret = sqlite3_step(statement);
			continue;
		}
		if (!(result = db_result_new())
			|| !(value_set = db_value_set_new(fields))
			|| db_result_set_value_set(result, value_set))
		{
			db_result_free(result);
			db_value_set_free(value_set);
			db_result_list_free(result_list);
			sqlite3_finalize(statement);
			return NULL;
		}
		if (db_result_list_add(result_list, result)) {
			db_result_free(result);
			db_result_list_free(result_list);
			sqlite3_finalize(statement);
			return NULL;
		}
		object_field = db_object_field_list_begin(db_object_object_field_list(object));
		bind = 0;
		while (object_field) {
			int integer;
			const char* string;

			switch (db_object_field_type(object_field)) {
			case DB_TYPE_PRIMARY_KEY:
			case DB_TYPE_INTEGER:
				integer = sqlite3_column_int(statement, bind);
				ret = sqlite3_errcode(backend_sqlite->db);
				if ((ret != SQLITE_OK && ret != SQLITE_ROW && ret != SQLITE_DONE)
					|| db_value_from_int(db_value_set_get(value_set, bind), integer))
				{
					db_result_list_free(result_list);
					sqlite3_finalize(statement);
					return NULL;
				}
				break;

			case DB_TYPE_STRING:
				string = (const char*)sqlite3_column_text(statement, bind);
				ret = sqlite3_errcode(backend_sqlite->db);
				if (!string
					|| (ret != SQLITE_OK && ret != SQLITE_ROW && ret != SQLITE_DONE)
					|| db_value_from_string(db_value_set_get(value_set, bind), string))
				{
					db_result_list_free(result_list);
					sqlite3_finalize(statement);
					return NULL;
				}
				break;

			case DB_TYPE_UNKNOWN:
			default:
				db_result_list_free(result_list);
				sqlite3_finalize(statement);
				return NULL;
				break;
			}
			object_field = db_object_field_next(object_field);
			bind++;
		}
		ret = sqlite3_step(statement);
	}
	if (ret != SQLITE_DONE) {
		db_result_list_free(result_list);
		sqlite3_finalize(statement);
		return NULL;
	}

	sqlite3_finalize(statement);
	return result_list;
}

int db_backend_sqlite_update(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

	if (!__sqlite3_initialized) {
		return 1;
	}
	if (!backend_sqlite) {
		return 1;
	}

	return 1;
}

int db_backend_sqlite_delete(void* data, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

	if (!__sqlite3_initialized) {
		return 1;
	}
	if (!backend_sqlite) {
		return 1;
	}

	return 1;
}

void db_backend_sqlite_free(void* data) {
	db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

	if (backend_sqlite) {
		if (backend_sqlite->db) {
			(void)db_backend_sqlite_disconnect(backend_sqlite);
		}
		free(backend_sqlite);
	}
}

int db_backend_sqlite_transaction_begin(void* data) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

    return 1;
}

int db_backend_sqlite_transaction_commit(void* data) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

    return 1;
}

int db_backend_sqlite_transaction_rollback(void* data) {
    db_backend_sqlite_t* backend_sqlite = (db_backend_sqlite_t*)data;

    return 1;
}

db_backend_handle_t* db_backend_sqlite_new_handle(void) {
	db_backend_handle_t* backend_handle = NULL;
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
			|| db_backend_handle_set_delete(backend_handle, db_backend_sqlite_delete)
			|| db_backend_handle_set_free(backend_handle, db_backend_sqlite_free)
            || db_backend_handle_set_transaction_begin(backend_handle, db_backend_sqlite_transaction_begin)
            || db_backend_handle_set_transaction_commit(backend_handle, db_backend_sqlite_transaction_commit)
            || db_backend_handle_set_transaction_rollback(backend_handle, db_backend_sqlite_transaction_rollback))
		{
			db_backend_handle_free(backend_handle);
			free(backend_sqlite);
			return NULL;
		}
	}
	return backend_handle;
}
