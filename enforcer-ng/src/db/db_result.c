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

/* DB RESULT DATA */

db_result_data_t* db_result_data_new(void) {
	db_result_data_t* result_data =
		(db_result_data_t*)calloc(1, sizeof(db_result_data_t));

	if (result_data) {
		result_data->type = DB_TYPE_UNKNOWN;
	}

	return result_data;
}

void db_result_data_free(db_result_data_t* result_data) {
	if (result_data) {
		if (result_data->value) {
			free(result_data->value);
		}
		free(result_data);
	}
}

db_type_t db_result_data_type(const db_result_data_t* result_data) {
	if (!result_data) {
		return DB_TYPE_UNKNOWN;
	}

	return result_data->type;
}

void* db_result_data_value(const db_result_data_t* result_data) {
	if (!result_data) {
		return NULL;
	}

	return result_data->value;
}

int db_result_data_set_type(db_result_data_t* result_data, db_type_t type) {
	if (!result_data) {
		return 1;
	}
	if (result_data->type == DB_TYPE_UNKNOWN) {
		return 1;
	}

	result_data->type = type;
	return 0;
}

int db_result_data_set_value(db_result_data_t* result_data, void* value) {
	if (!result_data) {
		return 1;
	}
	if (result_data->value) {
		return 1;
	}

	result_data->value = value;
	return 0;
}

int db_result_data_not_empty(const db_result_data_t* result_data) {
	if (!result_data) {
		return 1;
	}
	if (result_data->type == DB_TYPE_UNKNOWN) {
		return 1;
	}
	if (result_data->value) {
		return 1;
	}

	return 0;
}

/* DB RESULT */

db_result_t* db_result_new(db_result_data_t** data, size_t size) {
	db_result_t* result =
		(db_result_t*)calloc(1, sizeof(db_result_t));

	if (result) {
		result->data = data;
		result->size = size;
	}

	return result;
}

void db_result_free(db_result_t* result) {
	if (result) {
		if (result->data) {
			if (result->size) {
				int i;
				for (i=0; i<result->size; i++) {
					db_result_data_free(result->data[i]);
				}
			}
			free(result->data);
		}
		free(result);
	}
}

int db_result_not_empty(const db_result_t* result) {
	if (!result) {
		return 1;
	}
	if (!result->size) {
		return 1;
	}
	if (!result->data) {
		return 1;
	}
	return 0;
}

const db_result_t* db_result_next(const db_result_t* result) {
	if (!result) {
		return NULL;
	}

	return result->next;
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

const db_result_t* db_result_list_begin(const db_result_list_t* result_list) {
	if (!result_list) {
		return NULL;
	}

	return result_list->begin;
}
