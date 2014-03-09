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

db_value_t* db_value_new() {
	db_value_t* value =
		(db_value_t*)calloc(1, sizeof(db_value_t));

	return value;
}

void db_value_free(db_value_t* value) {
	if (value) {
		/* TODO: free data? */
		free(value);
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

int db_value_empty(const db_value_t* value) {
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
	return 1;
}

int db_value_to_string(const db_value_t* value, char** to_string, size_t* max_size) {
	return 1;
}
