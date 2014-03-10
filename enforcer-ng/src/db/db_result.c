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

/* DB RESULT */

db_result_t* db_result_new(void) {
	db_result_t* result =
		(db_result_t*)calloc(1, sizeof(db_result_t));

	return result;
}

void db_result_free(db_result_t* result) {
	if (result) {
		if (result->value_set) {
			db_value_set_free(result->value_set);
		}
		free(result);
	}
}

const db_value_set_t* db_result_value_set(const db_result_t* result) {
	if (!result) {
		return NULL;
	}

	return result->value_set;
}

int db_result_set_value_set(db_result_t* result, db_value_set_t* value_set) {
	if (!result) {
		return 1;
	}
	if (!value_set) {
		return 1;
	}
	if (result->value_set) {
		return 1;
	}

	result->value_set = value_set;
	return 0;
}

int db_result_not_empty(const db_result_t* result) {
	if (!result) {
		return 1;
	}
	if (!result->value_set) {
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
	if (result->next) {
		return 1;
	}

	if (result_list->begin) {
		if (!result_list->end) {
			return 1;
		}
		result_list->end->next = result;
		result_list->end = result;
	}
	else {
		result_list->begin = result;
		result_list->end = result;
	}

	return 0;
}

const db_result_t* db_result_list_begin(const db_result_list_t* result_list) {
	if (!result_list) {
		return NULL;
	}

	return result_list->begin;
}
