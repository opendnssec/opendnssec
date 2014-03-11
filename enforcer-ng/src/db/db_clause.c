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

#include "db_clause.h"

#include <stdlib.h>
#include <string.h>

/* DB CLAUSE */

db_clause_t* db_clause_new(void) {
	db_clause_t* clause =
		(db_clause_t*)calloc(1, sizeof(db_clause_t));

	if (clause) {
		clause->type = DB_CLAUSE_UNKNOWN;
		clause->operator = DB_CLAUSE_OPERATOR_AND;
	}

	return clause;
}

void db_clause_free(db_clause_t* clause) {
	if (clause) {
		if (clause->table) {
			free(clause->table);
		}
		if (clause->field) {
			free(clause->field);
		}
		free(clause);
	}
}

const char* db_clause_table(const db_clause_t* clause) {
	if (!clause) {
		return NULL;
	}

	return clause->table;
}

const char* db_clause_field(const db_clause_t* clause) {
	if (!clause) {
		return NULL;
	}

	return clause->field;
}

db_clause_type_t db_clause_type(const db_clause_t* clause) {
	if (!clause) {
		return DB_CLAUSE_UNKNOWN;
	}

	return clause->type;
}

db_type_t db_clause_value_type(const db_clause_t* clause) {
	if (!clause) {
		return DB_TYPE_UNKNOWN;
	}

	return clause->value_type;
}

const void* db_clause_value(const db_clause_t* clause) {
	if (!clause) {
		return NULL;
	}

	return clause->value;
}

db_clause_operator_t db_clause_operator(const db_clause_t* clause) {
	if (!clause) {
		return DB_CLAUSE_OPERATOR_UNKNOWN;
	}

	return clause->operator;
}

int db_clause_set_table(db_clause_t* clause, const char* table) {
	char* new_table;

	if (!clause) {
		return 1;
	}

	if (!(new_table = strdup(table))) {
		return 1;
	}

	if (clause->table) {
		free(clause->table);
	}
	clause->table = new_table;
	return 0;
}

int db_clause_set_field(db_clause_t* clause, const char* field) {
	char* new_field;

	if (!clause) {
		return 1;
	}

	if (!(new_field = strdup(field))) {
		return 1;
	}

	if (clause->field) {
		free(clause->field);
	}
	clause->field = new_field;
	return 0;
}

int db_clause_set_type(db_clause_t* clause, db_clause_type_t type) {
	if (!clause) {
		return 1;
	}

	clause->type = type;
	return 0;
}

int db_clause_set_value_type(db_clause_t* clause, db_type_t value_type) {
	if (!clause) {
		return 1;
	}

	clause->value_type = value_type;
	return 0;
}

int db_clause_set_value(db_clause_t* clause, void* value) {
	if (!clause) {
		return 1;
	}

	clause->value = value;
	return 0;
}

int db_clause_set_operator(db_clause_t* clause, db_clause_operator_t operator) {
	if (!clause) {
		return 1;
	}
	if (operator == DB_CLAUSE_OPERATOR_UNKNOWN) {
		return 1;
	}

	clause->operator = operator;
	return 0;
}

int db_clause_not_empty(const db_clause_t* clause) {
	if (!clause) {
		return 1;
	}
	if (!clause->field) {
		return 1;
	}
	if (clause->type == DB_CLAUSE_UNKNOWN) {
		return 1;
	}
	return 0;
}

const db_clause_t* db_clause_next(const db_clause_t* clause) {
	if (!clause) {
		return NULL;
	}

	return clause->next;
}

/* DB CLAUSE LIST */

db_clause_list_t* db_clause_list_new(void) {
	db_clause_list_t* clause_list =
		(db_clause_list_t*)calloc(1, sizeof(db_clause_list_t));

	return clause_list;
}

void db_clause_list_free(db_clause_list_t* clause_list) {
	if (clause_list) {
		if (clause_list->begin) {
			db_clause_t* this = clause_list->begin;
			db_clause_t* next = NULL;

			while (this) {
				next = this->next;
				db_clause_free(this);
				this = next;
			}
		}
		free(clause_list);
	}
}

int db_clause_list_add(db_clause_list_t* clause_list, db_clause_t* clause) {
	if (!clause_list) {
		return 1;
	}
	if (!clause) {
		return 1;
	}
	if (db_clause_not_empty(clause)) {
		return 1;
	}
	if (clause->next) {
		return 1;
	}

	if (clause_list->begin) {
		if (!clause_list->end) {
			return 1;
		}
		clause_list->end->next = clause;
		clause_list->end = clause;
	}
	else {
		clause_list->begin = clause;
		clause_list->end = clause;
	}

	return 0;
}

const db_clause_t* db_clause_list_begin(const db_clause_list_t* clause_list) {
	if (!clause_list) {
		return NULL;
	}

	return clause_list->begin;
}
