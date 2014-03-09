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

#ifndef __db_result_h
#define __db_result_h

typedef struct db_result_header db_result_header_t;
typedef struct db_result_data db_result_data_t;
typedef struct db_result db_result_t;
typedef struct db_result_list db_result_list_t;

#include "db_type.h"

#include <stdlib.h>

typedef struct db_result_header {
	char** header;
	size_t size;
} db_result_header_t;

db_result_header_t* db_result_header_new(char**, size_t);
void db_result_header_free(db_result_header_t*);

typedef struct db_result_data {
	db_type_t type;
	void* value;
} db_result_data_t;

db_result_data_t* db_result_data_new(void);
void db_result_data_free(db_result_data_t*);
db_type_t db_result_data_type(const db_result_data_t*);
void* db_result_data_value(const db_result_data_t*);
int db_result_data_set_type(db_result_data_t*, db_type_t);
int db_result_data_set_value(db_result_data_t*, void*);
int db_result_data_not_empty(const db_result_data_t*);

typedef struct db_result {
	db_result_t* next;
	db_result_data_t** data;
	size_t size;
} db_result_t;

db_result_t* db_result_new(db_result_data_t**, size_t);
void db_result_free(db_result_t*);
int db_result_not_empty(const db_result_t*);
const db_result_t* db_result_next(const db_result_t*);

typedef struct db_result_list {
	db_result_header_t* header;
	db_result_t* begin;
	db_result_t* end;
} db_result_list_t;

db_result_list_t* db_result_list_new(void);
void db_result_list_free(db_result_list_t*);
int db_result_list_add(db_result_list_t*, db_result_t*);
const db_result_t* db_result_list_begin(const db_result_list_t*);

#endif
