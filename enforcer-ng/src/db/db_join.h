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

#ifndef __db_join_h
#define __db_join_h

#ifdef __cplusplus
extern "C" {
#endif

struct db_join;
struct db_join_list;
typedef struct db_join db_join_t;
typedef struct db_join_list db_join_list_t;

#ifdef __cplusplus
}
#endif

#include "db_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * TODO
 */
struct db_join {
    db_join_t* next;
    char* from_table;
    char* from_field;
    char* to_table;
    char* to_field;
};

/**
 * TODO
 * \param[in] void TODO 
 * \return `db_join_t*` TODO
 */
db_join_t* db_join_new(void);

/**
 * TODO
 * \param[in] join TODO 
 * \return `void` TODO
 */
void db_join_free(db_join_t* join);

/**
 * TODO
 * \param[in] join TODO 
 * \return `const char*` TODO
 */
const char* db_join_from_table(const db_join_t* join);

/**
 * TODO
 * \param[in] join TODO 
 * \return `const char*` TODO
 */
const char* db_join_from_field(const db_join_t* join);

/**
 * TODO
 * \param[in] join TODO 
 * \return `const char*` TODO
 */
const char* db_join_to_table(const db_join_t* join);

/**
 * TODO
 * \param[in] join TODO 
 * \return `const char*` TODO
 */
const char* db_join_to_field(const db_join_t* join);

/**
 * TODO
 * \param[in] join TODO 
 * \param[in] from_table TODO 
 * \return `int` TODO
 */
int db_join_set_from_table(db_join_t* join, const char* from_table);

/**
 * TODO
 * \param[in] join TODO 
 * \param[in] from_field TODO 
 * \return `int` TODO
 */
int db_join_set_from_field(db_join_t* join, const char* from_field);

/**
 * TODO
 * \param[in] join TODO 
 * \param[in] to_table TODO 
 * \return `int` TODO
 */
int db_join_set_to_table(db_join_t* join, const char* to_table);

/**
 * TODO
 * \param[in] join TODO 
 * \param[in] to_field TODO 
 * \return `int` TODO
 */
int db_join_set_to_field(db_join_t* join, const char* to_field);

/**
 * TODO
 * \param[in] join TODO 
 * \return `int` TODO
 */
int db_join_not_empty(const db_join_t* join);

/**
 * TODO
 * \param[in] join TODO 
 * \return `const db_join_t*` TODO
 */
const db_join_t* db_join_next(const db_join_t* join);

/**
 * TODO
 */
struct db_join_list {
    db_join_t* begin;
    db_join_t* end;
};

/**
 * TODO
 * \param[in] void TODO 
 * \return `db_join_list_t*` TODO
 */
db_join_list_t* db_join_list_new(void);

/**
 * TODO
 * \param[in] join_list TODO 
 * \return `void` TODO
 */
void db_join_list_free(db_join_list_t* join_list);

/**
 * TODO
 * \param[in] join_list TODO 
 * \param[in] join TODO 
 * \return `int` TODO
 */
int db_join_list_add(db_join_list_t* join_list, db_join_t* join);

/**
 * TODO
 * \param[in] join_list TODO 
 * \return `const db_join_t*` TODO
 */
const db_join_t* db_join_list_begin(const db_join_list_t* join_list);

#ifdef __cplusplus
}
#endif

#endif
