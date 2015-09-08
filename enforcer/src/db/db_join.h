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

struct db_join;
struct db_join_list;
typedef struct db_join db_join_t;
typedef struct db_join_list db_join_list_t;

#include "db_type.h"

/**
 * A database join description.
 */
struct db_join {
    db_join_t* next;
    char* from_table;
    char* from_field;
    char* to_table;
    char* to_field;
};

/**
 * Delete a database join.
 * \param[in] join a db_join_t pointer.
 */
void db_join_free(db_join_t* join);

/**
 * Set the from table name of a database join. from_table will be copied.
 * On error join is left untouched. Asserts on NULL input;
 * \param[in] join a db_join_t pointer.
 * \param[in] from_table a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_join_set_from_table(db_join_t* join, const char* from_table);

/**
 * Set the from field name of a database join.
 * \param[in] join a db_join_t pointer.
 * \param[in] from_field a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_join_set_from_field(db_join_t* join, const char* from_field);

/**
 * Set the to table name of a database join.
 * \param[in] join a db_join_t pointer.
 * \param[in] to_table a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_join_set_to_table(db_join_t* join, const char* to_table);

/**
 * Set the to field of a database join.
 * \param[in] join a db_join_t pointer.
 * \param[in] to_field a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_join_set_to_field(db_join_t* join, const char* to_field);

/**
 * Check if the database join is not empty.
 * \param[in] join a db_join_t pointer.
 * \return false if empty, otherwise true.
 */
int db_join_not_empty(const db_join_t* join);

/**
 * A list of database joins.
 */
struct db_join_list {
    db_join_t* begin;
    db_join_t* end;
};

/**
 * Delete a database join list and all database joins within the list.
 * \param[in] join_list a db_join_list_t pointer.
 */
void db_join_list_free(db_join_list_t* join_list);

/**
 * Add a database join to a database join list, this takes over the ownership
 * of the database join.
 * \param[in] join_list a db_join_list_t pointer.
 * \param[in] join a db_join_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int db_join_list_add(db_join_list_t* join_list, db_join_t* join);

#endif
