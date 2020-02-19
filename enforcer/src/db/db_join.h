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
 * Get the from table name of a database join.
 * \param[in] join a db_join_t pointer.
 * \return a character pointer or NULL on error or if no from table name has
 * been set.
 */
extern const char* db_join_from_table(const db_join_t* join);

/**
 * Get the from field name of a database join.
 * \param[in] join a db_join_t pointer.
 * \return a character pointer or NULL on error or if no from field name has
 * been set.
 */
extern const char* db_join_from_field(const db_join_t* join);

/**
 * Get the to table name of a database join.
 * \param[in] join a db_join_t pointer.
 * \return a character pointer or NULL on error or if no to table name has been
 * set.
 */
extern const char* db_join_to_table(const db_join_t* join);

/**
 * Get the to field name of a database join.
 * \param[in] join a db_join_t pointer.
 * \return a character pointer or NULL on error or if no to field name has been
 * set.
 */
extern const char* db_join_to_field(const db_join_t* join);

/**
 * Get the next database join connected in a database join list.
 * \param[in] join a db_join_t pointer.
 * \return a db_join_t pointer or NULL on error or if there are no more database
 * joins in the list.
 */
extern const db_join_t* db_join_next(const db_join_t* join);

/**
 * A list of database joins.
 */
struct db_join_list {
    db_join_t* begin;
    db_join_t* end;
};

/**
 * Return the first database join in a database join list.
 * \param[in] join_list a db_join_list_t pointer.
 * \return a db_join_t pointer or NULL on error or if the list is empty.
 */
extern const db_join_t* db_join_list_begin(const db_join_list_t* join_list);

#endif
