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

#ifndef __db_clause_h
#define __db_clause_h

/**
 * The clause operation to make on the value.
 */
typedef enum {
    /**
     * Empty, not set or unknown.
     */
    DB_CLAUSE_UNKNOWN,
    /**
     * ==
     */
    DB_CLAUSE_EQUAL,
    /**
     * !=
     */
    DB_CLAUSE_NOT_EQUAL,
    /**
     * <
     */
    DB_CLAUSE_LESS_THEN,
    /**
     * <=
     */
    DB_CLAUSE_LESS_OR_EQUAL,
    /**
     * >=
     */
    DB_CLAUSE_GREATER_OR_EQUAL,
    /**
     * >
     */
    DB_CLAUSE_GREATER_THEN,
    /**
     * Is null.
     */
    DB_CLAUSE_IS_NULL,
    /**
     * Is not null.
     */
    DB_CLAUSE_IS_NOT_NULL,
    /**
     * This adds a nested clause as in wrapping the content with ( ).
     */
    DB_CLAUSE_NESTED
} db_clause_type_t;

#define DB_CLAUSE_EQ DB_CLAUSE_EQUAL
#define DB_CLAUSE_NE DB_CLAUSE_NOT_EQUAL
#define DB_CLAUSE_LT DB_CLAUSE_LESS_THEN
#define DB_CLAUSE_LE DB_CLAUSE_LESS_OR_EQUAL
#define DB_CLAUSE_GE DB_CLAUSE_GREATER_OR_EQUAL
#define DB_CLAUSE_GT DB_CLAUSE_GREATER_THEN

/**
 * The operator to do between the previous clause and this one.
 */
typedef enum {
    /**
     * Empty, not set or unknown.
     */
    DB_CLAUSE_OPERATOR_UNKNOWN,
    /**
     * ||
     */
    DB_CLAUSE_OPERATOR_AND,
    /**
     * &&
     */
    DB_CLAUSE_OPERATOR_OR
} db_clause_operator_t;

#define DB_CLAUSE_OP_AND DB_CLAUSE_OPERATOR_AND
#define DB_CLAUSE_OP_OR  DB_CLAUSE_OPERATOR_OR

struct db_clause;
struct db_clause_list;
typedef struct db_clause db_clause_t;
typedef struct db_clause_list db_clause_list_t;

#include "db_value.h"

/**
 * A database clause, describes the comparison of a database object field and a
 * value.
 */
struct db_clause {
    db_clause_t* next;
    char* table;
    char* field;
    db_clause_type_t type;
    db_value_t value;
    db_clause_operator_t clause_operator;
    db_clause_list_t* clause_list;
};

/**
 * Create a new database clause.
 * \return a db_clause_t pointer or NULL on error.
 */
extern db_clause_t* db_clause_new(void);

/**
 * Delete a database clause.
 * \param[in] clause a db_clause_t pointer.
 */
extern void db_clause_free(db_clause_t* clause);

/**
 * Get the field name of a database clause.
 * \param[in] a db_clause_t pointer.
 * \return a character pointer or NULL on error or if no field name has been set.
 */
extern const char* db_clause_field(const db_clause_t* clause);

/**
 * Get the database clause type of a database clause.
 * \param[in] a db_clause_t pointer.
 * \return a db_clause_type_t.
 */
extern db_clause_type_t db_clause_type(const db_clause_t* clause);

/**
 * Get the database value of a database value.
 * \param[in] a db_clause_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
extern const db_value_t* db_clause_value(const db_clause_t* clause);

/**
 * Get the database clause operator of a database clause.
 * \param[in] a db_clause_t pointer.
 * \return a db_clause_operator_t.
 */
extern db_clause_operator_t db_clause_operator(const db_clause_t* clause);

/**
 * Get the database clause list of a database clause, this is used for nested
 * database clauses.
 * \param[in] a db_clause_t pointer.
 * \return a db_clause_list_t pointer or NULL on error or if no database clause
 * list has been set.
 */
extern const db_clause_list_t* db_clause_list(const db_clause_t* clause);

/**
 * Set the field name of a database clause.
 * \param[in] a db_clause_t pointer.
 * \param[in] field a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_clause_set_field(db_clause_t* clause, const char* field);

/**
 * Set the database clause type of a database clause.
 * \param[in] a db_clause_t pointer.
 * \param[in] type a db_clause_type_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_clause_set_type(db_clause_t* clause, db_clause_type_t type);

/**
 * Set the database clause operator of a database clause.
 * \param[in] a db_clause_t pointer.
 * \param[in] clause_operator a db_clause_operator_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_clause_set_operator(db_clause_t* clause, db_clause_operator_t clause_operator);

/**
 * Check if the database clause is not empty.
 * \param[in] a db_clause_t pointer.
 * \return DB_ERROR_* if empty, otherwise DB_OK.
 */
extern int db_clause_not_empty(const db_clause_t* clause);

/**
 * Return the next database clause connected in a database clause list.
 * \param[in] a db_clause_t pointer.
 * \return a db_clause_t pointer or NULL on error or if there are no more
 * database clauses in the list.
 */
extern const db_clause_t* db_clause_next(const db_clause_t* clause);

/**
 * Get the writable database value of a database clause.
 * \param[in] a db_clause_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
extern db_value_t* db_clause_get_value(db_clause_t* clause);

/**
 * A list of database clauses.
 */
struct db_clause_list {
    db_clause_t* begin;
    db_clause_t* end;
};

/**
 * Create a new database clause list.
 * \return a db_clause_list_t pointer or NULL on error.
 */
extern db_clause_list_t* db_clause_list_new(void);

/**
 * Delete a database clause list and all database clauses in the list.
 * \param[in] clause_list a db_clause_list_t pointer.
 */
extern void db_clause_list_free(db_clause_list_t* clause_list);

/**
 * Add a database clause to a database clause list, this takes over the
 * ownership of the database clause.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \param[in] a db_clause_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_clause_list_add(db_clause_list_t* clause_list, db_clause_t* clause);

/**
 * Return the first database clause of a database clause list.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a db_clause_t pointer or NULL on error or if the list is empty.
 */
extern const db_clause_t* db_clause_list_begin(const db_clause_list_t* clause_list);

#endif
