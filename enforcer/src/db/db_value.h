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

#ifndef __db_value_h
#define __db_value_h

struct db_value;
struct db_value_set;
typedef struct db_value db_value_t;
typedef struct db_value_set db_value_set_t;

#include "config.h"

#include "db_type.h"
#include "db_enum.h"

#include <stdlib.h>

/**
 * A container for a database value.
 */
struct db_value {
    db_type_t type;
    int primary_key;
    char* text;
    db_type_int32_t int32;
    db_type_uint32_t uint32;
    db_type_int64_t int64;
    db_type_uint64_t uint64;
    int enum_value;
    const char* enum_text;
};

#define DB_VALUE_EMPTY { DB_TYPE_EMPTY, 0, NULL, 0, 0, 0, 0, 0, NULL }

/**
 * Create a new database value.
 * \return a db_value_t pointer or NULL on error.
 */
extern db_value_t* db_value_new(void);

/**
 * Delete a database value.
 * \param[in] value a db_value_t pointer.
 */
extern void db_value_free(db_value_t* value);

/**
 * Reset a database value, releasing all interal resources and marking it empty.
 * \param[in] value a db_value_t pointer.
 */
extern void db_value_reset(db_value_t* value);

/**
 * Copy the contant from one database value into another.
 * \param[in] value a db_value_t pointer to copy to.
 * \param[in] from_value a db_value_t pointer to copy from.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_copy(db_value_t* value, const db_value_t* from_value);

/**
 * Compare two database values A and B. Sets `result` with less than, equal to,
 * or greater than zero if A is found, respectively, to be less than, to match,
 * or be greater than B.
 * \param[in] value_a a db_value_t pointer.
 * \param[in] value_b a db_value_t pointer.
 * \param[out] result an integer pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_cmp(const db_value_t* value_a, const db_value_t* value_b, int* result);

/**
 * Get the type of a database value.
 * \param[in] value a db_value_t pointer.
 * \return a db_type_t.
 */
extern db_type_t db_value_type(const db_value_t* value);

/**
 * Get a pointer for the 32bit integer in a database value.
 * \param[in] value a db_value_t pointer.
 * \return a db_type_int32_t pointer or NULL on error, if empty or not a 32bit
 * integer value.
 * TODO: unit test
 */
extern const db_type_int32_t* db_value_int32(const db_value_t* value);

/**
 * Get a pointer for the unsigned 32bit integer in a database value.
 * \param[in] value a db_value_t pointer.
 * \return a db_type_uint32_t pointer or NULL on error, if empty or not an
 * unsigned 32bit integer value.
 * TODO: unit test
 */
extern const db_type_uint32_t* db_value_uint32(const db_value_t* value);

/**
 * Get a pointer for the 64bit integer in a database value.
 * \param[in] value a db_value_t pointer.
 * \return a db_type_int64_t pointer or NULL on error, if empty or not a 64bit
 * integer value.
 * TODO: unit test
 */
extern const db_type_int64_t* db_value_int64(const db_value_t* value);

/**
 * Get a pointer for the unsigned 64bit integer in a database value.
 * \param[in] value a db_value_t pointer.
 * \return a db_type_uint64_t pointer or NULL on error, if empty or not an
 * unsigned 64bit integer value.
 * TODO: unit test
 */
extern const db_type_uint64_t* db_value_uint64(const db_value_t* value);

/**
 * Get a character pointer for the text in a database value.
 * \param[in] value a db_value_t pointer.
 * \return a character pointer or NULL on error, if empty or not a text value.
 */
extern const char* db_value_text(const db_value_t* value);

/**
 * Sets `enum_value` with the integer value of an enumeration database value.
 * \param[in] value a db_value_t pointer.
 * \param[out] enum_value an integer pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_enum_value(const db_value_t* value, int* enum_value);

/**
 * Check if a database value is not empty.
 * \param[in] value a db_value_t pointer.
 * \return DB_ERROR_* if empty, otherwise DB_OK.
 */
extern int db_value_not_empty(const db_value_t* value);

/**
 * Get the 32bit integer representation of the database value.
 * \param[in] value a db_value_t pointer.
 * \param[out] to_int32 a db_type_int32_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_to_int32(const db_value_t* value, db_type_int32_t* to_int32);

/**
 * Get the unsigned 32bit integer representation of the database value.
 * \param[in] value a db_value_t pointer.
 * \param[out] to_uint32 a db_type_uint32_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_to_uint32(const db_value_t* value, db_type_uint32_t* to_uint32);

/**
 * Get the 64bit integer representation of the database value.
 * \param[in] value a db_value_t pointer.
 * \param[out] to_int64 a db_type_int64_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_to_int64(const db_value_t* value, db_type_int64_t* to_int64);

/**
 * Get the unsigned 64bit integer representation of the database value.
 * \param[in] value a db_value_t pointer.
 * \param[out] to_uint64 a db_type_uint64_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_to_uint64(const db_value_t* value, db_type_uint64_t* to_uint64);

/**
 * Get the character representation of the database value.
 * \param[in] value a db_value_t pointer.
 * \param[out] to_text a character pointer pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_to_text(const db_value_t* value, char** to_text);

/**
 * Get the integer enumeration representation of the database value.
 * \param[in] value a db_value_t pointer.
 * \param[out] to_int an integer pointer.
 * \param[in] enum_set a db_enum_t array that MUST end with NULL.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_to_enum_value(const db_value_t* value, int* to_int, const db_enum_t* enum_set);

/**
 * Set the database value to a 32bit integer value.
 * \param[in] value a db_value_t pointer.
 * \param[in] from_int32 a db_type_int32_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_from_int32(db_value_t* value, db_type_int32_t from_int32);

/**
 * Set the database value to an unsigned 32bit integer value.
 * \param[in] value a db_value_t pointer.
 * \param[in] from_uint32 a db_type_uint32_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_from_uint32(db_value_t* value, db_type_uint32_t from_uint32);

/**
 * Set the database value to a 64bit integer value.
 * \param[in] value a db_value_t pointer.
 * \param[in] from_int64 a db_type_int64_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_from_int64(db_value_t* value, db_type_int64_t from_int64);

/**
 * Set the database value to an unsigned 64bit integer value.
 * \param[in] value a db_value_t pointer.
 * \param[in] from_uint64 a db_type_uint64_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_from_uint64(db_value_t* value, db_type_uint64_t from_uint64);

/**
 * Set the database value to a text value.
 * \param[in] value a db_value_t pointer.
 * \param[in] from_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_from_text(db_value_t* value, const char* from_text);

/**
 * Set the database value to a text value.
 * \param[in] value a db_value_t pointer.
 * \param[in] from_text a character pointer.
 * \param[in] size a size_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_from_text2(db_value_t* value, const char* from_text, size_t size);

/**
 * Set the database value to an enumeration value based on an integer value.
 * \param[in] value a db_value_t pointer.
 * \param[in] enum_value an integer pointer.
 * \param[in] enum_set a db_enum_t array that MUST end with NULL.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_from_enum_value(db_value_t* value, int enum_value, const db_enum_t* enum_set);

/**
 * Mark the database as a primary key.
 * \param[in] value a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_value_set_primary_key(db_value_t* value);

/**
 * A container for a fixed set of database values.
 */
struct db_value_set {
    db_value_t* values;
    size_t size;
};

/**
 * Create a new set of database value.
 * \param[in] size a size_t.
 * \return a db_value_set_t pointer or NULL on error.
 */
extern db_value_set_t* db_value_set_new(size_t size);

/**
 * Create a new set of database value that is a copy of another.
 * \param[in] from_value_set a db_value_set_t pointer.
 * \return a db_value_set_t pointer or NULL on error.
 */
extern db_value_set_t* db_value_set_new_copy(const db_value_set_t* from_value_set);

/**
 * Delete a database value set and all values within the set.
 * \param[in] value_set a db_value_set_t pointer.
 */
extern void db_value_set_free(db_value_set_t* value_set);

/**
 * Get the size of database value set.
 * \param[in] value_set a db_value_set_t pointer.
 * \return a size_t.
 */
extern size_t db_value_set_size(const db_value_set_t* value_set);

/**
 * Get a read only database value at a position in a database value set.
 * \param[in] value_set a db_value_set_t pointer.
 * \param[in] at a size_t.
 * \return a db_value_t pointer or NULL on error.
 */
extern const db_value_t* db_value_set_at(const db_value_set_t* value_set, size_t at);

/**
 * Get a writable database value at a position in a database value set.
 * \param[in] value_set a db_value_set_t pointer.
 * \param[in] at a size_t.
 * \return a db_value_t pointer or NULL on error.
 */
extern db_value_t* db_value_set_get(db_value_set_t* value_set, size_t at);

#endif
