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

#ifdef __cplusplus
extern "C" {
#endif

struct db_value;
struct db_value_set;
typedef struct db_value db_value_t;
typedef struct db_value_set db_value_set_t;

#ifdef __cplusplus
}
#endif

#include "config.h"

#include "db_type.h"
#include "db_enum.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DB_VALUE_DATA_SIZE (SIZEOF_INT64_T / SIZEOF_VOIDP)

/**
 * TODO
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

/**
 * TODO
 * \return `db_value_t*` TODO
 */
db_value_t* db_value_new();

/**
 * TODO
 * \param[in] value TODO 
 * \return `void` TODO
 */
void db_value_free(db_value_t* value);

/**
 * TODO
 * \param[in] value TODO 
 * \return `void` TODO
 */
void db_value_reset(db_value_t* value);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] from_value TODO 
 * \return `int` TODO
 */
int db_value_copy(db_value_t* value, const db_value_t* from_value);

/**
 * TODO
 * \param[in] value_a TODO 
 * \param[in] value_b TODO 
 * \param[in] result TODO 
 * \return `int` TODO
 */
int db_value_cmp(const db_value_t* value_a, const db_value_t* value_b, int* result);

/**
 * TODO
 * \param[in] value TODO 
 * \return `db_type_t` TODO
 */
db_type_t db_value_type(const db_value_t* value);

/**
 * TODO
 * \param[in] value TODO 
 * \return `const char*` TODO
 */
const char* db_value_text(const db_value_t* value);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] enum_value TODO 
 * \return `int` TODO
 */
int db_value_enum_value(const db_value_t* value, int* enum_value);

/**
 * TODO
 * \param[in] value TODO 
 * \return `const char*` TODO
 */
const char* db_value_enum_text(const db_value_t* value);

/**
 * TODO
 * \param[in] value TODO 
 * \return `int` TODO
 */
int db_value_not_empty(const db_value_t* value);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] to_int32 TODO 
 * \return `int` TODO
 */
int db_value_to_int32(const db_value_t* value, db_type_int32_t* to_int32);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] to_uint32 TODO 
 * \return `int` TODO
 */
int db_value_to_uint32(const db_value_t* value, db_type_uint32_t* to_uint32);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] to_int64 TODO 
 * \return `int` TODO
 */
int db_value_to_int64(const db_value_t* value, db_type_int64_t* to_int64);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] to_uint64 TODO 
 * \return `int` TODO
 */
int db_value_to_uint64(const db_value_t* value, db_type_uint64_t* to_uint64);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] to_text TODO 
 * \return `int` TODO
 */
int db_value_to_text(const db_value_t* value, char** to_text);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] to_int TODO 
 * \param[in] enum_set TODO 
 * \return `int` TODO
 */
int db_value_to_enum_value(const db_value_t* value, int* to_int, const db_enum_t* enum_set);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] to_text TODO 
 * \param[in] enum_set TODO 
 * \return `int` TODO
 */
int db_value_to_enum_text(const db_value_t* value, const char** to_text, const db_enum_t* enum_set);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] from_int32 TODO 
 * \return `int` TODO
 */
int db_value_from_int32(db_value_t* value, db_type_int32_t from_int32);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] from_uint32 TODO 
 * \return `int` TODO
 */
int db_value_from_uint32(db_value_t* value, db_type_uint32_t from_uint32);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] from_int64 TODO 
 * \return `int` TODO
 */
int db_value_from_int64(db_value_t* value, db_type_int64_t from_int64);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] from_uint64 TODO 
 * \return `int` TODO
 */
int db_value_from_uint64(db_value_t* value, db_type_uint64_t from_uint64);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] from_text TODO 
 * \return `int` TODO
 */
int db_value_from_text(db_value_t* value, const char* from_text);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] enum_value TODO 
 * \param[in] enum_set TODO 
 * \return `int` TODO
 */
int db_value_from_enum_value(db_value_t* value, int enum_value, const db_enum_t* enum_set);

/**
 * TODO
 * \param[in] value TODO 
 * \param[in] enum_text TODO 
 * \param[in] enum_set TODO 
 * \return `int` TODO
 */
int db_value_from_enum_text(db_value_t* value, const char* enum_text, const db_enum_t* enum_set);

/**
 * TODO
 * \param[in] value TODO 
 * \return `int` TODO
 */
int db_value_primary_key(const db_value_t* value);

/**
 * TODO
 * \param[in] value TODO 
 * \return `int` TODO
 */
int db_value_set_primary_key(db_value_t* value);

/**
 * TODO
 */
struct db_value_set {
    db_value_t* values;
    size_t size;
};

/**
 * TODO
 * \param[in] size TODO 
 * \return `db_value_set_t*` TODO
 */
db_value_set_t* db_value_set_new(size_t size);

/**
 * TODO
 * \param[in] value_set TODO 
 * \return `void` TODO
 */
void db_value_set_free(db_value_set_t* value_set);

/**
 * TODO
 * \param[in] value_set TODO 
 * \return `size_t` TODO
 */
size_t db_value_set_size(const db_value_set_t* value_set);

/**
 * TODO
 * \param[in] value_set TODO 
 * \param[in] at TODO 
 * \return `const db_value_t*` TODO
 */
const db_value_t* db_value_set_at(const db_value_set_t* value_set, size_t at);

/**
 * TODO
 * \param[in] value_set TODO 
 * \param[in] at TODO 
 * \return `db_value_t*` TODO
 */
db_value_t* db_value_set_get(db_value_set_t* value_set, size_t at);

#ifdef __cplusplus
}
#endif

#endif
