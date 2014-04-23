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

#ifndef __db_type_h
#define __db_type_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A signed 32bit integer.
 */
typedef int32_t db_type_int32_t;
/**
 * An unsigned 32bit integer.
 */
typedef uint32_t db_type_uint32_t;
/**
 * A signed 64bit integer.
 */
typedef int64_t db_type_int64_t;
/**
 * An unsigned 64bit integer.
 */
typedef uint64_t db_type_uint64_t;
/**
 * The type of a database value.
 */
typedef enum {
    /**
     * No value, empty, not set.
     */
    DB_TYPE_EMPTY,
    /**
     * This will make the value a primary key / ID that can be any type.
     */
    DB_TYPE_PRIMARY_KEY,
    /**
     * A db_type_int32_t.
     */
    DB_TYPE_INT32,
    /**
     * A db_type_uint32_t.
     */
    DB_TYPE_UINT32,
    /**
     * A db_type_int64_t.
     */
    DB_TYPE_INT64,
    /**
     * A db_type_uint64_t.
     */
    DB_TYPE_UINT64,
    /**
     * A null terminated character string.
     */
    DB_TYPE_TEXT,
    /**
     * A enumerate value that can be represented as an integer or string.
     */
    DB_TYPE_ENUM,
    /**
     * This can be any type, primarily used for ID fields.
     */
    DB_TYPE_ANY
} db_type_t;

#ifdef __cplusplus
}
#endif

#endif
