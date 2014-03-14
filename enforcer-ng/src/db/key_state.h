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

#ifndef __key_state_h
#define __key_state_h

#ifdef __cplusplus
extern "C" {
#endif

struct key_state;
struct key_state_list;
typedef struct key_state key_state_t;
typedef struct key_state_list key_state_list_t;

typedef enum key_state_rrstate {
    invalid = -1,
    hidden = 0,
    rumoured = 1,
    omnipresent = 2,
    unretentive = 3,
    NA = 4
} key_state_rrstate_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"

#ifdef __cplusplus
extern "C" {
#endif

struct key_state {
    db_object_t* dbo;
    int id;
    key_state_rrstate_t state;
    int last_change;
    int minimize;
    int ttl;
};

key_state_t* key_state_new(const db_connection_t*);
void key_state_free(key_state_t*);
void key_state_reset(key_state_t*);
int key_state_copy(key_state_t*, const key_state_t*);
int key_state_from_result(key_state_t*, const db_result_t*);
int key_state_id(const key_state_t*);
key_state_rrstate_t key_state_state(const key_state_t*);
const char* key_state_state_text(const key_state_t*);
int key_state_last_change(const key_state_t*);
int key_state_minimize(const key_state_t*);
int key_state_ttl(const key_state_t*);
int key_state_get_by_id(key_state_t*, int);

struct key_state_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    key_state_t* key_state;
};

key_state_list_t* key_state_list_new(const db_connection_t*);
void key_state_list_free(key_state_list_t*);
int key_state_list_get_4_by_id(key_state_list_t*, int, int, int, int);
const key_state_t* key_state_list_begin(key_state_list_t*);
const key_state_t* key_state_list_next(key_state_list_t*);

#ifdef __cplusplus
}
#endif

#endif
