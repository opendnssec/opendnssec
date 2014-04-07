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

#ifndef __db_configuration_h
#define __db_configuration_h

#ifdef __cplusplus
extern "C" {
#endif

struct db_configuration;
struct db_configuration_list;
typedef struct db_configuration db_configuration_t;
typedef struct db_configuration_list db_configuration_list_t;

struct db_configuration {
    db_configuration_t* next;
    char* name;
    char* value;
};

db_configuration_t* db_configuration_new(void);
void db_configuration_free(db_configuration_t* configuration);
const char* db_configuration_name(const db_configuration_t* configuration);
const char* db_configuration_value(const db_configuration_t* configuration);
int db_configuration_set_name(db_configuration_t* configuration, const char* name);
int db_configuration_set_value(db_configuration_t* configuration, const char* value);
int db_configuration_not_empty(const db_configuration_t* configuration);

struct db_configuration_list {
    db_configuration_t* begin;
    db_configuration_t* end;
};

db_configuration_list_t* db_configuration_list_new(void);
void db_configuration_list_free(db_configuration_list_t* configuration_list);
int db_configuration_list_add(db_configuration_list_t* configuration_list, db_configuration_t* configuration);
const db_configuration_t* db_configuration_list_find(const db_configuration_list_t* configuration_list, const char* name);

#ifdef __cplusplus
}
#endif

#endif
