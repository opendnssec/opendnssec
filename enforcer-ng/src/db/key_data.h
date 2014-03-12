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

#ifndef __key_data_h
#define __key_data_h

#ifdef __cplusplus
extern "C" {
#endif

struct key_data;
struct key_data_list;
typedef struct key_data key_data_t;
typedef struct key_data_list key_data_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "key_state.h"

#ifdef __cplusplus
extern "C" {
#endif

struct key_data {
	db_object_t* dbo;
	int id;
	char* locator;
	int algorithm;
	int inception;
	char* role;
	int introducing;
	int shouldrevoke;
	int standby;
	int active_zsk;
	int publish;
	int active_ksk;
	char* ds_at_parent;
	int keytag;

	/* foreign key */
	int ds;
	int rrsig;
	int dnskey;
	int rrsigdnskey;
    key_state_t* key_state_ds;
    key_state_t* key_state_rrsig;
    key_state_t* key_state_dnskey;
    key_state_t* key_state_rrsigdnskey;
	key_state_list_t* key_state_list;
};

key_data_t* key_data_new(const db_connection_t*);
void key_data_free(key_data_t*);
void key_data_reset(key_data_t*);
int key_data_from_result(key_data_t*, const db_result_t*);
int key_data_id(const key_data_t*);
const char* key_data_locator(const key_data_t*);
int key_data_algorithm(const key_data_t*);
int key_data_inception(const key_data_t*);
const char* key_data_role(const key_data_t*);
int key_data_introducing(const key_data_t*);
int key_data_shouldrevoke(const key_data_t*);
int key_data_standby(const key_data_t*);
int key_data_active_zsk(const key_data_t*);
int key_data_publish(const key_data_t*);
int key_data_active_ksk(const key_data_t*);
const char* key_data_ds_at_parent(const key_data_t*);
int key_data_keytag(const key_data_t*);
int key_data_get_key_state_list(key_data_t*);
const key_state_t* key_data_get_ds(key_data_t*);
const key_state_t* key_data_get_rrsig(key_data_t*);
const key_state_t* key_data_get_dnskey(key_data_t*);
const key_state_t* key_data_get_rrsigdnskey(key_data_t*);

struct key_data_list {
	db_object_t* dbo;
	db_result_list_t* result_list;
	const db_result_t* result;
	key_data_t* key_data;
};

key_data_list_t* key_data_list_new(const db_connection_t*);
void key_data_list_free(key_data_list_t*);
int key_data_list_get_by_enforcer_zone_id(key_data_list_t*, int);
const key_data_t* key_data_list_begin(key_data_list_t*);
const key_data_t* key_data_list_next(key_data_list_t*);

#ifdef __cplusplus
}
#endif

#endif
