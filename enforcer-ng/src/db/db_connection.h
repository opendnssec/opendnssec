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

#ifndef __db_connection_h
#define __db_connection_h

#ifdef __cplusplus
extern "C" {
#endif

struct db_connection;
typedef struct db_connection db_connection_t;

#ifdef __cplusplus
}
#endif

#include "db_configuration.h"
#include "db_backend.h"
#include "db_result.h"
#include "db_object.h"
#include "db_join.h"
#include "db_clause.h"

#ifdef __cplusplus
extern "C" {
#endif

struct db_connection {
    const db_configuration_list_t* configuration_list;
    db_backend_t* backend;
};

db_connection_t* db_connection_new(void);
void db_connection_free(db_connection_t*);
int db_connection_set_configuration_list(db_connection_t*, const db_configuration_list_t*);
int db_connection_setup(db_connection_t*);
int db_connection_connect(const db_connection_t*);
int db_connection_disconnect(const db_connection_t*);
int db_connection_create(const db_connection_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*);
db_result_list_t* db_connection_read(const db_connection_t*, const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
int db_connection_update(const db_connection_t*, const db_object_t*, const db_object_field_list_t*, const db_value_set_t*, const db_join_list_t*, const db_clause_list_t*);
int db_connection_delete(const db_connection_t*, const db_object_t*, const db_join_list_t*, const db_clause_list_t*);
int db_connection_transaction_begin(const db_connection_t*);
int db_connection_transaction_commit(const db_connection_t*);
int db_connection_transaction_rollback(const db_connection_t*);

#ifdef __cplusplus
}
#endif

#endif
