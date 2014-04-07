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

/**
 * TODO
 */
struct db_connection {
    const db_configuration_list_t* configuration_list;
    db_backend_t* backend;
};

/**
 * TODO
 * \param[in] void TODO 
 * \return `db_connection_t*` TODO
 */
db_connection_t* db_connection_new(void);

/**
 * TODO
 * \param[in] connection TODO 
 * \return `void` TODO
 */
void db_connection_free(db_connection_t* connection);

/**
 * TODO
 * \param[in] connection TODO 
 * \param[in] configuration_list TODO 
 * \return `int` TODO
 */
int db_connection_set_configuration_list(db_connection_t* connection, const db_configuration_list_t* configuration_list);

/**
 * TODO
 * \param[in] connection TODO 
 * \return `int` TODO
 */
int db_connection_setup(db_connection_t* connection);

/**
 * TODO
 * \param[in] connection TODO 
 * \return `int` TODO
 */
int db_connection_connect(const db_connection_t* connection);

/**
 * TODO
 * \param[in] connection TODO 
 * \return `int` TODO
 */
int db_connection_disconnect(const db_connection_t* connection);

/**
 * TODO
 * \param[in] connection TODO 
 * \param[in] object TODO 
 * \param[in] object_field_list TODO 
 * \param[in] value_set TODO 
 * \return `int` TODO
 */
int db_connection_create(const db_connection_t* connection, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set);

/**
 * TODO
 * \param[in] connection TODO 
 * \param[in] object TODO 
 * \param[in] join_list TODO 
 * \param[in] clause_list TODO 
 * \return `db_result_list_t*` TODO
 */
db_result_list_t* db_connection_read(const db_connection_t* connection, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list);

/**
 * TODO
 * \param[in] connection TODO 
 * \param[in] object TODO 
 * \param[in] object_field_list TODO 
 * \param[in] value_set TODO 
 * \param[in] clause_list TODO 
 * \return `int` TODO
 */
int db_connection_update(const db_connection_t* connection, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list);

/**
 * TODO
 * \param[in] connection TODO 
 * \param[in] object TODO 
 * \param[in] clause_list TODO 
 * \return `int` TODO
 */
int db_connection_delete(const db_connection_t* connection, const db_object_t* object, const db_clause_list_t* clause_list);

/**
 * TODO
 * \param[in] connection TODO 
 * \return `int` TODO
 */
int db_connection_transaction_begin(const db_connection_t* connection);

/**
 * TODO
 * \param[in] connection TODO 
 * \return `int` TODO
 */
int db_connection_transaction_commit(const db_connection_t* connection);

/**
 * TODO
 * \param[in] connection TODO 
 * \return `int` TODO
 */
int db_connection_transaction_rollback(const db_connection_t* connection);

#ifdef __cplusplus
}
#endif

#endif
