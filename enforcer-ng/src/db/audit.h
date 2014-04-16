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

#ifndef __audit_h
#define __audit_h

#ifdef __cplusplus
extern "C" {
#endif

struct audit;
typedef struct audit audit_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A audit object.
 */
struct audit {
    db_object_t* dbo;
    int id;
    int partial;
};

/**
 * Create a new audit object.
 * \param[in] connection a db_connection_t pointer.
 * \return an audit_t pointer or NULL on error.
 */
audit_t* audit_new(const db_connection_t* connection);

/**
 * Delete an audit object, this does not delete it from the database.
 * \param[in] audit an audit_t pointer.
 */
void audit_free(audit_t* audit);

/**
 * Reset the content of an audit object making it as if its new. This does not
 * change anything in the database.
 * \param[in] audit an audit_t pointer.
 */
void audit_reset(audit_t* audit);

/**
 * Set the content of an audit object based on a database result.
 * \param[in] audit an audit_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_from_result(audit_t* audit, const db_result_t* result);

/**
 * Get the ID of an audit object. Undefined behavior if `audit` is NULL.
 * \param[in] audit an audit_t pointer.
 * \return an integer.
 */
int audit_id(const audit_t* audit);

/**
 * Get the partial of an audit object. Undefined behavior if `audit` is NULL.
 * \param[in] audit an audit_t pointer.
 * \return an integer.
 */
int audit_partial(const audit_t* audit);

/**
 * Set the partial of an audit object.
 * \param[in] audit an audit_t pointer.
 * \param[in] partial an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_set_partial(audit_t* audit, int partial);

/**
 * Create an audit object in the database.
 * \param[in] audit an audit_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_create(audit_t* audit);

/**
 * Get an audit object from the database by an id specified in `id`.
 * \param[in] audit an audit_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_get_by_id(audit_t* audit, int id);

/**
 * Update an audit object in the database.
 * \param[in] audit an audit_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_update(audit_t* audit);

/**
 * Delete an audit object from the database.
 * \param[in] audit an audit_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_delete(audit_t* audit);

#ifdef __cplusplus
}
#endif

#endif
