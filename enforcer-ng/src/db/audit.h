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
struct audit_list;
typedef struct audit audit_t;
typedef struct audit_list audit_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "audit_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A audit object.
 */
struct audit {
    db_object_t* dbo;
    db_value_t id;
    unsigned int partial;
#include "audit_struct_ext.h"
};

/**
 * Create a new audit object.
 * \param[in] connection a db_connection_t pointer.
 * \return a audit_t pointer or NULL on error.
 */
audit_t* audit_new(const db_connection_t* connection);

/**
 * Delete a audit object, this does not delete it from the database.
 * \param[in] audit a audit_t pointer.
 */
void audit_free(audit_t* audit);

/**
 * Reset the content of a audit object making it as if its new. This does not change anything in the database.
 * \param[in] audit a audit_t pointer.
 */
void audit_reset(audit_t* audit);

/**
 * Copy the content of a audit object.
 * \param[in] audit a audit_t pointer.
 * \param[in] audit_copy a audit_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_copy(audit_t* audit, const audit_t* audit_copy);

/**
 * Set the content of a audit object based on a database result.
 * \param[in] audit a audit_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_from_result(audit_t* audit, const db_result_t* result);

/**
 * Get the id of a audit object.
 * \param[in] audit a audit_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* audit_id(const audit_t* audit);

/**
 * Get the partial of a audit object. Undefined behavior if `audit` is NULL.
 * \param[in] audit a audit_t pointer.
 * \return an unsigned integer.
 */
unsigned int audit_partial(const audit_t* audit);

/**
 * Set the partial of a audit object.
 * \param[in] audit a audit_t pointer.
 * \param[in] partial an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_set_partial(audit_t* audit, unsigned int partial);

/**
 * Create a audit object in the database.
 * \param[in] audit a audit_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_create(audit_t* audit);

/**
 * Get a audit object from the database by an id specified in `id`.
 * \param[in] audit a audit_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_get_by_id(audit_t* audit, const db_value_t* id);

/**
 * Update a audit object in the database.
 * \param[in] audit a audit_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_update(audit_t* audit);

/**
 * Delete a audit object from the database.
 * \param[in] audit a audit_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_delete(audit_t* audit);

/**
 * A list of audit objects.
 */
struct audit_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    audit_t* audit;
};

/**
 * Create a new audit object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a audit_list_t pointer or NULL on error.
 */
audit_list_t* audit_list_new(const db_connection_t* connection);

/**
 * Delete a audit object list
 * \param[in] audit_list a audit_list_t pointer.
 */
void audit_list_free(audit_list_t* audit_list);

/**
 * Get all audit objects.
 * \param[in] audit_list a audit_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int audit_list_get(audit_list_t* audit_list);

/**
 * Get the first audit object in a audit object list. This will reset the position of the list.
 * \param[in] audit_list a audit_list_t pointer.
 * \return a audit_t pointer or NULL on error or if there are no
 * audit objects in the audit object list.
 */
const audit_t* audit_list_begin(audit_list_t* audit_list);

/**
 * Get the next audit object in a audit object list.
 * \param[in] audit_list a audit_list_t pointer.
 * \return a audit_t pointer or NULL on error or if there are no more
 * audit objects in the audit object list.
 */
const audit_t* audit_list_next(audit_list_t* audit_list);

#ifdef __cplusplus
}
#endif

#endif
