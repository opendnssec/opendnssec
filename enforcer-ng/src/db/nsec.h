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

#ifndef __nsec_h
#define __nsec_h

#ifdef __cplusplus
extern "C" {
#endif

struct nsec;
struct nsec_list;
typedef struct nsec nsec_t;
typedef struct nsec_list nsec_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "nsec_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A nsec object.
 */
struct nsec {
    db_object_t* dbo;
    db_value_t id;
#include "nsec_struct_ext.h"
};

/**
 * Create a new nsec object.
 * \param[in] connection a db_connection_t pointer.
 * \return a nsec_t pointer or NULL on error.
 */
nsec_t* nsec_new(const db_connection_t* connection);

/**
 * Delete a nsec object, this does not delete it from the database.
 * \param[in] nsec a nsec_t pointer.
 */
void nsec_free(nsec_t* nsec);

/**
 * Reset the content of a nsec object making it as if its new. This does not change anything in the database.
 * \param[in] nsec a nsec_t pointer.
 */
void nsec_reset(nsec_t* nsec);

/**
 * Copy the content of a nsec object.
 * \param[in] nsec a nsec_t pointer.
 * \param[in] nsec_copy a nsec_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec_copy(nsec_t* nsec, const nsec_t* nsec_copy);

/**
 * Set the content of a nsec object based on a database result.
 * \param[in] nsec a nsec_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec_from_result(nsec_t* nsec, const db_result_t* result);

/**
 * Get the id of a nsec object. Undefined behavior if `nsec` is NULL.
 * \param[in] nsec a nsec_t pointer.
 * \return a db_value_t pointer.
 */
const db_value_t* nsec_id(const nsec_t* nsec);

/**
 * Create a nsec object in the database.
 * \param[in] nsec a nsec_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec_create(nsec_t* nsec);

/**
 * Get a nsec object from the database by an id specified in `id`.
 * \param[in] nsec a nsec_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec_get_by_id(nsec_t* nsec, const db_value_t* id);

/**
 * Update a nsec object in the database.
 * \param[in] nsec a nsec_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec_update(nsec_t* nsec);

/**
 * Delete a nsec object from the database.
 * \param[in] nsec a nsec_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec_delete(nsec_t* nsec);

/**
 * A list of nsec objects.
 */
struct nsec_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    nsec_t* nsec;
};

/**
 * Create a new nsec object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a nsec_list_t pointer or NULL on error.
 */
nsec_list_t* nsec_list_new(const db_connection_t* connection);

/**
 * Delete a nsec object list
 * \param[in] nsec_list a nsec_list_t pointer.
 */
void nsec_list_free(nsec_list_t* nsec_list);

/**
 * Get all nsec objects.
 * \param[in] nsec_list a nsec_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int nsec_list_get(nsec_list_t* nsec_list);

/**
 * Get the first nsec object in a nsec object list. This will reset the position of the list.
 * \param[in] nsec_list a nsec_list_t pointer.
 * \return a nsec_t pointer or NULL on error or if there are no
 * nsec objects in the nsec object list.
 */
const nsec_t* nsec_list_begin(nsec_list_t* nsec_list);

/**
 * Get the next nsec object in a nsec object list.
 * \param[in] nsec_list a nsec_list_t pointer.
 * \return a nsec_t pointer or NULL on error or if there are no more
 * nsec objects in the nsec object list.
 */
const nsec_t* nsec_list_next(nsec_list_t* nsec_list);

#ifdef __cplusplus
}
#endif

#endif
