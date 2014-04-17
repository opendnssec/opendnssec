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

#ifndef __dbo_keylist_h
#define __dbo_keylist_h

#ifdef __cplusplus
extern "C" {
#endif

struct dbo_keylist;
struct dbo_keylist_list;
typedef struct dbo_keylist dbo_keylist_t;
typedef struct dbo_keylist_list dbo_keylist_list_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "dbo_keylist_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A dbo keylist object.
 */
struct dbo_keylist {
    db_object_t* dbo;
    int id;
    int ttl;
    int retiresafety;
    int publishsafety;
    unsigned int zones_share_keys;
    int purgeafter;
#include "dbo_keylist_struct_ext.h"
};

/**
 * Create a new dbo keylist object.
 * \param[in] connection a db_connection_t pointer.
 * \return a dbo_keylist_t pointer or NULL on error.
 */
dbo_keylist_t* dbo_keylist_new(const db_connection_t* connection);

/**
 * Delete a dbo keylist object, this does not delete it from the database.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 */
void dbo_keylist_free(dbo_keylist_t* dbo_keylist);

/**
 * Reset the content of a dbo keylist object making it as if its new. This does not change anything in the database.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 */
void dbo_keylist_reset(dbo_keylist_t* dbo_keylist);

/**
 * Copy the content of a dbo keylist object.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \param[in] dbo_keylist_copy a dbo_keylist_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_keylist_copy(dbo_keylist_t* dbo_keylist, const dbo_keylist_t* dbo_keylist_copy);

/**
 * Set the content of a dbo keylist object based on a database result.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_keylist_from_result(dbo_keylist_t* dbo_keylist, const db_result_t* result);

/**
 * Get the ID of a dbo keylist object. Undefined behavior if `dbo_keylist` is NULL.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \return an integer.
 */
int dbo_keylist_id(const dbo_keylist_t* dbo_keylist);

/**
 * Get the ttl of a dbo keylist object. Undefined behavior if `dbo_keylist` is NULL.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \return an integer.
 */
int dbo_keylist_ttl(const dbo_keylist_t* dbo_keylist);

/**
 * Get the retiresafety of a dbo keylist object. Undefined behavior if `dbo_keylist` is NULL.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \return an integer.
 */
int dbo_keylist_retiresafety(const dbo_keylist_t* dbo_keylist);

/**
 * Get the publishsafety of a dbo keylist object. Undefined behavior if `dbo_keylist` is NULL.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \return an integer.
 */
int dbo_keylist_publishsafety(const dbo_keylist_t* dbo_keylist);

/**
 * Get the zones_share_keys of a dbo keylist object. Undefined behavior if `dbo_keylist` is NULL.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \return an unsigned integer.
 */
unsigned int dbo_keylist_zones_share_keys(const dbo_keylist_t* dbo_keylist);

/**
 * Get the purgeafter of a dbo keylist object. Undefined behavior if `dbo_keylist` is NULL.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \return an integer.
 */
int dbo_keylist_purgeafter(const dbo_keylist_t* dbo_keylist);

/**
 * Set the ttl of a dbo keylist object.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \param[in] ttl an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_keylist_set_ttl(dbo_keylist_t* dbo_keylist, int ttl);

/**
 * Set the retiresafety of a dbo keylist object.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \param[in] retiresafety an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_keylist_set_retiresafety(dbo_keylist_t* dbo_keylist, int retiresafety);

/**
 * Set the publishsafety of a dbo keylist object.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \param[in] publishsafety an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_keylist_set_publishsafety(dbo_keylist_t* dbo_keylist, int publishsafety);

/**
 * Set the zones_share_keys of a dbo keylist object.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \param[in] zones_share_keys an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_keylist_set_zones_share_keys(dbo_keylist_t* dbo_keylist, unsigned int zones_share_keys);

/**
 * Set the purgeafter of a dbo keylist object.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \param[in] purgeafter an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_keylist_set_purgeafter(dbo_keylist_t* dbo_keylist, int purgeafter);

/**
 * Create a dbo keylist object in the database.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_keylist_create(dbo_keylist_t* dbo_keylist);

/**
 * Get a dbo keylist object from the database by an id specified in `id`.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \param[in] id an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_keylist_get_by_id(dbo_keylist_t* dbo_keylist, int id);

/**
 * Update a dbo keylist object in the database.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_keylist_update(dbo_keylist_t* dbo_keylist);

/**
 * Delete a dbo keylist object from the database.
 * \param[in] dbo_keylist a dbo_keylist_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_keylist_delete(dbo_keylist_t* dbo_keylist);

/**
 * A list of dbo keylist objects.
 */
struct dbo_keylist_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    dbo_keylist_t* dbo_keylist;
};

/**
 * Create a new dbo keylist object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a dbo_keylist_list_t pointer or NULL on error.
 */
dbo_keylist_list_t* dbo_keylist_list_new(const db_connection_t* connection);

/**
 * Delete a dbo keylist object list
 * \param[in] dbo_keylist_list a dbo_keylist_list_t pointer.
 */
void dbo_keylist_list_free(dbo_keylist_list_t* dbo_keylist_list);

/**
 * Get all dbo keylist objects.
 * \param[in] dbo_keylist_list a dbo_keylist_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int dbo_keylist_list_get(dbo_keylist_list_t* dbo_keylist_list);

/**
 * Get the first dbo keylist object in a dbo keylist object list. This will reset the position of the list.
 * \param[in] dbo_keylist_list a dbo_keylist_list_t pointer.
 * \return a dbo_keylist_t pointer or NULL on error or if there are no
 * dbo keylist objects in the dbo keylist object list.
 */
const dbo_keylist_t* dbo_keylist_list_begin(dbo_keylist_list_t* dbo_keylist_list);

/**
 * Get the next dbo keylist object in a dbo keylist object list.
 * \param[in] dbo_keylist_list a dbo_keylist_list_t pointer.
 * \return a dbo_keylist_t pointer or NULL on error or if there are no more
 * dbo keylist objects in the dbo keylist object list.
 */
const dbo_keylist_t* dbo_keylist_list_next(dbo_keylist_list_t* dbo_keylist_list);

#ifdef __cplusplus
}
#endif

#endif
