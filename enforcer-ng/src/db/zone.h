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

#ifndef __zone_h
#define __zone_h

#ifdef __cplusplus
extern "C" {
#endif

struct zone;
struct zone_list;
typedef struct zone zone_t;
typedef struct zone_list zone_list_t;

typedef enum zone_serial {
    ZONE_SERIAL_INVALID = -1,
    ZONE_SERIAL_COUNTER = 1,
    ZONE_SERIAL_DATECOUNTER = 2,
    ZONE_SERIAL_UNIXTIME = 3,
    ZONE_SERIAL_KEEP = 4
} zone_serial_t;

#ifdef __cplusplus
}
#endif

#include "db_object.h"
#include "zone_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A zone object.
 */
struct zone {
    db_object_t* dbo;
    db_value_t id;
    int propagationdelay;
    int ttl;
    int min;
    zone_serial_t serial;
#include "zone_struct_ext.h"
};

/**
 * Create a new zone object.
 * \param[in] connection a db_connection_t pointer.
 * \return a zone_t pointer or NULL on error.
 */
zone_t* zone_new(const db_connection_t* connection);

/**
 * Delete a zone object, this does not delete it from the database.
 * \param[in] zone a zone_t pointer.
 */
void zone_free(zone_t* zone);

/**
 * Reset the content of a zone object making it as if its new. This does not change anything in the database.
 * \param[in] zone a zone_t pointer.
 */
void zone_reset(zone_t* zone);

/**
 * Copy the content of a zone object.
 * \param[in] zone a zone_t pointer.
 * \param[in] zone_copy a zone_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_copy(zone_t* zone, const zone_t* zone_copy);

/**
 * Set the content of a zone object based on a database result.
 * \param[in] zone a zone_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_from_result(zone_t* zone, const db_result_t* result);

/**
 * Get the id of a zone object.
 * \param[in] zone a zone_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* zone_id(const zone_t* zone);

/**
 * Get the propagationdelay of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_t pointer.
 * \return an integer.
 */
int zone_propagationdelay(const zone_t* zone);

/**
 * Get the ttl of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_t pointer.
 * \return an integer.
 */
int zone_ttl(const zone_t* zone);

/**
 * Get the min of a zone object. Undefined behavior if `zone` is NULL.
 * \param[in] zone a zone_t pointer.
 * \return an integer.
 */
int zone_min(const zone_t* zone);

/**
 * Get the serial of a zone object.
 * \param[in] zone a zone_t pointer.
 * \return a zone_serial_t which may be ZONE_SERIAL_INVALID on error or if no serial has been set.
 */
zone_serial_t zone_serial(const zone_t* zone);

/**
 * Get the serial as text of a zone object.
 * \param[in] zone a zone_t pointer.
 * \return a character pointer or NULL on error or if no serial has been set.
 */
const char* zone_serial_text(const zone_t* zone);

/**
 * Set the propagationdelay of a zone object.
 * \param[in] zone a zone_t pointer.
 * \param[in] propagationdelay an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_set_propagationdelay(zone_t* zone, int propagationdelay);

/**
 * Set the ttl of a zone object.
 * \param[in] zone a zone_t pointer.
 * \param[in] ttl an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_set_ttl(zone_t* zone, int ttl);

/**
 * Set the min of a zone object.
 * \param[in] zone a zone_t pointer.
 * \param[in] min an integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_set_min(zone_t* zone, int min);

/**
 * Set the serial of a zone object.
 * \param[in] zone a zone_t pointer.
 * \param[in] serial a zone_serial_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_set_serial(zone_t* zone, zone_serial_t serial);

/**
 * Set the serial of a zone object from text.
 * \param[in] zone a zone_t pointer.
 * \param[in] serial a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_set_serial_text(zone_t* zone, const char* serial);

/**
 * Create a zone object in the database.
 * \param[in] zone a zone_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_create(zone_t* zone);

/**
 * Get a zone object from the database by an id specified in `id`.
 * \param[in] zone a zone_t pointer.
 * \param[in] id a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_get_by_id(zone_t* zone, const db_value_t* id);

/**
 * Update a zone object in the database.
 * \param[in] zone a zone_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_update(zone_t* zone);

/**
 * Delete a zone object from the database.
 * \param[in] zone a zone_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_delete(zone_t* zone);

/**
 * A list of zone objects.
 */
struct zone_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    zone_t* zone;
};

/**
 * Create a new zone object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a zone_list_t pointer or NULL on error.
 */
zone_list_t* zone_list_new(const db_connection_t* connection);

/**
 * Delete a zone object list
 * \param[in] zone_list a zone_list_t pointer.
 */
void zone_list_free(zone_list_t* zone_list);

/**
 * Get all zone objects.
 * \param[in] zone_list a zone_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_list_get(zone_list_t* zone_list);

/**
 * Get the first zone object in a zone object list. This will reset the position of the list.
 * \param[in] zone_list a zone_list_t pointer.
 * \return a zone_t pointer or NULL on error or if there are no
 * zone objects in the zone object list.
 */
const zone_t* zone_list_begin(zone_list_t* zone_list);

/**
 * Get the next zone object in a zone object list.
 * \param[in] zone_list a zone_list_t pointer.
 * \return a zone_t pointer or NULL on error or if there are no more
 * zone objects in the zone object list.
 */
const zone_t* zone_list_next(zone_list_t* zone_list);

#ifdef __cplusplus
}
#endif

#endif
