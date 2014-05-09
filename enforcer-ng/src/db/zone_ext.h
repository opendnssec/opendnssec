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

#ifndef __zone_ext_h
#define __zone_ext_h

#include "key_data.h"

#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get a list of keys for an enforcer zone object.
 * \param[in] zone an zone_t pointer.
 * \return a key_data_list_t pointer or NULL on error or if there are no keys
 * in the enforcer zone object.
 */
key_data_list_t* zone_get_keys(const zone_t* zone);

/**
 * Create a zone object from XML.
 * \param[in] zone a zone_t object being created.
 * \param[in] zone_node a xmlNodePtr to the XML for the zone.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_create_from_xml(zone_t* zone, xmlNodePtr zone_node);

/**
 * Update a zone object from XML.
 * \param[in] zone a zone_t object being updated.
 * \param[in] zone_node a xmlNodePtr to the XML for the zone.
 * \param[out] updated an integer pointer that will be set to non-zero if any
 * values in the zone was updated.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int zone_update_from_xml(zone_t* zone, xmlNodePtr zone_node, int* updated);

#ifdef __cplusplus
}
#endif

#endif
