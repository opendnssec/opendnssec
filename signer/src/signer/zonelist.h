/*
 * $Id$
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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

/**
 *
 * The zonelist and all.
 */

#ifndef SIGNER_ZONELIST_H
#define SIGNER_ZONELIST_H

#include "signer/zone.h"

#include <ldns/ldns.h>
#include <stdio.h>
#include <time.h>

struct tasklist_struct;

/**
 * Zone list
 *
 */
typedef struct zonelist_struct zonelist_type;
struct zonelist_struct {
    ldns_rbtree_t* zones;
    time_t last_modified;
};

/**
 * Create zone list.
 * \return zonelist_type* created zone list
 */
zonelist_type* zonelist_create(void);

/**
 * Read zonelist file.
 * \param[in] zonelistfile zonelist configuration file
 * \param[in] last_modified last modified
 * \return zonelist_type* zone list if reading was succesful, NULL otherwise
 */
zonelist_type* zonelist_read(const char* zonelistfile, time_t last_modified);

/**
 * Lock all zones in zone list.
 * \param[in] zonelist zone list
 *
 */
void zonelist_lock(zonelist_type* zonelist);

/**
 * Unlock all zones in zone list.
 * \param[in] zonelist zone list
 *
 */
void zonelist_unlock(zonelist_type* zonelist);

/**
 * Add zone to zone list.
 * \param[in] zonelist zone list
 * \param[in] zone zone to add
 * \return zone_type* added zone
 *
 */
zone_type* zonelist_add_zone(zonelist_type* zonelist, zone_type* zone);

/**
 * Update zone list.
 * /param[in] zl zone list
 * /param[in] tl task list
 * /param[in] buf feedback message
 *
 */
void zonelist_update(zonelist_type* zl, struct tasklist_struct* tl,
    char* buf);

/**
 * Merge zone lists.
 * /param[in] zl1 base zone list
 * /param[in] zl2 additional zone list
 *
 */
void zonelist_merge(zonelist_type* zl1, zonelist_type* zl2);

/**
 * Clean up a zonelist.
 * \param[in] zonelist list to clean up
 *
 */
void zonelist_cleanup(zonelist_type* zonelist);

#endif /* SIGNER_ZONELIST_H */
