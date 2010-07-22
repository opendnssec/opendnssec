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
 * Zone signing tools.
 *
 */

#ifndef SIGNER_TOOLS_H
#define SIGNER_TOOLS_H

#include "config.h"
#include "daemon/config.h"
#include "signer/zone.h"

/**
 * Read zone input adapter.
 * \param[in] zone zone
 * \return int 0 on success, 1 on fail
 *
 */
int tools_read_input(zone_type* zone);

/**
 * Add DNSKEY (and NSEC3PARAM) records to zone.
 * \param[in] zone zone
 * \return int 0 on success, 1 on fail
 *
 */
int tools_add_dnskeys(zone_type* zone);

/**
 * Update zone with pending changes.
 * \param[in] zone zone
 * \return int 0 on success, 1 on fail
 *
 */
int tools_update(zone_type* zone);

/**
 * Add NSEC(3) records to zone.
 * \param[in] zone zone
 * \return int 0 on success, 1 on fail
 *
 */
int tools_nsecify(zone_type* zone);

/**
 * Add RRSIG records to zone.
 * \param[in] zone zone
 * \return int 0 on success, 1 on fail
 *
 */
int tools_sign(zone_type* zone);

/**
 * Audit zone.
 * \param[in] zone zone
 * \param[in] config configuration settings
 * \return int 0 on success, 1 on fail
 *
 */
int tools_audit(zone_type* zone, engineconfig_type* config);

/**
 * Write zone to output adapter.
 * \param[in] zone zone
 * \return int 0 on success, 1 on fail
 *
 */
int tools_write_output(zone_type* zone);

#endif /* SIGNER_TOOLS_H */
