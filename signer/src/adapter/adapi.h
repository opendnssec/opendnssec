/*
 * Copyright (c) 2009-2011 NLNet Labs. All rights reserved.
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
 * Adapter API.
 */

#ifndef ADAPTER_ADAPI_H
#define ADAPTER_ADAPI_H

#include "config.h"
#include "status.h"
#include "signer/zone.h"

#include <ldns/ldns.h>

/**
 * Get the inbound serial.
 * \param[in] zone zone
 * \return uint32_t inbound serial
 *
 */
uint32_t adapi_get_serial(zone_type* zone);

/**
 * Set the inbound serial.
 * \param[in] zone zone
 * \param[in] serial inbound serial
 *
 */
void adapi_set_serial(zone_type* zone, uint32_t serial);

/**
 * Get origin.
 * \param[in] zone zone
 * \return ldns_rdf* origin
 *
 */
extern ldns_rdf* adapi_get_origin(zone_type* zone);

/**
 * Get ttl.
 * \param[in] zone zone
 * \return uint32_t ttl
 *
 */
extern uint32_t adapi_get_ttl(zone_type* zone);

/*
 * Do full zone transaction.
 * \param[in] zone zone
 * \param[in] more_coming more transactions are possible
 *
 */
extern void adapi_trans_full(zone_type* zone, unsigned more_coming);

/*
 * Do incremental zone transaction.
 * \param[in] zone zone
 * \param[in] more_coming more transactions are possible
 *
 */
extern void adapi_trans_diff(zone_type* zone, unsigned more_coming);

/**
 * Add RR.
 * \param[in] zone zone
 * \param[in] rr RR
 * \param[in] backup from backup
 * \return ods_status status
 *
 */
extern ods_status adapi_add_rr(zone_type* zone, ldns_rr* rr, int backup);

/**
 * Delete RR.
 * \param[in] zone zone
 * \param[in] rr RR
 * \param[in] backup from backup
 * \return ods_status status
 *
 */
extern ods_status adapi_del_rr(zone_type* zone, ldns_rr* rr, int backup);

/**
 * Print zonefile.
 * \param[in] fd file descriptor
 * \param[in] zone zone
 * \return ods_status status
 *
 */
extern ods_status adapi_printzone(FILE* fd, zone_type* zone);

/**
 * Print axfr.
 * \param[in] fd file descriptor
 * \param[in] zone zone
 * \return ods_status status
 *
 */
extern ods_status adapi_printaxfr(FILE* fd, zone_type* zone);

/**
 * Print ixfr.
 * \param[in] fd file descriptor
 * \param[in] zone zone
 * \return ods_status status
 *
 */
extern ods_status adapi_printixfr(FILE* fd, zone_type* zone);

#endif /* ADAPTER_ADAPI_H */
