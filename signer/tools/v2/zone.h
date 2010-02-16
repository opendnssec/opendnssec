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
 * Zone attributes.
 *
 */

#ifndef SIGNER_ZONE_H
#define SIGNER_ZONE_H

#include "config.h"
#include "v2/adapter.h"
#include "v2/nsec3params.h"
#include "v2/signconf.h"
#include "v2/zonedata.h"

#include <ldns/ldns.h>
#include <stdio.h>

#define MAX_BACKOFF 3600

/**
 * Zone.
 *
 */
typedef struct zone_struct zone_type;
struct zone_struct {
    const char* name;
    ldns_rdf* dname;
    ldns_rr_class klass;
    uint32_t default_ttl;
    uint32_t inbound_serial;
    uint32_t outbound_serial;
    const char* policy_name;
    const char* signconf_filename;
    signconf_type* signconf;
    adapter_type* inbound_adapter;
    adapter_type* outbound_adapter;
    zonedata_type* zonedata;
    nsec3params_type* nsec3params;
};

/**
 * Create a new zone.
 * \param[in] name zone name
 * \param[in] klass zone class
 * \return zone_type* zone
 *
 */
zone_type* zone_create(const char* name, ldns_rr_class klass);

/**
 * Add a RR to the zone.
 * \param[in] zone zone structure
 * \param[in] rr resource record
 * \return 0 on success, 1 on error
 *
 */
int zone_add_rr(zone_type* zone, ldns_rr* rr);

/**
 * Add empty non-terminalz to the zone.
 * \param[in] zone zone structure
 * \return 0 on success, 1 on error
 *
 */
int zone_entize(zone_type* zone);

/**
 * Nsecify zone.
 * \param[in] zone zone structure
 * \return 0 on success, 1 on error
 *
 */
int zone_nsecify(zone_type* zone);

/**
 * Add the DNSKEYs from the Signer Configuration to the zone data.
 * \param[in] zone zone structure
 * \return 0 on success, 1 on error
 *
 */
int zone_publish_dnskeys(zone_type* zone);

/**
 * Calculate the output serial.
 * \param[in] zone zone in question
 *
 */
void zone_calc_outbound_serial(zone_type* zone);

/**
 * Clean up a zone.
 * \param[in] zone zone to cleanup
 *
 */
void zone_cleanup(zone_type* zone);

/**
 * Print a zone.
 * \param[in] out file descriptor
 * \param[in] zone zone to print
 * \param[in] skip_soa if we already have printed the soa
 *
 */
void zone_print(FILE* fd, zone_type* zone, int skip_soa);

#endif /* SIGNER_ZONE_H */
