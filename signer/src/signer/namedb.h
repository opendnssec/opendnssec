/*
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
 * Domain name database.
 *
 */

#ifndef SIGNER_NAMEDB_H
#define SIGNER_NAMEDB_H

#include "config.h"
#include <ldns/ldns.h>

typedef struct namedb_struct namedb_type;

#include "signer/denial.h"
#include "signer/domain.h"
#include "signer/zone.h"
#include "signer/nsec3params.h"
#include "signer/names.h"

/**
 * Domain name database.
 *
 */
struct namedb_struct {
    zone_type* zone;
    namesrc_type names;
    uint32_t inbserial;
    uint32_t intserial;
    uint32_t outserial;
    uint32_t altserial;
    unsigned is_initialized : 1;
    unsigned serial_updated : 1;
    unsigned force_serial : 1;
    unsigned have_serial : 1;
};

/**
 * Initialize denial of existence chain.
 * \param[in] db namedb
 *
 */
void namedb_init_denials(namedb_type* db);

/**
 * Create a new namedb.
 * \param[in] zone zone reference
 * \return namedb_type* namedb
 *
 */
namedb_type* namedb_create(void* zone);

/**
 * Determine new SOA SERIAL.
 * \param[in] db namedb
 * \param[in] zone_name zone name
 * \param[in] format <SOA><Serial> format from signer configuration
 * \param[in] inbound_serial inbound serial
 * \return ods_status status
 *
 */
ods_status namedb_update_serial(zone_type* db, const char* zone_name,
    const char* format, uint32_t inbound_serial);

/**
 * Add empty non-terminals for domain.
 * \param[in] db namedb
 * \param[in] domain domain
 * \param[in] apex apex domain name
 * \return ods_status status
 *
 */
ods_status namedb_domain_entize(names_type view, domain_type* domain,
 ldns_rdf* apex);

/**
 * Look up domain.
 * \param[in] db namedb
 * \param[in] dname domain name
 * \return domain_type* domain, if found
 *
 */
domain_type* namedb_lookup_domain(namedb_type* db, ldns_rdf* dname);

/**
 * Add domain to namedb.
 * \param[in] db namedb
 * \param[in] dname domain name
 * \return domain_type* added domain
 *
 */
domain_type* namedb_add_domain(namedb_type* db, ldns_rdf* dname);

/**
 * Delete domain from namedb
 * \param[in] db namedb
 * \param[in] domain domain
 * \return domain_type* deleted domain
 *
 */
domain_type* namedb_del_domain(namedb_type* db, domain_type* domain);

/**
 * Add denial to namedb.
 * \param[in] db namedb
 * \param[in] dname domain name
 * \param[in] n3p NSEC3 parameters, NULL if we do NSEC
 * \return denial_type* added denial
 *
 */
denial_type* namedb_add_denial(zone_type* zone, names_type db, ldns_rdf* dname,
    nsec3params_type* n3p);

/**
 * Delete denial from namedb
 * \param[in] db namedb
 * \param[in] denial denial
 * \return denial_type* deleted denial
 *
 */
denial_type* namedb_del_denial(names_type view, namedb_type* db, denial_type* denial);

/**
 * Examine updates to namedb.
 * \param[in] db namedb
 * \return ods_status status
 *
 */
ods_status namedb_examine(names_type db);

/**
 * Apply differences in db.
 * \param[in] db namedb
 * \param[in] is_ixfr true if incremental change
 * \param[in] more_coming more transactions possible
 *
 */
void namedb_diff(zone_type* zone, names_type view, unsigned is_ixfr, unsigned more_coming);

/**
 * Nsecify db.
 * \param[in] db namedb
 * \param[out] num_added number of NSEC RRs added
 *
 */
void namedb_nsecify(zone_type* zone, names_type view, uint32_t* num_added);

/**
 * Export db to file.
 * \param[in] fd file descriptor
 * \param[in] namedb namedb
 * \param[out] status status
 *
 */
void namedb_export(FILE* fd, names_type view, ods_status* status);

/**
 * Wipe out all NSEC(3) RRsets.
 * \param[in] db namedb
 *
 */
void namedb_wipe_denial(zone_type* zone, names_type view);

/**
 * Clean up namedb.
 * \param[in] namedb namedb
 *
 */
void namedb_cleanup(namedb_type* db);

#endif /* SIGNER_NAMEDB_H */
