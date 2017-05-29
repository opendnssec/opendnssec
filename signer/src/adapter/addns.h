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
 * DNS Adapters.
 *
 */

#ifndef ADAPTER_ADDNS_H
#define ADAPTER_ADDNS_H

#include "config.h"
#include "status.h"
#include "wire/acl.h"
#include "wire/tsig.h"
#include "signer/zone.h"
#include "signer/names.h"
#include <ldns/ldns.h>
#include <stdio.h>
#include <time.h>

/**
 * DNS input adapter.
 *
 */
typedef struct dnsin_struct dnsin_type;
struct dnsin_struct {
    acl_type* request_xfr;
    acl_type* allow_notify;
    tsig_type* tsig;
    time_t last_modified;
};

/**
 * DNS output adapter.
 *
 */
typedef struct dnsout_struct dnsout_type;
struct dnsout_struct {
    acl_type* provide_xfr;
    acl_type* do_notify;
    tsig_type* tsig;
    time_t last_modified;
};

/**
 * Create DNS input adapter.
 * \return dnsin_type* DNS input adapter
 *
 */
dnsin_type* dnsin_create(void);

/**
 * Create DNS output adapter.
 * \return dnsout_type* DNS output adapter
 *
 */
dnsout_type* dnsout_create(void);

/**
 * Update DNS input adapter.
 * \param[out] addns DNS input adapter
 * \param[in] filename filename
 * \param[out] last_mod last modified
 * \return ods_status status
 *
 */
ods_status dnsin_update(dnsin_type** addns, const char* filename,
    time_t* last_mod);

/**
 * Update DNS output adapter.
 * \param[out] addns DNS output adapter
 * \param[in] filename filename
 * \param[out] last_mod last modified
 * \return ods_status status
 *
 */
ods_status dnsout_update(dnsout_type** addns, const char* filename,
    time_t* last_mod);

/**
 * Read the next RR from zone file.
 * \param[in] fd file descriptor
 * \param[in] line read line
 * \param[in] orig origin
 * \param[in] prev previous name
 * \param[in] ttl default ttl
 * \param[in] status status
 * \param[out] l line count
 * \return ldns_rr* RR
 *
 */
ldns_rr* addns_read_rr(FILE* fd, char* line, ldns_rdf** orig, ldns_rdf** prev,
    uint32_t* ttl, ldns_status* status, unsigned int* l);


/**
 * Read zone from DNS input adapter.
 * \param[in] zone zone reference
 * \return ods_status status
 *
 */
ods_status addns_read(zone_type* zone, names_type view);

/**
 * Write zone to DNS output adapter.
 * \param[in] zone zone reference
 * \return ods_status status
 *
 */
ods_status addns_write(zone_type* zone, names_type view);

/**
 * Clean up DNS input adapter.
 * \param[in] addns DNS input adapter
 *
 */
void dnsin_cleanup(dnsin_type* addns);

/**
 * Clean up DNS output adapter.
 * \param[in] addns DNS output adapter
 *
 */
void dnsout_cleanup(dnsout_type* addns);

#endif /* ADAPTER_ADDNS_H */
