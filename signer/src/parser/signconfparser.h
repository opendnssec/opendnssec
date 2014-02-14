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
 * Parsing signer configuration files.
 *
 */

#ifndef PARSER_SIGNCONFPARSER_H
#define PARSER_SIGNCONFPARSER_H

#include "parser/confparser.h"
#include "shared/allocator.h"
#include "shared/duration.h"
#include "signer/keys.h"
#include "config.h"

#include <ldns/ldns.h>

/**
 * Parse keys from the signer configuration file.
 * \param[in] sc signer configuration reference
 * \param[in] cfgfile the configuration file name.
 * \return keylist_type* key list
 *
 */
keylist_type* parse_sc_keys(void* sc, const char* cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name.
 * \return duration_type* duration
 *
 */
duration_type* parse_sc_sig_resign_interval(const char* cfgfile);
duration_type* parse_sc_sig_refresh_interval(const char* cfgfile);
duration_type* parse_sc_sig_validity_default(const char* cfgfile);
duration_type* parse_sc_sig_validity_denial(const char* cfgfile);
duration_type* parse_sc_sig_jitter(const char* cfgfile);
duration_type* parse_sc_sig_inception_offset(const char* cfgfile);
duration_type* parse_sc_dnskey_ttl(const char* cfgfile);
duration_type* parse_sc_nsec3param_ttl(const char* cfgfile);
duration_type* parse_sc_soa_ttl(const char* cfgfile);
duration_type* parse_sc_soa_min(const char* cfgfile);
duration_type* parse_sc_max_zone_ttl(const char* cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name.
 * \return ldns_rr_type rr type
 *
 */
ldns_rr_type parse_sc_nsec_type(const char* cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name.
 * \return uint32_t integer
 *
 */
uint32_t parse_sc_nsec3_algorithm(const char* cfgfile);
uint32_t parse_sc_nsec3_iterations(const char* cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name.
 * \return int integer
 *
 */
int parse_sc_nsec3_optout(const char* cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name.
 * \return const char* string
 *
 */
const char* parse_sc_soa_serial(allocator_type* allocator,
    const char* cfgfile);
const char* parse_sc_nsec3_salt(allocator_type* allocator,
    const char* cfgfile);

#endif /* PARSER_SIGNCONFPARSER_H */
