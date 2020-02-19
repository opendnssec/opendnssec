/*
 * Copyright (c) 2009-2018 NLNet Labs.
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
 */

/**
 * Parsing signer configuration files.
 *
 */

#ifndef PARSER_SIGNCONFPARSER_H
#define PARSER_SIGNCONFPARSER_H

#include "confparser.h"
#include "status.h"
#include "duration.h"
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
extern keylist_type* parse_sc_keys(void* sc, const char* cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name.
 * \return duration_type* duration
 *
 */
extern duration_type* parse_sc_sig_resign_interval(const char* cfgfile);
extern duration_type* parse_sc_sig_refresh_interval(const char* cfgfile);
extern duration_type* parse_sc_sig_validity_default(const char* cfgfile);
extern duration_type* parse_sc_sig_validity_denial(const char* cfgfile);
extern duration_type* parse_sc_sig_validity_keyset(const char* cfgfile);
extern duration_type* parse_sc_sig_jitter(const char* cfgfile);
extern duration_type* parse_sc_sig_inception_offset(const char* cfgfile);
extern duration_type* parse_sc_dnskey_ttl(const char* cfgfile);
extern const char** parse_sc_dnskey_sigrrs(const char* cfgfile);
extern duration_type* parse_sc_nsec3param_ttl(const char* cfgfile);
extern duration_type* parse_sc_soa_ttl(const char* cfgfile);
extern duration_type* parse_sc_soa_min(const char* cfgfile);
extern duration_type* parse_sc_max_zone_ttl(const char* cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name.
 * \return ldns_rr_type rr type
 *
 */
extern ldns_rr_type parse_sc_nsec_type(const char* cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name.
 * \return uint32_t integer
 *
 */
extern uint32_t parse_sc_nsec3_algorithm(const char* cfgfile);
extern uint32_t parse_sc_nsec3_iterations(const char* cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name.
 * \return int integer
 *
 */
extern int parse_sc_nsec3_optout(const char* cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name.
 * \return boolean
 */
extern int parse_sc_passthrough(const char* cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name.
 * \return const char* string
 *
 */
extern const char* parse_sc_soa_serial(const char* cfgfile);
extern const char* parse_sc_nsec3_salt(const char* cfgfile);

#endif /* PARSER_SIGNCONFPARSER_H */
