/*
 * Copyright (c) 2017 NLNet Labs. All rights reserved.
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
 * Parsing configuration files.
 */

#ifndef PARSER_CONFPARSER_H
#define PARSER_CONFPARSER_H

#include <time.h>
#include "config.h"
#include "status.h"
#include "cfg.h"
#include <stdint.h>

/**
 * Check config file with rng file.
 * \param[in] cfgfile the configuration file name
 * \param[in] rngfile the rng file name
 * \return ods_status status
 *
 */
ods_status parse_file_check(const char* cfgfile, const char* rngfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile configuration file
 * \param[in] expr xml expression
 * \param[in] required if the element is required
 * \return const char* string value
 *
 */
const char* parse_conf_string(const char* cfgfile, const char* expr,
    int required);

/**
 * Parse elements from the configuration file.
 * \param[in] allocator the allocator
 * \param[in] cfgfile the configuration file name
 * \return const char* string
 *
 */

/** Common */
const char* parse_conf_policy_filename(const char* cfgfile);
const char* parse_conf_zonelist_filename_enforcer(const char* cfgfile);
const char* parse_conf_zonelist_filename_signer(const char* cfgfile);
const char* parse_conf_zonefetch_filename(const char* cfgfile);
const char* parse_conf_log_filename(const char* cfgfile);

/** Enforcer and Signer specific */
const char* parse_conf_pid_filename(const char* cfgfile, int is_enforcer);
const char* parse_conf_delegation_signer_submit_command(const char* cfgfile);
const char* parse_conf_delegation_signer_retract_command(const char* cfgfile);
const char* parse_conf_clisock_filename(const char* cfgfile, int is_enforcer);
const char* parse_conf_working_dir(const char* cfgfile, int is_enforcer);
const char* parse_conf_username(const char* cfgfile, int is_enforcer);
const char* parse_conf_group(const char* cfgfile, int is_enforcer);
const char* parse_conf_chroot(const char* cfgfile, int is_enforcer);
const char* parse_conf_datastore(const char* cfgfile);
const char* parse_conf_db_host(const char* cfgfile);
const char* parse_conf_db_username(const char* cfgfile);
const char* parse_conf_db_password(const char* cfgfile);
engineconfig_database_type_t parse_conf_db_type(const char *cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name
 * \return int integer
 *
 */

/** Common */
int parse_conf_use_syslog(const char* cfgfile);
int parse_conf_verbosity(const char* cfgfile);

/** Enforcer and signer specific */
int parse_conf_worker_threads(const char* cfgfile, int is_enforcer);
int parse_conf_signer_threads(const char* cfgfile);
int parse_conf_manual_keygen(const char* cfgfile);
int parse_conf_db_port(const char *cfgfile);
time_t parse_conf_automatic_keygen_period(const char* cfgfile);
struct engineconfig_repository* parse_conf_repositories(const char* cfgfile);
const char* parse_conf_notify_command(const char* cfgfile);
struct engineconfig_listener* parse_conf_listener(const char* cfgfile);

#endif /* PARSE_CONFPARSER_H */
