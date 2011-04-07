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
 * Parsing configuration files.
 */

#ifndef PARSER_CONFPARSER_H
#define PARSER_CONFPARSER_H

#include "config.h"
#include "adapter/adapter.h"
#include "shared/allocator.h"
#include "shared/status.h"

#define ADMAX 6 /* Maximum number of adapters that can be initialized */

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
 * Parse the adapters.
 * \param[in] allocator the allocator
 * \param[in] cfgfile the configuration file name
 * \param[out] count number of adapters encountered
 * \return adapter_type** bunch of adapters that need to be initialized.
 *
 */
adapter_type** parse_conf_adapters(allocator_type* allocator,
    const char* cfgfile, int* count);

/**
 * Parse elements from the configuration file.
 * \param[in] allocator the allocator
 * \param[in] cfgfile the configuration file name
 * \return const char* string
 *
 */

/** Common */
const char* parse_conf_zonelist_filename(allocator_type* allocator,
    const char* cfgfile);
const char* parse_conf_zonefetch_filename(allocator_type* allocator,
    const char* cfgfile);
const char* parse_conf_log_filename(allocator_type* allocator,
    const char* cfgfile);

/** Signer specific */
const char* parse_conf_pid_filename(allocator_type* allocator,
    const char* cfgfile);
const char* parse_conf_notify_command(allocator_type* allocator,
    const char* cfgfile);
const char* parse_conf_clisock_filename(allocator_type* allocator,
    const char* cfgfile);
const char* parse_conf_working_dir(allocator_type* allocator,
    const char* cfgfile);
const char* parse_conf_username(allocator_type* allocator,
    const char* cfgfile);
const char* parse_conf_group(allocator_type* allocator,
    const char* cfgfile);
const char* parse_conf_chroot(allocator_type* allocator,
    const char* cfgfile);

/**
 * Parse elements from the configuration file.
 * \param[in] cfgfile the configuration file name
 * \return int integer
 *
 */

/** Common */
int parse_conf_use_syslog(const char* cfgfile);

/** Signer specific */
int parse_conf_worker_threads(const char* cfgfile);
int parse_conf_signer_threads(const char* cfgfile);

#endif /* PARSE_CONFPARSER_H */
