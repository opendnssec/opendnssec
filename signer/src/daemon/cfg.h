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
 * Signer engine configuration.
 *
 */

#ifndef DAEMON_CONFIG_H
#define DAEMON_CONFIG_H

#include "config.h"
#include "adapter/adapter.h"
#include "shared/allocator.h"
#include "shared/locks.h"
#include "shared/status.h"

#include <stdio.h>

/**
 * Engine configuration.
 *
 */
typedef struct engineconfig_struct engineconfig_type;
struct engineconfig_struct {
    allocator_type* allocator;
    adapter_type** adapters;
    const char* cfg_filename;
    const char* zonelist_filename;
    const char* zonefetch_filename;
    const char* log_filename;
    const char* pid_filename;
    const char* notify_command;
    const char* clisock_filename;
    const char* working_dir;
    const char* username;
    const char* group;
    const char* chroot;
    int use_syslog;
    int num_adapters;
    int num_worker_threads;
    int num_signer_threads;
    int verbosity;
};

/**
 * Configure engine.
 * \param[in] allocator memory allocation
 * \param[in] cfgfile config file
 * \param[in] cmdline_verbosity log level
 * \return engineconfig_type* engine configuration
 *
 */
engineconfig_type* engine_config(allocator_type* allocator,
    const char* cfgfile, int cmdline_verbosity);

/**
 * Check configuration.
 * \param[in] config engine configuration
 * \return ods_status status
 *
 */
ods_status engine_config_check(engineconfig_type* config);

/**
 * Print engine configuration.
 * \param[in] out output file descriptor
 * \param[in] config engine configuration
 *
 */
void engine_config_print(FILE* out, engineconfig_type* config);

/**
 * Clean up config.
 * \param[in] config engine configuration
 *
 */
void engine_config_cleanup(engineconfig_type* config);

#endif /* DAEMON_CONFIG_H */
