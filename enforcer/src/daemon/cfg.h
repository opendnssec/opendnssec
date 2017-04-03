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
 * Enforcer configuration.
 *
 */

#ifndef DAEMON_CONFIG_H
#define DAEMON_CONFIG_H

#include "config.h"
#include "status.h"

#include <stdio.h>
#include <time.h>

#include "libhsm.h"

typedef enum {
    ENFORCER_DATABASE_TYPE_NONE,
    ENFORCER_DATABASE_TYPE_SQLITE,
    ENFORCER_DATABASE_TYPE_MYSQL
} engineconfig_database_type_t;

/**
 * Engine configuration.
 *
 */
typedef struct engineconfig_struct engineconfig_type;
struct engineconfig_struct {
    const char* cfg_filename;
    const char* policy_filename;
    const char* zonelist_filename;
    const char* zonefetch_filename;
    const char* log_filename;
    const char* pid_filename;
    const char* delegation_signer_submit_command;
    const char* delegation_signer_retract_command;
    const char* clisock_filename;
    const char* working_dir;
    const char* username;
    const char* group;
    const char* chroot;
    const char* datastore; /* Datastore/SQLite or Datastore/MySQL/Database */
    const char* db_host; /* Datastore/MySQL/Host */
    const char* db_username; /* Datastore/MySQL/Username */
    const char* db_password; /* Datastore/MySQL/Password */
    int use_syslog;
    int num_worker_threads;
    int manual_keygen;
    int verbosity;
    int db_port; /* Datastore/MySQL/Host/@Port */
    time_t automatic_keygen_duration;
    time_t rollover_notification;
    hsm_repository_t* repositories;
    engineconfig_database_type_t db_type;
};

/**
 * Configure engine.
 * \param[in] allocator memory allocation
 * \param[in] cfgfile config file
 * \param[in] cmdline_verbosity log level
 * \return engineconfig_type* engine configuration
 *
 */
engineconfig_type* engine_config(const char* cfgfile,
    int cmdline_verbosity, engineconfig_type* oldcfg);

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
