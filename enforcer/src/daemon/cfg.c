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
 * Signer engine configuration.
 *
 */

#include "config.h"
#include "daemon/cfg.h"
#include "parser/confparser.h"
#include "file.h"
#include "log.h"
#include "status.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static const char* conf_str = "config";

/**
 * duplicate string but don't ignore NULL ptrs
 */
static const char *
strdup_or_null(const char *s)
{
    return s?strdup(s):s;
}

/**
 * Configure engine.
 *
 */
engineconfig_type*
engine_config(const char* cfgfile,
    int cmdline_verbosity, engineconfig_type* oldcfg)
{
    engineconfig_type* ecfg;
    const char* rngfile = ODS_SE_RNGDIR "/conf.rng";
    FILE* cfgfd = NULL;

    if (!cfgfile || cfgfile[0] == 0) {
        ods_log_error("[%s] failed to read: no filename given", conf_str);
        return NULL;
    }
    ods_log_verbose("[%s] read cfgfile: %s", conf_str, cfgfile);

    /* check syntax (slows down parsing configuration file) */
    if (parse_file_check(cfgfile, rngfile) != ODS_STATUS_OK) {
        ods_log_error("[%s] failed to read: unable to parse file %s",
            conf_str, cfgfile);
        return NULL;
    }

    /* open cfgfile */
    cfgfd = ods_fopen(cfgfile, NULL, "r");
    if (cfgfd) {
        ecfg = malloc(sizeof(engineconfig_type));
        if (!ecfg) {
            ods_log_error("[%s] failed to read: malloc failed", conf_str);
            ods_fclose(cfgfd);
            return NULL;
        }
        if (oldcfg) {
            /* This is a reload */
            ecfg->cfg_filename = strdup(oldcfg->cfg_filename);
            ecfg->clisock_filename = strdup(oldcfg->clisock_filename);
            ecfg->working_dir = strdup(oldcfg->working_dir);
            ecfg->username = strdup_or_null(oldcfg->username);
            ecfg->group = strdup_or_null(oldcfg->group);
            ecfg->chroot = strdup_or_null(oldcfg->chroot);
            ecfg->pid_filename = strdup(oldcfg->pid_filename);
            ecfg->datastore = strdup(oldcfg->datastore);
            ecfg->db_host = strdup_or_null(oldcfg->db_host);
            ecfg->db_username = strdup_or_null(oldcfg->db_username);
            ecfg->db_password = strdup_or_null(oldcfg->db_password);
            ecfg->db_port = oldcfg->db_port;
            ecfg->db_type = oldcfg->db_type;
        } else {
            ecfg->cfg_filename = strdup(cfgfile);
            ecfg->clisock_filename = parse_conf_clisock_filename(cfgfile);
            ecfg->working_dir = parse_conf_working_dir(cfgfile);
            ecfg->username = parse_conf_username(cfgfile);
            ecfg->group = parse_conf_group(cfgfile);
            ecfg->chroot = parse_conf_chroot(cfgfile);
            ecfg->pid_filename = parse_conf_pid_filename(cfgfile);
            ecfg->datastore = parse_conf_datastore(cfgfile);
            ecfg->db_host = parse_conf_db_host(cfgfile);
            ecfg->db_username = parse_conf_db_username(cfgfile);
            ecfg->db_password = parse_conf_db_password(cfgfile);
            ecfg->db_port = parse_conf_db_port(cfgfile);
            ecfg->db_type = parse_conf_db_type(cfgfile);
        }
        /* get values */
        ecfg->policy_filename = parse_conf_policy_filename(cfgfile);
        ecfg->zonelist_filename = parse_conf_zonelist_filename(cfgfile);
        ecfg->zonefetch_filename = parse_conf_zonefetch_filename(cfgfile);
        ecfg->log_filename = parse_conf_log_filename(cfgfile);
        ecfg->delegation_signer_submit_command = 
            parse_conf_delegation_signer_submit_command(cfgfile);
        ecfg->delegation_signer_retract_command = 
            parse_conf_delegation_signer_retract_command(cfgfile);
        ecfg->use_syslog = parse_conf_use_syslog(cfgfile);
        ecfg->num_worker_threads = parse_conf_worker_threads(cfgfile);
        ecfg->manual_keygen = parse_conf_manual_keygen(cfgfile);
        ecfg->repositories = parse_conf_repositories(cfgfile);
        /* If any verbosity has been specified at cmd line we will use that */
        ecfg->verbosity = cmdline_verbosity > 0 ?
            cmdline_verbosity : parse_conf_verbosity(cfgfile);
        ecfg->automatic_keygen_duration =
            parse_conf_automatic_keygen_period(cfgfile);
        ecfg->rollover_notification =
            parse_conf_rollover_notification(cfgfile);

        /* done */
        ods_fclose(cfgfd);
        return ecfg;
    }

    ods_log_error("[%s] failed to read: unable to open file %s", conf_str,
        cfgfile);
    return NULL;
}


/**
 * Check configuration.
 *
 */
ods_status
engine_config_check(engineconfig_type* config)
{
    if (!config) {
        ods_log_error("[%s] check failed: config does not exist", conf_str);
        return ODS_STATUS_CFG_ERR;
    }
    if (!config->policy_filename) {
        ods_log_error("[%s] check failed: no policy filename", conf_str);
        return ODS_STATUS_CFG_ERR;
    }
    if (!config->zonelist_filename) {
        ods_log_error("[%s] check failed: no zonelist filename", conf_str);
        return ODS_STATUS_CFG_ERR;
    }
    if (!config->clisock_filename) {
        ods_log_error("[%s] check failed: no socket filename", conf_str);
        return ODS_STATUS_CFG_ERR;
    }
    if (!config->datastore) {
        ods_log_error("[%s] check failed: no datastore", conf_str);
        return ODS_STATUS_CFG_ERR;
    }

    /*  [TODO] room for more checks here */

    return ODS_STATUS_OK;
}


/**
 * Print configuration.
 *
 */
void
engine_config_print(FILE* out, engineconfig_type* config)
{
    if (!out) {
        return;
    }
    ods_log_assert(out);

    fprintf(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    if (config) {
        ods_log_assert(config);

        fprintf(out, "<Configuration>\n");

        /* Common */
        fprintf(out, "\t<Common>\n");
        if (config->use_syslog && config->log_filename) {
	        fprintf(out, "\t\t<Logging>\n");
	        fprintf(out, "\t\t\t<Syslog>\n");
	        fprintf(out, "\t\t\t\t<Facility>%s</Facility>\n",
                config->log_filename);
	        fprintf(out, "\t\t\t</Syslog>\n");
	        fprintf(out, "\t\t</Logging>\n");
		} else if (config->log_filename) {
	        fprintf(out, "\t\t<Logging>\n");
	        fprintf(out, "\t\t\t<File>\n");
	        fprintf(out, "\t\t\t\t<Filename>%s</Filename>\n",
                config->log_filename);
	        fprintf(out, "\t\t\t</File>\n");
	        fprintf(out, "\t\t</Logging>\n");
        }

        fprintf(out, "\t\t<PolicyFile>%s</PolicyFile>\n",
                config->policy_filename);
        fprintf(out, "\t\t<ZoneListFile>%s</ZoneListFile>\n",
            config->zonelist_filename);
        if (config->zonefetch_filename) {
            fprintf(out, "\t\t<ZoneFetchFile>%s</ZoneFetchFile>\n",
                config->zonefetch_filename);
        }

        fprintf(out, "\t</Common>\n");

        /* Enforcer */
        fprintf(out, "\t<Enforcer>\n");
        if (config->username || config->group || config->chroot) {
            fprintf(out, "\t\t<Privileges>\n");
            if (config->username) {
                fprintf(out, "\t\t<User>%s</User>\n", config->username);
            }
            if (config->group) {
                fprintf(out, "\t\t<Group>%s</Group>\n", config->group);
            }
            if (config->chroot) {
                fprintf(out, "\t\t<Directory>%s</Directory>\n",
                    config->chroot);
            }
            fprintf(out, "\t\t</Privileges>\n");
        }
        fprintf(out, "\t\t<WorkingDirectory>%s</WorkingDirectory>\n",
            config->working_dir);
        fprintf(out, "\t\t<WorkerThreads>%i</WorkerThreads>\n",
            config->num_worker_threads);
        if (config->manual_keygen) {
            fprintf(out, "\t\t<ManualKeyGeneration/>\n");
        }
        if (config->delegation_signer_submit_command) {
            fprintf(out, "\t\t<DelegationSignerSubmitCommand>%s</DelegationSignerSubmitCommand>\n",
                config->delegation_signer_submit_command);
        }
        if (config->delegation_signer_retract_command) {
            fprintf(out, "\t\t<DelegationSignerRetractCommand>%s</DelegationSignerRetractCommand>\n",
                    config->delegation_signer_retract_command);
        }
        fprintf(out, "\t</Enforcer>\n");

        fprintf(out, "</Configuration>\n");

        /* make configurable:
           - pid_filename
           - clisock_filename
         */
    }
}

/**
 * Clean up config.
 *
 */
void
engine_config_cleanup(engineconfig_type* config)
{
    if (!config) {
        return;
    }
    free((void*) config->cfg_filename);
    free((void*) config->policy_filename);
    free((void*) config->zonelist_filename);
    free((void*) config->zonefetch_filename);
    free((void*) config->log_filename);
    free((void*) config->pid_filename);
    free((void*) config->delegation_signer_submit_command);
    free((void*) config->delegation_signer_retract_command);
    free((void*) config->clisock_filename);
    free((void*) config->working_dir);
    free((void*) config->username);
    free((void*) config->group);
    free((void*) config->chroot);
    free((void*) config->datastore);
	free((void*) config->db_host);
	free((void*) config->db_username);
	free((void*) config->db_password);
    hsm_repository_free(config->repositories);
	config->repositories = NULL;
    free(config);
}

