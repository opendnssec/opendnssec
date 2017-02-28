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
 * Configure engine.
 *
 */
engineconfig_type*
engine_config(const char* cfgfile, int cmdline_verbosity)
{
    engineconfig_type* ecfg;
    FILE* cfgfd = NULL;

    if (!cfgfile) {
        return NULL;
    }
    /* open cfgfile */
    cfgfd = ods_fopen(cfgfile, NULL, "r");
    if (cfgfd) {
        ods_log_verbose("[%s] read cfgfile: %s", conf_str, cfgfile);
        /* create config */
        CHECKALLOC(ecfg = (engineconfig_type*) malloc(sizeof(engineconfig_type)));
        /* get values */
        ecfg->cfg_filename = strdup(cfgfile);
        ecfg->zonelist_filename = parse_conf_zonelist_filename(cfgfile);
        ecfg->log_filename = parse_conf_log_filename(cfgfile);
        ecfg->pid_filename = parse_conf_pid_filename(cfgfile);
        ecfg->notify_command = parse_conf_notify_command(cfgfile);
        ecfg->clisock_filename = parse_conf_clisock_filename(cfgfile);
        ecfg->working_dir = parse_conf_working_dir(cfgfile);
        ecfg->username = parse_conf_username(cfgfile);
        ecfg->group = parse_conf_group(cfgfile);
        ecfg->chroot = parse_conf_chroot(cfgfile);
        ecfg->use_syslog = parse_conf_use_syslog(cfgfile);
        ecfg->num_worker_threads = parse_conf_worker_threads(cfgfile);
        ecfg->num_signer_threads = parse_conf_signer_threads(cfgfile);
        /* If any verbosity has been specified at cmd line we will use that */
        if (cmdline_verbosity > 0) {
        	ecfg->verbosity = cmdline_verbosity;
        }
        else {
        	ecfg->verbosity = parse_conf_verbosity(cfgfile);
        }
        ecfg->interfaces = parse_conf_listener(cfgfile);
        ecfg->repositories = parse_conf_repositories(cfgfile);
        /* done */
        ods_fclose(cfgfd);
        return ecfg;
    }
    ods_log_error("[%s] unable to create config: failed to open file %s",
        conf_str, cfgfile);
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
        ods_log_error("[%s] config-check failed: no config", conf_str);
        return ODS_STATUS_CFG_ERR;
    }
    if (!config->cfg_filename) {
        ods_log_error("[%s] config-check failed: no config filename",
            conf_str);
        return ODS_STATUS_CFG_ERR;
    }
    if (!config->zonelist_filename) {
        ods_log_error("[%s] config-check failed: no zonelist filename",
            conf_str);
        return ODS_STATUS_CFG_ERR;
    }
    if (!config->clisock_filename) {
        ods_log_error("[%s] config-check failed: no socket filename",
            conf_str);
        return ODS_STATUS_CFG_ERR;
    }
    if (!config->interfaces) {
        ods_log_error("[%s] config-check failed: no listener",
            conf_str);
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
    fprintf(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    if (config) {
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
        fprintf(out, "\t</Common>\n");

        /* Enforcer */
        fprintf(out, "\t<Enforcer>\n");
        fprintf(out, "\t\t<ZoneListFile>%s</ZoneListFile>\n",
            config->zonelist_filename);
        fprintf(out, "\t</Enforcer>\n");

        /* Signer */
        fprintf(out, "\t<Signer>\n");
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
        if (config->interfaces) {
             size_t i = 0;
             fprintf(out, "\t\t<Listener>\n");

             for (i=0; i < config->interfaces->count; i++) {
                 fprintf(out, "\t\t\t<Interface>");
                 if (config->interfaces->interfaces[i].address) {
                     fprintf(out, "<Address>%s</Address>",
                         config->interfaces->interfaces[i].address);
                 }
                 if (config->interfaces->interfaces[i].port) {
                     fprintf(out, "<Port>%s</Port>",
                         config->interfaces->interfaces[i].port);
                 }
                 fprintf(out, "<Interface>\n");
             }
             fprintf(out, "\t\t</Listener>\n");

        }

        fprintf(out, "\t\t<WorkingDirectory>%s</WorkingDirectory>\n",
            config->working_dir);
        fprintf(out, "\t\t<WorkerThreads>%i</WorkerThreads>\n",
            config->num_worker_threads);
        fprintf(out, "\t\t<SignerThreads>%i</SignerThreads>\n",
            config->num_signer_threads);
        if (config->notify_command) {
            fprintf(out, "\t\t<NotifyCommand>%s</NotifyCommand>\n",
                config->notify_command);
        }
        fprintf(out, "\t</Signer>\n");

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
    listener_cleanup(config->interfaces);
    hsm_repository_free(config->repositories);
    free((void*)config->notify_command);
    free((void*)config->cfg_filename);
    free((void*)config->zonelist_filename);
    free((void*)config->log_filename);
    free((void*)config->pid_filename);
    free((void*)config->clisock_filename);
    free((void*)config->working_dir);
    free((void*)config->username);
    free((void*)config->group);
    free((void*)config->chroot);
    free(config);
}

