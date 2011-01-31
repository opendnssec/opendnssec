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

#include "config.h"
#include "daemon/cfg.h"
#include "parser/confparser.h"
#include "shared/file.h"
#include "shared/log.h"
#include "util/se_malloc.h"

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
    engineconfig_type* ecfg = (engineconfig_type*) se_calloc(1,
        sizeof(engineconfig_type));
    const char* rngfile = ODS_SE_RNGDIR "/conf.rng";
    FILE* cfgfd = NULL;

    if (!cfgfile) {
        ods_log_error("[%s] failed to read: no filename given", conf_str);
        return NULL;
    }
    ods_log_assert(cfgfile);
    ods_log_verbose("[%s] read cfgfile: %s", conf_str, cfgfile);

    /* check syntax (slows down parsing configuration file) */
    if (parse_file_check(cfgfile, rngfile) != 0) {
        ods_log_error("[%s] failed to read: unable to parse file %s",
            conf_str, cfgfile);
        se_free((void*) ecfg);
        return NULL;
    }

    /* open cfgfile */
    cfgfd = ods_fopen(cfgfile, NULL, "r");
    if (cfgfd) {
        /* get values */
        ecfg->cfg_filename = se_strdup(cfgfile);
        ecfg->zonelist_filename = parse_conf_zonelist_filename(cfgfile);
        ecfg->zonefetch_filename = parse_conf_zonefetch_filename(cfgfile);
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
        ecfg->verbosity = cmdline_verbosity;

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
int
engine_check_config(engineconfig_type* config)
{
    int ret = 0;

    if (!config) {
        ods_log_error("[%s] check failed: config does not exist", conf_str);
        return 1;
    }

    /* room for more checks here */

    return ret;
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

        fprintf(out, "\t\t<ZoneListFile>%s</ZoneListFile>\n",
            config->zonelist_filename);
        if (config->zonefetch_filename) {
            fprintf(out, "\t\t<ZoneFetchFile>%s</ZoneFetchFile>\n",
                config->zonefetch_filename);
        }

        fprintf(out, "\t</Common>\n");

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
    return;
}


/**
 * Clean up engine configuration.
 *
 */
void
engine_config_cleanup(engineconfig_type* config)
{
    if (config) {
        if (config->cfg_filename) {
            se_free((void*) config->cfg_filename);
            config->cfg_filename = NULL;
        }
        if (config->zonelist_filename) {
            se_free((void*) config->zonelist_filename);
            config->zonelist_filename = NULL;
        }
        if (config->zonefetch_filename) {
            se_free((void*) config->zonefetch_filename);
            config->zonefetch_filename = NULL;
        }
        if (config->log_filename) {
            se_free((void*) config->log_filename);
            config->zonefetch_filename = NULL;
        }
        if (config->pid_filename) {
            se_free((void*) config->pid_filename);
            config->pid_filename = NULL;
        }
        if (config->notify_command) {
            se_free((void*) config->notify_command);
            config->notify_command = NULL;
        }
        if (config->clisock_filename) {
            se_free((void*) config->clisock_filename);
            config->clisock_filename = NULL;
        }
        if (config->working_dir) {
            se_free((void*) config->working_dir);
            config->working_dir = NULL;
        }
        if (config->username) {
            se_free((void*) config->username);
            config->username = NULL;
        }
        if (config->group) {
            se_free((void*) config->group);
            config->group = NULL;
        }
        if (config->chroot) {
            se_free((void*) config->chroot);
            config->chroot = NULL;
        }
        se_free((void*) config);
    }
    return;
}
