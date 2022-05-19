/*
 * Copyright (c) 2017-2018 NLNet Labs.
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
 * Engine configuration for both signer and enforcer
 *
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libxml/xpath.h>
#include <libxml/relaxng.h>
#include <libxml/xmlreader.h>
#include <sys/un.h>

#include "file.h"
#include "log.h"
#include "status.h"
#include "log.h"
#include "cfg.h"
#include "utilities.h"
#include "settings.h"

static const char* conf_str = "config";

ods_status
parse_file_check(const char* cfgfile, const char* rngfile)
{
    const char* parser_str = "parser";
    xmlDocPtr doc = NULL;
    xmlDocPtr rngdoc = NULL;
    xmlRelaxNGParserCtxtPtr rngpctx = NULL;
    xmlRelaxNGValidCtxtPtr rngctx = NULL;
    xmlRelaxNGPtr schema = NULL;
    int status;

    if (!cfgfile || !rngfile) {
        ods_log_error("[%s] no cfgfile or rngfile", parser_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(cfgfile);
    ods_log_assert(rngfile);
    ods_log_debug("[%s] check cfgfile %s with rngfile %s", parser_str,
        cfgfile, rngfile);

    /* Load XML document */
    doc = xmlParseFile(cfgfile);
    if (doc == NULL) {
        ods_log_error("[%s] unable to read cfgfile %s", parser_str,
            cfgfile);
        return ODS_STATUS_XML_ERR;
    }
    /* Load rng document */
    rngdoc = xmlParseFile(rngfile);
    if (rngdoc == NULL) {
        ods_log_error("[%s] unable to read rngfile %s", parser_str,
            rngfile);
        xmlFreeDoc(doc);
        return ODS_STATUS_OK;
    }
    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    if (rngpctx == NULL) {
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        ods_log_error("[%s] unable to create XML RelaxNGs parser context",
           parser_str);
        return ODS_STATUS_XML_ERR;
    }
    /* Parse a schema definition resource and
     * build an internal XML schema structure.
     */
    schema = xmlRelaxNGParse(rngpctx);
    if (schema == NULL) {
        ods_log_error("[%s] unable to parse a schema definition resource",
            parser_str);
        xmlRelaxNGFreeParserCtxt(rngpctx);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return ODS_STATUS_PARSE_ERR;
    }
    /* Create an XML RelaxNGs validation context. */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        ods_log_error("[%s] unable to create RelaxNGs validation context",
            parser_str);
        xmlRelaxNGFree(schema);
        xmlRelaxNGFreeParserCtxt(rngpctx);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return ODS_STATUS_RNG_ERR;
    }
    /* Validate a document tree in memory. */
    status = xmlRelaxNGValidateDoc(rngctx,doc);
    if (status != 0) {
        ods_log_error("[%s] cfgfile validation failed %s", parser_str,
            cfgfile);
        xmlRelaxNGFreeValidCtxt(rngctx);
        xmlRelaxNGFree(schema);
        xmlRelaxNGFreeParserCtxt(rngpctx);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return ODS_STATUS_RNG_ERR;
    }

    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFree(schema);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(rngdoc);
    xmlFreeDoc(doc);
    return ODS_STATUS_OK;
}

int
engine_config_repositories(settings_handle h, struct engineconfig_repository** target)
{
    int count;
    int valid = 0;
    int intvalue;
    struct engineconfig_repository* cur;
    valid |= settings_getcompound(h, &count, "//Configuration/RepositoryList/Repository");
    for(int i=0; i<count; i++) {
        cur = (struct engineconfig_repository*) malloc(sizeof (struct engineconfig_repository));
        valid |= settings_getstring(h, &cur->name, NULL, "//Configuration/RepositoryList/Repository[%d]/@name", i + 1);
        valid |= settings_getstring(h, &cur->module, NULL, "//Configuration/RepositoryList/Repository[%d]/Module", i + 1);
        valid |= settings_getstring(h, &cur->tokenlabel, NULL, "//Configuration/RepositoryList/Repository[%d]/TokenLabel", i + 1);
        valid |= settings_getstring(h, &cur->pin, settings_value_NULL, "//Configuration/RepositoryList/Repository[%d]/PIN", i + 1);
        valid |= settings_getbool(h, (int*)&cur->allow_extract, "//Configuration/RepositoryList/Repository[%d]/AllowExtraction", i + 1);
        valid |= settings_getbool(h, &intvalue, "//Configuration/RepositoryList/Repository[%d]/RequireBackup", i + 1);
        cur->require_backup = intvalue;
        valid |= settings_getbool(h, &intvalue, "//Configuration/RepositoryList/Repository[%d]/SkipPublicKey", i + 1);
        cur->use_pubkey = (intvalue ? 0 : 1);
        *target = cur;
        target = &(cur->next);
    }
    *target = NULL;
    return valid;
}

int
engine_config_listener(settings_handle h, struct engineconfig_listener** target)
{
    int count;
    int valid = 0;
    char* defaultport = "15354";
    struct engineconfig_listener* cur;
    valid |= settings_getcompound(h, &count, "//Configuration/Signer/Listener/Interface");
    for(int i=0; i<count; i++) {
        cur = (struct engineconfig_listener*) malloc(sizeof(struct engineconfig_listener));
        valid |= settings_getstring(h, &cur->address, NULL, "//Configuration/Signer/Listener/Interface[%d]/Address",i+1);
        valid |= settings_getstring(h, &cur->port, &defaultport, "//Configuration/Signer/Listener/Interface[%d]/Port",i+1);
        *target = cur;
        target = &(cur->next);
    }
    *target = NULL;
    return valid;
}

static int
engine_config_logging(settings_handle cfghandle, int cmdline_verbosity, int* verbosity, int* use_syslog, char**log_filename)
{
    int intvalue;
    int valid = 0;
    /* this part also used within startup sequence */
    valid |= settings_getstring(cfghandle, (char**)log_filename, settings_value_NULL, "//Configuration/Common/Logging/File/Filename");
    valid |= settings_getstring(cfghandle, (char**)log_filename, log_filename, "//Configuration/Common/Logging/Syslog/Facility");
    settings_getbool(cfghandle, use_syslog, "//Configuration/Common/Logging/Syslog/Facility");
    if (cmdline_verbosity <= 0) {
        intvalue = ODS_EN_VERBOSITY;
        valid |= settings_getint(cfghandle, verbosity, &intvalue, "//Configuration/Common/Logging/Verbosity");
    } else
        *verbosity = cmdline_verbosity;
    return valid;
}

engineconfig_type*
engine_config(const char* cfgfile,
    int cmdline_verbosity, engineconfig_type* oldcfg)
{
    int valid = 0;
    int intvalue;
    char* strvalue;
    engineconfig_type* ecfg = NULL;
    settings_handle cfghandle = NULL;

    if (!cfgfile || cfgfile[0] == 0) {
        ods_log_error("[%s] failed to read: no filename given", conf_str);
        return NULL;
    }
    ods_log_verbose("[%s] read cfgfile: %s", conf_str, cfgfile);

    if (settings_access(&cfghandle, -1, cfgfile)) {
        ods_log_error("[%s] failed to read: unable to open file %s", conf_str, cfgfile);
        return NULL;
    }
    CHECKALLOC(ecfg = malloc(sizeof (engineconfig_type)));
    if (oldcfg) {
        /* This is a reload */
        ecfg->cfg_filename = dupstr(oldcfg->cfg_filename);
        ecfg->clisock_filename_enforcer = dupstr(oldcfg->clisock_filename_enforcer);
        ecfg->clisock_filename_signer = dupstr(oldcfg->clisock_filename_signer);
        ecfg->working_dir_enforcer = dupstr(oldcfg->working_dir_enforcer);
        ecfg->working_dir_signer = dupstr(oldcfg->working_dir_signer);
        ecfg->username_enforcer = dupstr(oldcfg->username_enforcer);
        ecfg->username_signer = dupstr(oldcfg->username_signer);
        ecfg->group_enforcer = dupstr(oldcfg->group_enforcer);
        ecfg->group_signer = dupstr(oldcfg->group_signer);
        ecfg->chroot_enforcer = dupstr(oldcfg->chroot_enforcer);
        ecfg->chroot_signer = dupstr(oldcfg->chroot_signer);
        ecfg->pid_filename_enforcer = dupstr(oldcfg->pid_filename_enforcer);
        ecfg->pid_filename_signer = dupstr(oldcfg->pid_filename_signer);
        ecfg->datastore = dupstr(oldcfg->datastore);
        ecfg->db_host = dupstr(oldcfg->db_host);
        ecfg->db_username = dupstr(oldcfg->db_username);
        ecfg->db_password = dupstr(oldcfg->db_password);
        ecfg->db_port = oldcfg->db_port;
        ecfg->db_type = oldcfg->db_type;
    } else {
        ecfg->cfg_filename = strdup(cfgfile);
        valid |= settings_getstringdefault(cfghandle, (char**)&ecfg->clisock_filename_enforcer, OPENDNSSEC_ENFORCER_SOCKETFILE, "//Configuration/Enforcer/SocketFile");
        valid |= settings_getstringdefault(cfghandle, (char**)&ecfg->clisock_filename_signer, ODS_SE_SOCKFILE, "//Configuration/Signer/SocketFile");
        if (strlen(ecfg->clisock_filename_enforcer) >= sizeof (((struct sockaddr_un*) 0)->sun_path)) {
            ((char*) ecfg->clisock_filename_enforcer)[sizeof (((struct sockaddr_un*) 0)->sun_path) - 1] = '\0';
            ods_log_warning("SocketFile path too long, truncated to %s", ecfg->clisock_filename_enforcer);
        }
        if (strlen(ecfg->clisock_filename_signer) >= sizeof (((struct sockaddr_un*) 0)->sun_path)) {
            ((char*) ecfg->clisock_filename_signer)[sizeof (((struct sockaddr_un*) 0)->sun_path) - 1] = '\0';
            ods_log_warning("SocketFile path too long, truncated to %s", ecfg->clisock_filename_signer);
        }
        valid |= settings_getstringdefault(cfghandle, (char**)&ecfg->working_dir_enforcer, OPENDNSSEC_ENFORCER_WORKINGDIR, "//Configuration/Enforcer/WorkingDirectory");
        valid |= settings_getstringdefault(cfghandle, (char**)&ecfg->working_dir_signer, ODS_SE_WORKDIR, "//Configuration/Signer/WorkingDirectory");
        valid |= settings_getstring(cfghandle, (char**)&ecfg->username_enforcer, settings_value_NULL, "//Configuration/Enforcer/Privileges/User");
        valid |= settings_getstring(cfghandle, (char**)&ecfg->username_signer, settings_value_NULL, "//Configuration/Signer/Privileges/User");
        valid |= settings_getstring(cfghandle, (char**)&ecfg->group_enforcer, settings_value_NULL, "//Configuration/Enforcer/Privileges/Group");
        valid |= settings_getstring(cfghandle, (char**)&ecfg->group_signer, settings_value_NULL, "//Configuration/Signer/Privileges/Group");
        valid |= settings_getstring(cfghandle, (char**)&ecfg->chroot_enforcer, settings_value_NULL, "//Configuration/Enforcer/Privileges/Directory");
        valid |= settings_getstring(cfghandle, (char**)&ecfg->chroot_signer, settings_value_NULL, "//Configuration/Signer/Privileges/Directory");
        valid |= settings_getstringdefault(cfghandle, (char**)&ecfg->pid_filename_enforcer, OPENDNSSEC_ENFORCER_PIDFILE, "//Configuration/Enforcer/PidFile");
        valid |= settings_getstringdefault(cfghandle, (char**)&ecfg->pid_filename_signer, ODS_SE_PIDFILE, "//Configuration/Signer/PidFile");
        valid |= settings_getstringdefault(cfghandle, (char**)&ecfg->datastore, "KASP", "//Configuration/Enforcer/Datastore/MySQL/Database");
        valid |= settings_getstring(cfghandle, (char**)&ecfg->db_host, settings_value_NULL, "//Configuration/Enforcer/Datastore/MySQL/Host");
        valid |= settings_getstring(cfghandle, (char**)&ecfg->db_username, settings_value_NULL, "//Configuration/Enforcer/Datastore/MySQL/Username");
        valid |= settings_getstring(cfghandle, (char**)&ecfg->db_password, settings_value_NULL, "//Configuration/Enforcer/Datastore/MySQL/Password");
        valid |= settings_getint(cfghandle, &ecfg->db_port, settings_value_NULL, "//Configuration/Enforcer/Datastore/MySQL/Host/@Port");
        intvalue = 0;
        settings_getbool(cfghandle, &intvalue, "//Configuration/Enforcer/Datastore/MySQL/Database");
        if (!intvalue) {
            settings_getbool(cfghandle, &intvalue, "//Configuration/Enforcer/Datastore/SQLite");
            if (intvalue) {
                valid |= settings_getstring(cfghandle, (char**)&ecfg->datastore, NULL, "//Configuration/Enforcer/Datastore/SQLite");
                intvalue = ENFORCER_DATABASE_TYPE_SQLITE;
            } else
                intvalue = ENFORCER_DATABASE_TYPE_NONE;
        } else
            intvalue = ENFORCER_DATABASE_TYPE_MYSQL;
        ecfg->db_type = intvalue;
    }

    /* get values */
    valid |= settings_getstring(cfghandle, (char**)&ecfg->policy_filename, NULL, "//Configuration/Common/PolicyFile");
    valid |= settings_getstring(cfghandle, (char**)&ecfg->zonelist_filename_enforcer, NULL, "//Configuration/Common/ZoneListFile");
    valid |= settings_getstringdefault(cfghandle, &strvalue, OPENDNSSEC_ENFORCER_WORKINGDIR, "//Configuration/Enforcer/WorkingDirectory");
    asprintf((char**)&ecfg->zonelist_filename_signer, "%s%s%s", strvalue, ((strlen(strvalue) > 0 && strvalue[strlen(strvalue) - 1] != '/') ? "/" : ""), OPENDNSSEC_ENFORCER_ZONELIST);
    valid |= settings_getstring(cfghandle, (char**)&ecfg->zonefetch_filename, settings_value_NULL, "//Configuration/Common/ZoneFetchFile");

    engine_config_logging(cfghandle, cmdline_verbosity, &ecfg->verbosity, &ecfg->use_syslog, (char**)&ecfg->log_filename);

    valid |= settings_getstring(cfghandle, (char**)&ecfg->delegation_signer_submit_command, settings_value_NULL, "//Configuration/Enforcer/DelegationSignerSubmitCommand");
    valid |= settings_getstring(cfghandle, (char**)&ecfg->delegation_signer_retract_command, settings_value_NULL, "//Configuration/Enforcer/DelegationSignerRetractCommand");
    valid |= settings_getstring(cfghandle, (char**)&ecfg->notify_command, settings_value_NULL, "//Configuration/Signer/NotifyCommand");
    intvalue = ODS_SE_WORKERTHREADS;
    valid |= settings_getint(cfghandle, &ecfg->num_worker_threads_enforcer, &intvalue, "//Configuration/Enforcer/WorkerThreads");
    valid |= settings_getint(cfghandle, &ecfg->num_worker_threads_signer, &intvalue, "//Configuration/Signer/WorkerThreads");
    valid |= settings_getint(cfghandle, &ecfg->num_signer_threads, &ecfg->num_worker_threads_signer, "//Configuration/Signer/SignerThreads");

    valid |= settings_getbool(cfghandle, &ecfg->manual_keygen, "//Configuration/Enforcer/ManualKeyGeneration");
    valid |= engine_config_repositories(cfghandle, &ecfg->repositories);
    valid |= engine_config_listener(cfghandle, &ecfg->interfaces);
    valid |= settings_getduration(cfghandle, &ecfg->automatic_keygen_duration, 365 * 24 * 3600, "//Configuration/Enforcer/AutomaticKeyGenerationPeriod");
    valid |= settings_getduration(cfghandle, &ecfg->rollover_notification, 0, "//Configuration/Enforcer/RolloverNotification");

    settings_access(&cfghandle, -1, NULL);
    return ecfg;
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
    if (!config->zonelist_filename_enforcer) {
        ods_log_error("[%s] check failed: no zonelist filename for enforcer", conf_str);
        return ODS_STATUS_CFG_ERR;
    }
    if (!config->zonelist_filename_signer) {
        ods_log_error("[%s] check failed: no zonelist filename for signer", conf_str);
        return ODS_STATUS_CFG_ERR;
    }

    if (!config->clisock_filename_enforcer) {
        ods_log_error("[%s] check failed: no socket filename for enforcer", conf_str);
        return ODS_STATUS_CFG_ERR;
    }
    if (!config->clisock_filename_signer) {
        ods_log_error("[%s] check failed: no socket filename for signer", conf_str);
        return ODS_STATUS_CFG_ERR;
    }

    if (!config->datastore) {
        ods_log_error("[%s] check failed: no datastore", conf_str);
        return ODS_STATUS_CFG_ERR;
    }
    if (!config->cfg_filename) {
        ods_log_error("[%s] check failed: no config filename", conf_str);
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

        if(config->repositories) {
            fprintf(out, "\t<RepositoryList>\n");
            for(struct engineconfig_repository* repo = config->repositories; repo; repo=repo->next) {
                fprintf(out, "\t\t<Repository name=\"%s\">\n", repo->name);
                fprintf(out, "\t\t\t<Module>%s</Module>\n",repo->module);
                fprintf(out, "\t\t\t<TokenLabel>%s</Module>\n",repo->tokenlabel);
                if(repo->pin)
                    fprintf(out, "\t\t\t<PIN>%s</Module>\n",repo->pin);
                //if(repo->capacity)
                //    fprintf(out, "\t\t\t<Capacity>%d</Capacity>\n",repo->capacity);
                if(repo->require_backup)
                    fprintf(out, "\t\t\t<RequireBackup/>\n");
                if(!repo->use_pubkey)
                    fprintf(out, "\t\t\t<SkipPublicKey/>\n");
                if(repo->allow_extract)
                    fprintf(out, "\t\t\t<AllowExtraction/>\n");
                fprintf(out, "\t\t</Repository>\n");
            }
            fprintf(out, "\t</RepositoryList>\n");
        }

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
            config->zonelist_filename_enforcer);
        if (config->zonefetch_filename) {
            fprintf(out, "\t\t<ZoneFetchFile>%s</ZoneFetchFile>\n",
                config->zonefetch_filename);
        }

        fprintf(out, "\t</Common>\n");

        /* Enforcer */
        fprintf(out, "\t<Enforcer>\n");
        if (config->username_enforcer || config->group_enforcer || config->chroot_enforcer) {
            fprintf(out, "\t\t<Privileges>\n");
            if (config->username_enforcer) {
                fprintf(out, "\t\t<User>%s</User>\n", config->username_enforcer);
            }
            if (config->group_enforcer) {
                fprintf(out, "\t\t<Group>%s</Group>\n", config->group_enforcer);
            }
            if (config->chroot_enforcer) {
                fprintf(out, "\t\t<Directory>%s</Directory>\n",
                    config->chroot_enforcer);
            }
            fprintf(out, "\t\t</Privileges>\n");
        }
        fprintf(out, "\t\t<WorkingDirectory>%s</WorkingDirectory>\n",
            config->working_dir_enforcer);
        fprintf(out, "\t\t<WorkerThreads>%i</WorkerThreads>\n",
            config->num_worker_threads_enforcer);
        if (config->manual_keygen) {
            fprintf(out, "\t\t<ManualKeyGeneration/>\n");
        }
        if (config->automatic_keygen_duration) {
            duration_type* period = duration_create();
            duration_set_time(period, config->automatic_keygen_duration);
            char* periodstr = duration2string(period);
            fprintf(out, "\t\t<AutomaticKeyGenerationPeriod>%s</AutomaticKeyGenerationPeriod>\n",periodstr);
            free(periodstr);
            duration_cleanup(period);
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

        /* Signer */
        fprintf(out, "\t<Signer>\n");
        if (config->username_signer || config->group_signer || config->chroot_signer) {
            fprintf(out, "\t\t<Privileges>\n");
            if (config->username_signer) {
                fprintf(out, "\t\t<User>%s</User>\n", config->username_signer);
            }
            if (config->group_signer) {
                fprintf(out, "\t\t<Group>%s</Group>\n", config->group_signer);
            }
            if (config->chroot_signer) {
                fprintf(out, "\t\t<Directory>%s</Directory>\n",
                    config->chroot_signer);
            }
            fprintf(out, "\t\t</Privileges>\n");
        }
        if (config->interfaces) {
            fprintf(out, "\t\t<Listener>\n");

            struct engineconfig_listener *listener;
            listener = config->interfaces;

            while (listener) {
                fprintf(out, "\t\t\t<Interface>");
                if (listener->address) {
                    fprintf(out, "<Address>%s</Address>",
                        listener->address);
                }
                if (listener->port) {
                    fprintf(out, "<Port>%s</Port>",
                        listener->port);
                }
                fprintf(out, "</Interface>\n");
                listener = listener->next;
            }
            fprintf(out, "\t\t</Listener>\n");
        }

        fprintf(out, "\t\t<WorkingDirectory>%s</WorkingDirectory>\n",
            config->working_dir_signer);
        fprintf(out, "\t\t<WorkerThreads>%i</WorkerThreads>\n",
            config->num_worker_threads_signer);
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

void
engine_config_freehsms(struct engineconfig_repository* hsm)
{
    struct engineconfig_repository *hsmtofree;
    hsmtofree = hsm;
    while (hsmtofree) {
        hsm = hsmtofree->next;
        free((void*)hsmtofree->name);
        free((void*)hsmtofree->module);
        free((void*)hsmtofree->pin);
        free((void*)hsmtofree->tokenlabel);
        free(hsmtofree);
        hsmtofree = hsm;
    }
}

void
engine_config_freelistener(struct engineconfig_listener* listener)
{
    struct engineconfig_listener *listenertofree;
    listenertofree = listener;
    while (listenertofree) {
        listener = listenertofree->next;
        free((void*)listenertofree->address);
        free((void*)listenertofree->port);
        free(listenertofree);
        listenertofree = listener;
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
    free((void*) config->zonelist_filename_enforcer);
    free((void*) config->zonelist_filename_signer);
    free((void*) config->zonefetch_filename);
    free((void*) config->log_filename);
    free((void*) config->pid_filename_enforcer);
    free((void*) config->pid_filename_signer);
    free((void*) config->delegation_signer_submit_command);
    free((void*) config->delegation_signer_retract_command);
    free((void*) config->clisock_filename_enforcer);
    free((void*) config->working_dir_enforcer);
    free((void*) config->username_enforcer);
    free((void*) config->group_enforcer);
    free((void*) config->chroot_enforcer);
    free((void*) config->clisock_filename_signer);
    free((void*) config->working_dir_signer);
    free((void*) config->username_signer);
    free((void*) config->group_signer);
    free((void*) config->chroot_signer);
    free((void*) config->datastore);
    free((void*) config->db_host);
    free((void*) config->db_username);
    free((void*) config->db_password);
    engine_config_freehsms(config->repositories);
    config->repositories = NULL;
    engine_config_freelistener(config->interfaces);
    config->interfaces = NULL;    
    free((void*) config->notify_command);
    free(config);
}

struct engineconfig_repository*
parse_conf_repositories(const char* cfgfile)
{
    struct engineconfig_repository* repositories;
    settings_handle cfghandle;
    if (settings_access(&cfghandle, -1, cfgfile)) {
        ods_log_error("[%s] failed to read: unable to open file %s", conf_str, cfgfile);
        return NULL;
    }
    engine_config_repositories(cfghandle, &repositories);
    settings_access(&cfghandle, -1, NULL);
    return repositories;
}

int
parse_conf_logging(const char* cfgfile, int cmdline_verbosity, int* verbosity, int* use_syslog, char**log_filename)
{
    int valid = 0;
    settings_handle cfghandle;
    settings_access(&cfghandle, -1, cfgfile);
    valid |= engine_config_logging(cfghandle, cmdline_verbosity, verbosity, use_syslog, log_filename);
    settings_access(&cfghandle, -1, NULL);
    return valid;
}
