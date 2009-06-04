/*
 * $Id$
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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

/* 
 * communicator.c code implements the server_main
 * function needed by daemon.c
 *
 * The bit that makes the daemon do something useful
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include "daemon.h"
#include "daemon_util.h"
#include "communicator.h"
#include "kaspaccess.h"
#include "ksm/ksm.h"
#include "ksm/memory.h"
#include "ksm/string_util2.h"
#include "ksm/datetime.h"
#include "config.h"

#include <libxml/xmlreader.h>
#include <libxml/xpath.h>

    int
server_init(DAEMONCONFIG *config)
{
    if (config == NULL) {
        log_msg(NULL, LOG_ERR, "Error, no config provided");
        exit(1);
    }

    /* set the default pidfile if nothing was provided on the command line*/
    if (config->pidfile == NULL) {
        config->pidfile = COM_PID;
    }

    return 0;
}

/*
 * Main loop of keygend server
 */
    void
server_main(DAEMONCONFIG *config)
{
    DB_HANDLE	dbhandle;
    int status = 0;
    int status2 = 0;

    xmlTextReaderPtr reader;
    xmlDocPtr doc;
    xmlXPathContextPtr xpathCtx;
    xmlXPathObjectPtr xpathObj;

    int ret = 0; /* status of the XML parsing */
    char* zonelist_filename = ZONELISTFILE;
    char* zone_name;
    char* current_policy;
    char* current_filename;
    
    xmlChar *name_expr = (unsigned char*) "name";
    xmlChar *policy_expr = (unsigned char*) "//Zone/Policy";
    xmlChar *filename_expr = (unsigned char*) "//Zone/SignerConfiguration";

    struct timeval tv;

    KSM_POLICY *policy;

    if (config == NULL) {
        log_msg(NULL, LOG_ERR, "Error, no config provided");
        exit(1);
    }

    policy = (KSM_POLICY *)malloc(sizeof(KSM_POLICY));
    policy->signer = (KSM_SIGNER_POLICY *)malloc(sizeof(KSM_SIGNER_POLICY));
    policy->signature = (KSM_SIGNATURE_POLICY *)malloc(sizeof(KSM_SIGNATURE_POLICY));
    policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
    policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
    policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
    policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));
    policy->name = (char *)calloc(KSM_NAME_LENGTH, sizeof(char));
    /* Let's check all of those mallocs, or should we use MemMalloc ? */
    if (policy->signer == NULL || policy->signature == NULL ||
            policy->ksk == NULL || policy->zsk == NULL || 
            policy->denial == NULL || policy->enforcer == NULL) {
        log_msg(config, LOG_ERR, "Malloc for policy struct failed\n");
        exit(1);
    }
    kaspSetPolicyDefaults(policy, NULL);

    while (1) {

        /* Read the config file */
        status = ReadConfig(config);
        if (status != 0) {
            log_msg(config, LOG_ERR, "Error reading config");
            exit(1);
        }

        log_msg(config, LOG_INFO, "Connecting to Database...");
        kaspConnect(config, &dbhandle);

        /* In case zonelist is huge use the XmlTextReader API so that we don't hold the whole file in memory */
        reader = xmlNewTextReaderFilename(zonelist_filename);
        if (reader != NULL) {
            ret = xmlTextReaderRead(reader);
            while (ret == 1) {
                /* Found <Zone> */
                if (strncmp((char*) xmlTextReaderLocalName(reader), "Zone", 4) == 0 
                        && strncmp((char*) xmlTextReaderLocalName(reader), "ZoneList", 8) != 0
                        && xmlTextReaderNodeType(reader) == 1) {
                    /* Get the zone name (TODO what if this is null?) */
                    zone_name = NULL;
                    StrAppend(&zone_name, (char*) xmlTextReaderGetAttribute(reader, name_expr));

                    log_msg(config, LOG_INFO, "Zone %s found.", zone_name);

                    /* Expand this node and get the rest of the info with XPath */
                    xmlTextReaderExpand(reader);
                    doc = xmlTextReaderCurrentDoc(reader);
                    if (doc == NULL) {
                        log_msg(config, LOG_ERR, "Error: can not read zone \"%s\"; skipping\n", zone_name);
                        /* Don't return? try to parse the rest of the zones? */
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }

                    /* TODO should we validate here? Or should we validate the whole document? */

                    xpathCtx = xmlXPathNewContext(doc);
                    if(xpathCtx == NULL) {
                        log_msg(config, LOG_ERR,"Error: can not create XPath context for \"%s\"; skipping zone\n", zone_name);
                        /* Don't return? try to parse the rest of the zones? */
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }

                    /* Extract the Policy name and signer configuration filename for this zone */
                    /* Evaluate xpath expression for policy */
                    xpathObj = xmlXPathEvalExpression(policy_expr, xpathCtx);
                    if(xpathObj == NULL) {
                        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s; skipping zone\n", policy_expr);
                        /* Don't return? try to parse the rest of the zones? */
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }
                    current_policy = NULL;
                    StrAppend(&current_policy, (char*) xmlXPathCastToString(xpathObj));
                    log_msg(config, LOG_INFO, "Policy set to %s.", current_policy);
                    if (current_policy != policy->name) {
                        /* Read new Policy */ 
                        kaspSetPolicyDefaults(policy, current_policy);

                        status2 = KsmPolicyRead(policy);
                        if (status2 != 0) {
                            /* Don't return? try to parse the rest of the zones? */
                            log_msg(config, LOG_ERR, "Error reading policy");
                            ret = xmlTextReaderRead(reader);
                            continue;
                        }
                        log_msg(config, LOG_INFO, "Policy %s found.", policy->name);

                        /* Update the salt if it is not up to date */
                        status2 = KsmPolicyUpdateSalt(policy);
                        if (status2 != 0) {
                            /* Don't return? try to parse the rest of the zones? */
                            log_msg(config, LOG_ERR, "Error updating salt");
                            ret = xmlTextReaderRead(reader);
                            continue;
                        }
                    } else {
                        /* Policy is same as previous zone, do not re-read */
                    }

                    /* Evaluate xpath expression for signer configuration filename */
                    xpathObj = xmlXPathEvalExpression(filename_expr, xpathCtx);
                    if(xpathObj == NULL) {
                        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s; skipping zone\n", policy_expr);
                        /* Don't return? try to parse the rest of the zones? */
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }
                    current_filename = NULL;
                    StrAppend(&current_filename, (char*) xmlXPathCastToString(xpathObj));
                    log_msg(config, LOG_INFO, "Config will be output to %s.", current_filename);
                    /* TODO should we check that we have not written to this file in this run?*/

                    /* turn this zone and policy into a file */
                    status2 = commGenSignConf(zone_name, current_filename, policy);
                    if (status2 != 0) {
                        log_msg(config, LOG_ERR, "Error writing signconf");
                        /* Don't return? try to parse the rest of the zones? */
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }
                }
                /* Read the next line */
                ret = xmlTextReaderRead(reader);
            }
            xmlFreeTextReader(reader);
            if (ret != 0) {
                log_msg(config, LOG_ERR, "%s : failed to parse\n", zonelist_filename);
            }
        } else {
            log_msg(config, LOG_ERR, "Unable to open %s\n", zonelist_filename);
        }
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);

        /* StrFree(zone_name); ??*/

        /* Release our hold on the database */
        log_msg(config, LOG_INFO, "Disconnecting from Database...");
        kaspDisconnect(&dbhandle);

        /* If we have been sent a SIGTERM then it is time to exit */ 
        if (config->term == 1 ){
            log_msg(config, LOG_INFO, "Received SIGTERM, exiting...");
            exit(0);
        }

        /* sleep for the configured interval */
        tv.tv_sec = config->interval;
        tv.tv_usec = 0;
        log_msg(config, LOG_INFO, "Sleeping for %i seconds.",config->interval);
        select(0, NULL, NULL, NULL, &tv);

        /* If we have been sent a SIGTERM then it is time to exit */ 
        if (config->term == 1 ){
            log_msg(config, LOG_INFO, "Received SIGTERM, exiting...");
            exit(0);
        }
    }

    free(policy->name);
    free(policy->enforcer);
    free(policy->denial);
    free(policy->zsk);
    free(policy->ksk);
    free(policy->signature);
    free(policy->signer);
    free(policy);

}

/*
 *  generate the configuration file for the signer

 *  returns 0 on success and -1 if something went wrong
 */
int commGenSignConf(char* zone_name, char* current_filename, KSM_POLICY *policy)
{
    int status = 0;
    FILE *file;
    char *temp_filename;    /* In case this fails we write to a temp file and only overwrite
                               the current file when we are finished */
    char *old_filename;     /* Keep a copy of the previous version, just in case! (Also gets
                               round potentially different behaviour of rename over existing
                               file.) */
    char*   datetime = DtParseDateTimeString("now");
    int zone_id = -1;

    if (zone_name == NULL || current_filename == NULL || policy == NULL)
    {
        /* error */
        log_msg(NULL, LOG_ERR, "NULL policy or zone provided\n");
        MemFree(datetime);
        return -1;
    }

    /* Get zone ID from name (or return if it doesn't exist) */
    status = KsmZoneIdFromName(zone_name, &zone_id);
    if (status != 0 || zone_id == -1)
    {
        /* error */
        log_msg(NULL, LOG_ERR, "Error looking up zone \"%s\" in database (maybe it doesn't exist?)\n", zone_name);
        MemFree(datetime);
        return -1;
    }

    old_filename = NULL;
    StrAppend(&old_filename, current_filename);
    StrAppend(&old_filename, ".OLD");

    temp_filename = NULL;
    StrAppend(&temp_filename, current_filename);
    StrAppend(&temp_filename, ".tmp");

    file = fopen(temp_filename, "w");

    if (file == NULL)
    {
        /* error */
        log_msg(NULL, LOG_ERR, "Could not open: %s\n", temp_filename);
        MemFree(datetime);
        return -1;
    }

    fprintf(file, "<SignerConfiguration>\n");
    fprintf(file, "\t<Zone name=\"%s\">\n", zone_name);

    fprintf(file, "\t\t<Signatures>\n");
    fprintf(file, "\t\t\t<Resign>PT%dS</Resign>\n", policy->signature->resign);
    fprintf(file, "\t\t\t<Refresh>PT%dS</Refresh>\n", policy->signer->refresh);
    fprintf(file, "\t\t\t<Validity>\n");
    fprintf(file, "\t\t\t\t<Default>PT%dS</Default>\n", policy->signature->valdefault);
    fprintf(file, "\t\t\t\t<Denial>PT%dS</Denial>\n", policy->signature->valdenial);
    fprintf(file, "\t\t\t</Validity>\n");
    fprintf(file, "\t\t\t<Jitter>PT%dS</Jitter>\n", policy->signer->jitter);
    fprintf(file, "\t\t\t<InceptionOffset>PT%dS</InceptionOffset>\n", policy->signature->clockskew);
    fprintf(file, "\t\t</Signatures>\n");

    fprintf(file, "\n");

    fprintf(file, "\t\t<Denial>\n");
    if (policy->denial->version == 3)
    {
        fprintf(file, "\t\t\t<NSEC3>\n");
        if (policy->denial->optout == 1)
        {
            fprintf(file, "\t\t\t\t<OptOut />\n");
        }
        fprintf(file, "\t\t\t\t<Hash>\n");
        fprintf(file, "\t\t\t\t\t<Algorithm>%d</Algorithm>\n", policy->denial->algorithm);
        fprintf(file, "\t\t\t\t\t<Iterations>%d</Iterations>\n", policy->denial->iteration);
        fprintf(file, "\t\t\t\t\t<Salt>%s</Salt>\n", policy->denial->salt);
        fprintf(file, "\t\t\t\t</Hash>\n");
        fprintf(file, "\t\t\t</NSEC3>\n");
    } else {
        fprintf(file, "\t\t\t<NSEC />\n");
    }

    fprintf(file, "\t\t</Denial>\n");

    fprintf(file, "\n");

    /* start of keys section */ 
    fprintf(file, "\t\t<Keys>\n");
    fprintf(file, "\t\t\t<TTL>PT%dS</TTL>\n", policy->ksk->ttl);

    KsmRequestKeys(0, 0, datetime, commKeyConfig, file, policy->id, zone_id);

    fprintf(file, "\t\t</Keys>\n");

    fprintf(file, "\n");

    fprintf(file, "\t\t<SOA>\n");
    fprintf(file, "\t\t\t<TTL>PT%dS</TTL>\n", policy->signer->soattl);
    fprintf(file, "\t\t\t<Minimum>PT%dS</Minimum>\n", policy->signer->soamin);
    fprintf(file, "\t\t\t<Serial>%s</Serial>\n", KsmKeywordSerialValueToName( policy->signer->serial) );
    fprintf(file, "\t\t</SOA>\n");

    fprintf(file, "\t</Zone>\n");
    fprintf(file, "</SignerConfiguration>\n");

    status = fclose(file);

    if (status == EOF) /* close failed... do something? */
    {
        MemFree(datetime);
        return -1;
    }

    /* we now have a complete xml file. First move the old one out of the way */
    status = rename(current_filename, old_filename);
    if (status != 0 && status != -1)
    {
        /* cope with initial condition of files not existing */
        MemFree(datetime);
        return -1;
    }

    /* Then copy our temp into place */
    if (rename(temp_filename, current_filename) != 0)
    {
        MemFree(datetime);
        return -1;
    }

    MemFree(datetime);
    return 0;
}

/*
 * CallBack to print key info in signerConfiguration
 */

int commKeyConfig(void* context, KSM_KEYDATA* key_data)
{
    FILE *file = (FILE *)context;

    fprintf(file, "\t\t\t<Key>\n");
    fprintf(file, "\t\t\t\t<Flags>%d</Flags>\n", key_data->keytype);
    fprintf(file, "\t\t\t\t<Algorithm>%d</Algorithm>\n", key_data->algorithm);
    fprintf(file, "\t\t\t\t<Locator>%s</Locator>\n", key_data->location);
    if (key_data->keytype == KSM_TYPE_KSK)
    {
        fprintf(file, "\t\t\t\t<KSK />\n");
    }
    else
    {
        fprintf(file, "\t\t\t\t<ZSK />\n");
    }
    fprintf(file, "\t\t\t\t<%s />\n", KsmKeywordStateValueToName(key_data->state));
    fprintf(file, "\t\t\t</Key>\n");
    fprintf(file, "\n");

    return 0;
}

