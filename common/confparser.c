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

#include "confparser.h"
#include "log.h"
#include "status.h"
#include "duration.h"
#include "compat.h"

#include <libxml/xpath.h>
#include <libxml/relaxng.h>
#include <libxml/xmlreader.h>
#include <string.h>
#include <stdlib.h>
#include <sys/un.h>

static const char* parser_str = "parser";

/**
 * Parse elements from the configuration file.
 *
 */
ods_status
parse_file_check(const char* cfgfile, const char* rngfile)
{
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
        return ODS_STATUS_XML_ERR;
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

/* TODO: look how the enforcer reads this now */

/**
 * Parse elements from the configuration file.
 *
 */
const char*
parse_conf_string(const char* cfgfile, const char* expr, int required)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlChar *xexpr = NULL;
    const char* string = NULL;

    ods_log_assert(expr);
    ods_log_assert(cfgfile);

    /* Load XML document */
    doc = xmlParseFile(cfgfile);
    if (doc == NULL) {
        return NULL;
    }
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if (xpathCtx == NULL) {
        ods_log_error("[%s] unable to create new XPath context for cfgile "
            "%s expr %s", parser_str, cfgfile, (char*) expr);
        xmlFreeDoc(doc);
        return NULL;
    }
    /* Get string */
    xexpr = (unsigned char*) expr;
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if (xpathObj == NULL || xpathObj->nodesetval == NULL ||
        xpathObj->nodesetval->nodeNr <= 0) {
        if (required) {
            ods_log_error("[%s] unable to evaluate required element %s in "
                "cfgfile %s", parser_str, (char*) xexpr, cfgfile);
        }
        xmlXPathFreeContext(xpathCtx);
        if (xpathObj) {
            xmlXPathFreeObject(xpathObj);
        }
        xmlFreeDoc(doc);
        return NULL;
    }
    if (xpathObj->nodesetval != NULL &&
        xpathObj->nodesetval->nodeNr > 0) {
        string = (const char*) xmlXPathCastToString(xpathObj);
        xmlXPathFreeContext(xpathCtx);
        xmlXPathFreeObject(xpathObj);
        xmlFreeDoc(doc);
        return string;
    }
    xmlXPathFreeContext(xpathCtx);
    xmlXPathFreeObject(xpathObj);
    xmlFreeDoc(doc);
    return NULL;
}

/**
 * Parse the repositories.
 *
 */

struct engineconfig_repository*
parse_conf_repositories(const char* cfgfile)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode* curNode = NULL;
    xmlChar* xexpr = NULL;

    int i;
    struct engineconfig_repository *head = NULL, *cur = NULL, *prev = NULL;

    doc = xmlParseFile(cfgfile);
    if (doc == NULL) {
        ods_log_error("[%s] could not parse <RepositoryList>: "
            "xmlParseFile() failed", parser_str);
        return NULL;
    }
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse <RepositoryList>: "
            "xmlXPathNewContext() failed", parser_str);
        return NULL;
    }
    xexpr = (xmlChar*) "//Configuration/RepositoryList/Repository";
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse <RepositoryList>: "
            "xmlXPathEvalExpression failed", parser_str);
        return NULL;
    }

    if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
            cur = (struct engineconfig_repository*) malloc(sizeof(struct engineconfig_repository));
            cur->name = NULL;
            cur->module = NULL;
            cur->pin = NULL;
            cur->require_backup = 0;
            cur->use_pubkey = 1;
            cur->next = NULL;

            if (prev)
                prev->next = cur;
            else
                head = cur;

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            cur->name = (char *) xmlGetProp(xpathObj->nodesetval->nodeTab[i],
                                             (const xmlChar *)"name");
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"RequireBackup"))
                    cur->require_backup = 1;
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Module"))
                    cur->module = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"TokenLabel"))
                    cur->tokenlabel = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"PIN"))
                    cur->pin = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"SkipPublicKey"))
                    cur->use_pubkey = 0;

                curNode = curNode->next;
            }
            prev = cur;
        }
    }

    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    if (doc) {
        xmlFreeDoc(doc);
    }
    return head;
}


/**
 * Parse elements from the configuration file.
 *
 */
 
const char*
parse_conf_policy_filename(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(cfgfile,
		                        "//Configuration/Common/PolicyFile",
		                        1);
    
    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}

const char*
parse_conf_zonelist_filename_enforcer(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Common/ZoneListFile",
                                        1);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}

const char*
parse_conf_zonelist_filename_signer(const char* cfgfile)
{
    int lwd = 0;
    int lzl = 0;
    int found = 0;
    char* dup = NULL;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Enforcer/WorkingDirectory",
                                        0);

    if (str) {
        found = 1;
    } else {
        str = OPENDNSSEC_ENFORCER_WORKINGDIR;
    }
    lwd = strlen(str);
    lzl = strlen(OPENDNSSEC_ENFORCER_ZONELIST);
    if (lwd>0 && strncmp(str + (lwd-1), "/", 1) != 0) {
        CHECKALLOC(dup = malloc(sizeof(char)*(lwd+lzl+2)));
        memcpy(dup, str, sizeof(char)*(lwd+1));
        strlcat(dup, "/", sizeof(char)*(lwd+2));
        strlcat(dup, OPENDNSSEC_ENFORCER_ZONELIST, sizeof(char)*(lwd+lzl+2));
        lwd += (lzl+1);
    } else {
        CHECKALLOC(dup = malloc(sizeof(char)*(lwd+lzl+1)));
        memcpy(dup, str, sizeof(char)*(lwd+1));
        strlcat(dup, OPENDNSSEC_ENFORCER_ZONELIST, sizeof(char)*(lwd+lzl+1));
        lwd += (lzl+1);
    }
    if (found) {
        free((void*)str);
    }
    ods_log_assert(dup);
    return (const char*) dup;
}



const char*
parse_conf_zonefetch_filename(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Common/ZoneFetchFile",
                                        0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}


const char*
parse_conf_log_filename(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Common/Logging/Syslog/Facility",
                                        0);
    if (!str) {
        str = parse_conf_string(cfgfile,
                                "//Configuration/Common/Logging/File/Filename",
                                0);
    }
    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup; /* NULL, Facility or Filename */
}


const char*
parse_conf_pid_filename(const char* cfgfile, int is_enforcer)
{
    const char* dup = NULL;
    const char* str;

    if (is_enforcer)
        str = parse_conf_string(cfgfile,
                                "//Configuration/Enforcer/PidFile",
                                0);
    else
        str = parse_conf_string(cfgfile,
                                "//Configuration/Signer/PidFile",
                                0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    } else {
        dup = is_enforcer ? strdup(OPENDNSSEC_ENFORCER_PIDFILE) : strdup(ODS_SE_PIDFILE);
    }
    return dup;
}


const char*
parse_conf_delegation_signer_submit_command(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Enforcer/DelegationSignerSubmitCommand",
                                        0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}

const char*
parse_conf_delegation_signer_retract_command(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Enforcer/DelegationSignerRetractCommand",
                                        0);
    
    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}

const char*
parse_conf_clisock_filename(const char* cfgfile, int is_enforcer)
{
    char* dup = NULL;
    const char* str;
    if (is_enforcer)
        str = parse_conf_string(cfgfile,
                                "//Configuration/Enforcer/SocketFile",
                                0);
    else
        str = parse_conf_string(cfgfile,
                                "//Configuration/Signer/SocketFile",
                                0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    } else {
        dup = is_enforcer ? strdup(OPENDNSSEC_ENFORCER_SOCKETFILE) : strdup(ODS_SE_SOCKFILE);
    }
    if (strlen(dup) >= sizeof(((struct sockaddr_un*)0)->sun_path)) {
        dup[sizeof(((struct sockaddr_un*)0)->sun_path)-1] = '\0'; /* don't worry about just a few bytes 'lost' */
        ods_log_warning("[%s] SocketFile path too long, truncated to %s", parser_str, dup);
    }
    return dup;
}

const char*
parse_conf_working_dir(const char* cfgfile, int is_enforcer)
{
    const char* dup = NULL;
    const char* str;
    if (is_enforcer)
        str = parse_conf_string(cfgfile,
                             "//Configuration/Enforcer/WorkingDirectory",
                             0);
    else 
        str = parse_conf_string(cfgfile,
                                "//Configuration/Signer/WorkingDirectory",
                                0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    } else {
        dup = is_enforcer ? strdup(OPENDNSSEC_ENFORCER_WORKINGDIR) : strdup(ODS_SE_WORKDIR);
    }
    return dup;
}


const char*
parse_conf_username(const char* cfgfile, int is_enforcer)
{
    const char* dup = NULL;
    const char* str;
    if (is_enforcer)
    str = parse_conf_string(cfgfile,
                            "//Configuration/Enforcer/Privileges/User",
                            0);
    else
        str = parse_conf_string(cfgfile,
                                "//Configuration/Signer/Privileges/User",
                                0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}


const char*
parse_conf_group(const char* cfgfile, int is_enforcer)
{
    const char* dup = NULL;
    const char* str;

    if (is_enforcer)
        str = parse_conf_string(cfgfile,
                                "//Configuration/Enforcer/Privileges/Group",
                                0);
     else
         str = parse_conf_string(cfgfile,
                                 "//Configuration/Signer/Privileges/Group",
                                 0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}


const char*
parse_conf_chroot(const char* cfgfile, int is_enforcer)
{
    const char* dup = NULL;
    const char* str;

    if (is_enforcer)
        str = parse_conf_string(cfgfile,
                                "//Configuration/Enforcer/Privileges/Directory",
                                0);
    else
        str = parse_conf_string(cfgfile,
                                "//Configuration/Signer/Privileges/Directory",
                                0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}

const char*
parse_conf_datastore(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Enforcer/Datastore/MySQL/Database",
                                        0);
    if (!str) {
        str = parse_conf_string(cfgfile,
                                "//Configuration/Enforcer/Datastore/SQLite",
                                0);
    }
    if (str) {
        dup = strdup(str);
        free((void*)str);
    } else {
            /* use "KASP" as default for datastore */
        dup = strdup("KASP");
    }
    return dup;	
}

const char*
parse_conf_db_host(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Enforcer/Datastore/MySQL/Host",
                                        0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}

const char*
parse_conf_db_username(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Enforcer/Datastore/MySQL/Username",
                                        0);
    
    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}

const char*
parse_conf_db_password(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Enforcer/Datastore/MySQL/Password",
                                        0);
    
    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}

/**
 * Parse elements from the configuration file.
 *
 */
int
parse_conf_use_syslog(const char* cfgfile)
{
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Common/Logging/Syslog/Facility",
                                        0);
    if (str) {
        free((void*)str);
        return 1;
    }
    return 0;
}

int
parse_conf_verbosity(const char* cfgfile)
{
    int verbosity = ODS_EN_VERBOSITY;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Common/Logging/Verbosity",
                                        0);
    if (str) {
        if (strlen(str) > 0) {
        	verbosity = atoi(str);
        }
        free((void*)str);
    }
    return verbosity;
}


int
parse_conf_worker_threads(const char* cfgfile, int is_enforcer)
{
    int numwt = ODS_SE_WORKERTHREADS;
    const char* str;

    if (is_enforcer)
        str = parse_conf_string(cfgfile,
                                "//Configuration/Enforcer/WorkerThreads",
                                0);
    else
        str = parse_conf_string(cfgfile,
                                "//Configuration/Signer/WorkerThreads",
                                0);
    if (str) {
        if (strlen(str) > 0) {
            numwt = atoi(str);
        }
        free((void*)str);
    }
    return numwt;
}

int
parse_conf_manual_keygen(const char* cfgfile)
{
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Enforcer/ManualKeyGeneration",
                                        0);
    if (str) {
        free((void*)str);
        return 1;
    }
    return 0;
}

int
parse_conf_db_port(const char* cfgfile)
{
    int port = 0; /* returning 0 (zero) means use the default port */
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Enforcer/Datastore/MySQL/Host/@Port",
                                        0);
    if (str) {
        if (strlen(str) > 0) {
            port = atoi(str);
        }
        free((void*)str);
    }
    return port;
}

engineconfig_database_type_t 
parse_conf_db_type(const char *cfgfile) {
    const char* str = NULL;

    if ((str = parse_conf_string(cfgfile,
                                 "//Configuration/Enforcer/Datastore/MySQL/Host",
                                 0)))
    {
        free((void*)str);
        return ENFORCER_DATABASE_TYPE_MYSQL;
    }

    if ((str = parse_conf_string(cfgfile,
                                 "//Configuration/Enforcer/Datastore/SQLite",
                                 0)))
    {
        free((void*)str);
        return ENFORCER_DATABASE_TYPE_SQLITE;
    }

    return ENFORCER_DATABASE_TYPE_NONE;
}

time_t
parse_conf_automatic_keygen_period(const char* cfgfile)
{
    time_t period = 365 * 24 * 3600; /* default 1 normal year in seconds */
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Enforcer/AutomaticKeyGenerationPeriod",
                                        0);
    if (str) {
        if (strlen(str) > 0) {
            duration_type* duration = duration_create_from_string(str);
            if (duration) {
                time_t duration_period = duration2time(duration);
                period = duration_period;
                duration_cleanup(duration);
            }
        }
        free((void*)str);
    }
    return period;
}

/**
 * Parse the listener interfaces.
 *
 */

struct engineconfig_listener*
parse_conf_listener(const char* cfgfile)
{
    struct engineconfig_listener *listener = NULL, *head = NULL, *cur = NULL, *prev = NULL;
    int i = 0;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode* curNode = NULL;
    xmlChar* xexpr = NULL;

    ods_log_assert(cfgfile);

    /* Load XML document */
    doc = xmlParseFile(cfgfile);
    if (doc == NULL) {
        ods_log_error("[%s] could not parse <Listener>: "
            "xmlParseFile() failed", parser_str);
        return NULL;
    }
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse <Listener>: "
            "xmlXPathNewContext() failed", parser_str);
        return NULL;
    }
    /* Evaluate xpath expression */
    xexpr = (xmlChar*) "//Configuration/Signer/Listener/Interface";
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse <Listener>: "
            "xmlXPathEvalExpression failed", parser_str);
        return NULL;
    }
    /* Parse interfaces */

    /* If port is not set in Listener in the conf file, default value is used.
     * default port: 15354
     */
    if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
            cur = (struct engineconfig_listener*) malloc(sizeof(struct engineconfig_listener));
            if (prev)
                prev->next = cur;
            else
                head = cur;

            cur->address = NULL;
            cur->port = strdup("15354");
            cur->next = NULL;

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Address")) {
                    cur->address = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name, (const xmlChar *)"Port")) {
                    free((char *)cur->port);
                    cur->port = (char *) xmlNodeGetContent(curNode);
                }
                curNode = curNode->next;
            }
            prev = cur;
        }
    }
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    if (doc) {
        xmlFreeDoc(doc);
    }
    return head;
}

const char*
parse_conf_notify_command(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Signer/NotifyCommand",
                                        0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}

int
parse_conf_signer_threads(const char* cfgfile)
{
    int numwt = ODS_SE_WORKERTHREADS;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Signer/SignerThreads",
                                        0);
    if (str) {
        if (strlen(str) > 0) {
            numwt = atoi(str);
        }
        free((void*)str);
        return numwt;
    }
    /* no SignerThreads value configured, look at WorkerThreads */
    return parse_conf_worker_threads(cfgfile, 1);
}

time_t
parse_conf_rollover_notification(const char* cfgfile)
{
    time_t period = 0;
    const char* str = parse_conf_string(cfgfile,
                                        "//Configuration/Enforcer/RolloverNotification",
                                        0);
    if (str) {
        if (strlen(str) > 0) {
            duration_type* duration = duration_create_from_string(str);
            if (duration) {
                period = duration2time(duration);
                duration_cleanup(duration);
            }
        }
        free((void*)str);
    }
    return period;
}
