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
 * Parsing configuration files.
 *
 */

#include "config.h"
#include "compat.h"
#include "parser/confparser.h"
#include "parser/zonelistparser.h"
#include "log.h"
#include "status.h"
#include "wire/acl.h"

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
    int status = 0;

    if (!cfgfile || !rngfile) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_debug("[%s] check cfgfile %s with rngfile %s", parser_str,
        cfgfile, rngfile);
    /* Load XML document */
    doc = xmlParseFile(cfgfile);
    if (doc == NULL) {
        ods_log_error("[%s] unable to parse file: failed to load cfgfile %s",
            parser_str, cfgfile);
        return ODS_STATUS_XML_ERR;
    }
    /* Load rng document */
    rngdoc = xmlParseFile(rngfile);
    if (rngdoc == NULL) {
        ods_log_error("[%s] unable to parse file: failed to load rngfile %s",
            parser_str, rngfile);
        xmlFreeDoc(doc);
        return ODS_STATUS_XML_ERR;
    }
    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    if (rngpctx == NULL) {
        ods_log_error("[%s] unable to parse file: "
           "xmlRelaxNGNewDocParserCtxt() failed", parser_str);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return ODS_STATUS_XML_ERR;
    }
    /* Parse a schema definition resource and
     * build an internal XML schema structure.
     */
    schema = xmlRelaxNGParse(rngpctx);
    if (schema == NULL) {
        ods_log_error("[%s] unable to parse file: xmlRelaxNGParse() failed",
            parser_str);
        xmlRelaxNGFreeParserCtxt(rngpctx);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return ODS_STATUS_PARSE_ERR;
    }
    /* Create an XML RelaxNGs validation context. */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        ods_log_error("[%s] unable to parse file: xmlRelaxNGNewValidCtxt() "
            "failed", parser_str);
        xmlRelaxNGFree(schema);
        xmlRelaxNGFreeParserCtxt(rngpctx);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return ODS_STATUS_RNG_ERR;
    }
    /* Validate a document tree in memory. */
    status = xmlRelaxNGValidateDoc(rngctx,doc);
    if (status != 0) {
        ods_log_error("[%s] unable to parse file: xmlRelaxNGValidateDoc() "
            "failed", parser_str);
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
 * Parse the repositories.
 *
 */
hsm_repository_t*
parse_conf_repositories(const char* cfgfile)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode* curNode = NULL;
    xmlChar* xexpr = NULL;

    int i;
    char* name;
    char* module;
    char* tokenlabel;
    char* pin;
    uint8_t use_pubkey;
    uint8_t allowextract;
    int require_backup;
    hsm_repository_t* rlist = NULL;
    hsm_repository_t* repo  = NULL;

    /* Load XML document */
    doc = xmlParseFile(cfgfile);
    if (doc == NULL) {
        ods_log_error("[%s] could not parse <RepositoryList>: "
            "xmlParseFile() failed", parser_str);
        return NULL;
    }
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse <RepositoryList>: "
            "xmlXPathNewContext() failed", parser_str);
        return NULL;
    }
    /* Evaluate xpath expression */
    xexpr = (xmlChar*) "//Configuration/RepositoryList/Repository";
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse <RepositoryList>: "
            "xmlXPathEvalExpression failed", parser_str);
        return NULL;
    }
    /* Parse repositories */
    if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
            repo = NULL;
            name = NULL;
            module = NULL;
            tokenlabel = NULL;
            pin = NULL;
            use_pubkey = 1;
            allowextract = 0;
            require_backup = 0;

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            name = (char *) xmlGetProp(xpathObj->nodesetval->nodeTab[i],
                                             (const xmlChar *)"name");
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"RequireBackup"))
                    require_backup = 1;
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Module"))
                    module = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"TokenLabel"))
                    tokenlabel = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"PIN"))
                    pin = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"SkipPublicKey"))
                    use_pubkey = 0;
                if (xmlStrEqual(curNode->name, (const xmlChar *)"AllowExtraction"))
                    allowextract = 1;

                curNode = curNode->next;
            }
            if (name && module && tokenlabel) {
                repo = hsm_repository_new(name, module, tokenlabel, pin,
                    use_pubkey, allowextract, require_backup);
            }
            if (!repo) {
               ods_log_error("[%s] unable to add %s repository: "
                   "hsm_repository_new() failed", parser_str, name?name:"-");
            } else {
               repo->next = rlist;
               rlist = repo;
               ods_log_debug("[%s] added %s repository to repositorylist",
                   parser_str, name);
            }
            free((void*)name);
            free((void*)module);
            free((void*)tokenlabel);
            free((void*)pin);
        }
    }

    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    if (doc) {
        xmlFreeDoc(doc);
    }
    return rlist;
}


/**
 * Parse the listener interfaces.
 *
 */
listener_type*
parse_conf_listener(const char* cfgfile)
{
    listener_type* listener = NULL;
    interface_type* interface = NULL;
    int i = 0;
    char* address = NULL;
    const char* port = NULL;
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
    listener = listener_create();
    ods_log_assert(listener);

    /* If port is not set in Listener in the conf file, default value is used.
     * default port: 15354
     */
    if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
            address = NULL;
            port = strdup("15354");

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Address")) {
                    address = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name, (const xmlChar *)"Port")) {
                    free((char *)port);
                    port = (char *) xmlNodeGetContent(curNode);
                }
                curNode = curNode->next;
            }
            if (address) {
                interface = listener_push(listener, address,
                    acl_parse_family(address), port);
            } else {
                interface = listener_push(listener, (char *)"", AF_INET, port);
                if (interface) {
                    interface = listener_push(listener, (char *)"", AF_INET6, port);
                }
            }
            if (!interface) {
               ods_log_error("[%s] unable to add %s:%s interface: "
                   "listener_push() failed", parser_str, address?address:"",
                   port);
            } else {
               ods_log_debug("[%s] added %s:%s interface to listener",
                   parser_str, address?address:"", port);
            }
            free((void*)port);
            free((void*)address);
        }
    }
    else {
        interface = listener_push(listener, (char *)"", AF_INET, "15354");
        if (interface) {
            interface = listener_push(listener, (char *)"", AF_INET6, "15354");
        }
    }
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    if (doc) {
        xmlFreeDoc(doc);
    }
    return listener;
}


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
        ods_log_error("[%s] unable to parse file %s: xmlParseFile() failed",
            parser_str, cfgfile);
        return NULL;
    }
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if (xpathCtx == NULL) {
        ods_log_error("[%s] unable to parse file %s: xmlXPathNewContext() "
            "failed", parser_str, cfgfile);
        xmlFreeDoc(doc);
        return NULL;
    }
    /* Get string */
    xexpr = (unsigned char*) expr;
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if (xpathObj == NULL || xpathObj->nodesetval == NULL ||
        xpathObj->nodesetval->nodeNr <= 0) {
        if (required) {
            ods_log_error("[%s] unable to evaluate expression %s in cfgile %s",
                parser_str, (char*) xexpr, cfgfile);
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

/*
 *  TODO all parse routines parse the complete file. Yuk!
 *  TODO make a parse_conf_bool for testing existence of empty elements
 *      instead of abusing parse_conf_string
 * */

const char*
parse_conf_zonelist_filename(const char* cfgfile)
{
    int lwd = 0;
    int lzl = 0;
    int found = 0;
    char* dup = NULL;
    const char* str = parse_conf_string(
        cfgfile,
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
parse_conf_pid_filename(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(
        cfgfile,
        "//Configuration/Signer/PidFile",
        0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    } else {
        dup = strdup(ODS_SE_PIDFILE);
    }
    return dup;
}


const char*
parse_conf_notify_command(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(
        cfgfile,
        "//Configuration/Signer/NotifyCommand",
        0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}


const char*
parse_conf_clisock_filename(const char* cfgfile)
{
    char* dup = NULL;
    const char* str = parse_conf_string(
        cfgfile,
        "//Configuration/Signer/SocketFile",
        0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    } else {
        dup = strdup(ODS_SE_SOCKFILE);
    }
    if (strlen(dup) >= sizeof(((struct sockaddr_un*)0)->sun_path)) {
        dup[sizeof(((struct sockaddr_un*)0)->sun_path)-1] = '\0'; /* don't worry about just a few bytes 'lost' */
        ods_log_warning("[%s] SocketFile path too long, truncated to %s", parser_str, dup);
    }
    return dup;
}


const char*
parse_conf_working_dir(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(
        cfgfile,
        "//Configuration/Signer/WorkingDirectory",
        0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    } else {
        dup = strdup(ODS_SE_WORKDIR);
    }
    ods_log_assert(dup);
    return dup;
}


const char*
parse_conf_username(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(
        cfgfile,
        "//Configuration/Signer/Privileges/User",
        0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}


const char*
parse_conf_group(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(
        cfgfile,
        "//Configuration/Signer/Privileges/Group",
        0);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}


const char*
parse_conf_chroot(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(
        cfgfile,
        "//Configuration/Signer/Privileges/Directory",
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
	int verbosity = ODS_SE_VERBOSITY;
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
parse_conf_worker_threads(const char* cfgfile)
{
    int numwt = ODS_SE_WORKERTHREADS;
    const char* str = parse_conf_string(cfgfile,
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
    return parse_conf_worker_threads(cfgfile);
}
