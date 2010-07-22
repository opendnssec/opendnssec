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

#include "parser/confparser.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <libxml/xpath.h> /* xmlXPath*() */
#include <libxml/relaxng.h> /* xmlRelaxNG*() */
#include <libxml/xmlreader.h> /* xmlParseFile(), xmlFreeDoc() */
#include <string.h> /* strlen() */
#include <stdlib.h> /* atoi() */


/**
 * Parse elements from the configuration file.
 *
 */
int
parse_file_check(const char* cfgfile, const char* rngfile)
{
    xmlDocPtr doc = NULL;
    xmlDocPtr rngdoc = NULL;
    xmlRelaxNGParserCtxtPtr rngpctx = NULL;
    xmlRelaxNGValidCtxtPtr rngctx = NULL;
    xmlRelaxNGPtr schema = NULL;
    int status = 0;

    se_log_assert(cfgfile);
    se_log_assert(rngfile);
    se_log_debug("check config file: %s, use rng file: %s", cfgfile,
        rngfile);

    /* Load XML document */
    doc = xmlParseFile(cfgfile);
    if (doc == NULL) {
        se_log_error("unable to read config file '%s'", cfgfile);
        return 1;
    }
    /* Load rng document */
    rngdoc = xmlParseFile(rngfile);
    if (rngdoc == NULL) {
        se_log_error("unable to read conf rng file '%s'", rngfile);
        xmlFreeDoc(doc);
        return 1;
    }
    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    if (rngpctx == NULL) {
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        se_log_error("unable to create XML RelaxNGs parser context");
        return 1;
    }
    /* Parse a schema definition resource and
     * build an internal XML schema structure.
     */
    schema = xmlRelaxNGParse(rngpctx);
    if (schema == NULL) {
        se_log_error("unable to parse a schema definition resource");
        xmlRelaxNGFreeParserCtxt(rngpctx);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return 1;
    }
    /* Create an XML RelaxNGs validation context. */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        se_log_error("unable to create RelaxNGs validation context");
        xmlRelaxNGFree(schema);
        xmlRelaxNGFreeParserCtxt(rngpctx);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return 1;
    }
    /* Validate a document tree in memory. */
    status = xmlRelaxNGValidateDoc(rngctx,doc);
    if (status != 0) {
        se_log_error("configuration file validation failed '%s'",
            cfgfile);
        xmlRelaxNGFreeValidCtxt(rngctx);
        xmlRelaxNGFree(schema);
        xmlRelaxNGFreeParserCtxt(rngpctx);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return 1;
    }

    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFree(schema);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(rngdoc);
    xmlFreeDoc(doc);

    return 0;
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

    se_log_assert(expr);
    se_log_assert(cfgfile);

    /* Load XML document */
    doc = xmlParseFile(cfgfile);
    if (doc == NULL) {
        return NULL;
    }
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if (xpathCtx == NULL) {
        se_log_error("unable to create new XPath context for cfgile %s expr %s",
            cfgfile, expr);
        xmlFreeDoc(doc);
        return NULL;
    }
    /* Get string */
    xexpr = (unsigned char*) expr;
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if (xpathObj == NULL || xpathObj->nodesetval == NULL ||
        xpathObj->nodesetval->nodeNr <= 0) {
        if (required) {
            se_log_error("unable to evaluate required "
                "element %s in cfgfile %s", xexpr, cfgfile);
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


const char*
parse_conf_zonelist_filename(const char* cfgfile)
{
    return parse_conf_string(cfgfile,
        "//Configuration/Common/ZoneListFile",
        1);
}


const char*
parse_conf_zonefetch_filename(const char* cfgfile)
{
    return parse_conf_string(cfgfile,
        "//Configuration/Common/ZoneFetchFile",
        0);
}


const char*
parse_conf_log_filename(const char* cfgfile)
{
    const char* str = parse_conf_string(cfgfile,
        "//Configuration/Common/Logging/Syslog/Facility",
        0);
    if (!str) {
        str = parse_conf_string(cfgfile,
            "//Configuration/Common/Logging/File/Filename",
            0);
    }
    return str; /* NULL, Facility or Filename */
}


const char*
parse_conf_pid_filename(const char* cfgfile)
{
    const char* str = parse_conf_string(cfgfile,
        "//Configuration/Signer/PidFile",
        0);
    if (!str) {
        return se_strdup(ODS_SE_PIDFILE);
    }
    return str;
}


const char*
parse_conf_notify_command(const char* cfgfile)
{
    return parse_conf_string(cfgfile,
        "//Configuration/Signer/NotifyCommand",
        0);
}


const char*
parse_conf_clisock_filename(const char* cfgfile)
{
    const char* str = parse_conf_string(cfgfile,
        "//Configuration/Signer/SocketFile",
        0);
    if (!str) {
        return se_strdup(ODS_SE_SOCKFILE);
    }
    return str;
}


const char* parse_conf_working_dir(const char* cfgfile)
{
    const char* str = parse_conf_string(cfgfile,
        "//Configuration/Signer/WorkingDirectory",
        0);
    if (!str) {
        return se_strdup(ODS_SE_WORKDIR);
    }
    return str;
}


const char*
parse_conf_username(const char* cfgfile)
{
   return parse_conf_string(cfgfile,
        "//Configuration/Signer/Privileges/User",
        0);
}


const char* parse_conf_group(const char* cfgfile)
{
   return parse_conf_string(cfgfile,
        "//Configuration/Signer/Privileges/Group",
        0);
}


const char* parse_conf_chroot(const char* cfgfile)
{
   return parse_conf_string(cfgfile,
        "//Configuration/Signer/Privileges/Directory",
        0);
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
        se_free((void*)str);
        return 1;
    }
    return 0;
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
        se_free((void*)str);
    }
    return numwt;
}


int
parse_conf_signer_threads(const char* cfgfile)
{
    int numwt = ODS_SE_SIGNERTHREADS;
    const char* str = parse_conf_string(cfgfile,
        "//Configuration/Signer/SignerThreads",
        0);
    if (str) {
        if (strlen(str) > 0) {
            numwt = atoi(str);
        }
        se_free((void*)str);
    }
    return numwt;
}
