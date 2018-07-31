/*
 * Copyright (c) 2009-2018 NLNet Labs.
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
 * Parsing DNS Adapter.
 *
 */

#include "parser/addnsparser.h"
#include "log.h"

#include <libxml/xpath.h>
#include <libxml/xmlreader.h>
#include <stdlib.h>
#include <string.h>

static const char* parser_str = "parser";


/**
 * Parse the remote servers.
 *
 */
static acl_type*
parse_addns_remote(const char* filename,
    tsig_type* tsig, char* expr)
{
    acl_type* acl = NULL;
    acl_type* new_acl = NULL;
    int i = 0;
    char* address = NULL;
    char* port = NULL;
    char* key = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode* curNode = NULL;
    xmlChar* xexpr = NULL;

    if (!filename || !expr) {
        return NULL;
    }
    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        ods_log_error("[%s] could not parse %s: xmlParseFile() failed",
            parser_str, expr);
        return NULL;
    }
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse %s: xmlXPathNewContext() failed",
            parser_str, expr);
        return NULL;
    }
    /* Evaluate xpath expression */
    xexpr = (xmlChar*) expr;
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse %s: xmlXPathEvalExpression() "
            "failed", parser_str, expr);
        return NULL;
    }
    /* Parse interfaces */
    if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
            address = NULL;
            port = NULL;
            key = NULL;

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Address")) {
                    address = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name,
                    (const xmlChar *)"Port")) {
                    port = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name,
                    (const xmlChar *)"Key")) {
                    key = (char *) xmlNodeGetContent(curNode);
                }
                curNode = curNode->next;
            }
            if (address) {
                new_acl = acl_create(address, port, key, tsig);
                if (!new_acl) {
                   ods_log_error("[%s] unable to add server %s:%s %s to list "
                       "%s: acl_create() failed", parser_str, address,
                       port?port:"", key?key:"", (char*) expr);
                } else {
                   new_acl->next = acl;
                   acl = new_acl;
                   ods_log_debug("[%s] added server %s:%s %s to list %s",
                       parser_str, address, port?port:"", key?key:"",
                       (char*) expr);
                }
            }
            free((void*)address);
            free((void*)port);
            free((void*)key);
        }
    }
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    if (doc) {
        xmlFreeDoc(doc);
    }
    return acl;
}


/**
 * Parse the ACL interfaces.
 *
 */
static acl_type*
parse_addns_acl(const char* filename,
    tsig_type* tsig, char* expr)
{
    acl_type* acl = NULL;
    acl_type* new_acl = NULL;
    int i = 0;
    char* prefix = NULL;
    char* key = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode* curNode = NULL;
    xmlChar* xexpr = NULL;

    if (!filename || !expr) {
        return NULL;
    }
    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        ods_log_error("[%s] could not parse %s: xmlParseFile() failed",
            parser_str, expr);
        return NULL;
    }
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse %s: xmlXPathNewContext() failed",
            parser_str, expr);
        return NULL;
    }
    /* Evaluate xpath expression */
    xexpr = (xmlChar*) expr;
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse %s: xmlXPathEvalExpression() "
            "failed", parser_str, expr);
        return NULL;
    }
    /* Parse interfaces */
    if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
            prefix = NULL;
            key = NULL;

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Prefix")) {
                    prefix = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name,
                    (const xmlChar *)"Key")) {
                    key = (char *) xmlNodeGetContent(curNode);
                }
                curNode = curNode->next;
            }
            if (prefix || key) {
                new_acl = acl_create(prefix, NULL, key, tsig);
                if (!new_acl) {
                   ods_log_error("[%s] unable to add acl for %s %s to list "
                       "%s: acl_create() failed", parser_str, prefix?prefix:"",
                       key?key:"", (char*) expr);
                } else {
                   new_acl->next = acl;
                   acl = new_acl;
                   ods_log_debug("[%s] added %s %s interface to list %s",
                       parser_str, prefix?prefix:"", key?key:"", (char*) expr);
                }
            }
            free((void*)prefix);
            free((void*)key);
        }
    }
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    if (doc) {
        xmlFreeDoc(doc);
    }
    return acl;
}


/**
 * Parse the TSIG credentials.
 *
 */
static tsig_type*
parse_addns_tsig_static(const char* filename,
    char* expr)
{
    tsig_type* tsig = NULL;
    tsig_type* new_tsig = NULL;
    int i = 0;
    char* name = NULL;
    char* algo = NULL;
    char* secret = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode* curNode = NULL;
    xmlChar* xexpr = NULL;

    if (!filename || !expr) {
        return NULL;
    }
    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        ods_log_error("[%s] could not parse %s: xmlParseFile() failed",
            parser_str, expr);
        return NULL;
    }
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse %s: xmlXPathNewContext() failed",
            parser_str, expr);
        return NULL;
    }
    /* Evaluate xpath expression */
    xexpr = (xmlChar*) expr;
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse %s: xmlXPathEvalExpression() "
            "failed", parser_str, expr);
        return NULL;
    }
    /* Parse interfaces */
    if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
            name = NULL;
            algo = NULL;
            secret = NULL;

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Name")) {
                    name = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name,
                    (const xmlChar *)"Algorithm")) {
                    algo = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name,
                    (const xmlChar *)"Secret")) {
                    secret = (char *) xmlNodeGetContent(curNode);
                }
                curNode = curNode->next;
            }
            if (name && algo && secret) {
                new_tsig = tsig_create(name, algo, secret);
                if (!new_tsig) {
                   ods_log_error("[%s] unable to add tsig %s: "
                       "tsig_create() failed", parser_str, name);
                } else {
                   new_tsig->next = tsig;
                   tsig = new_tsig;
                   ods_log_debug("[%s] added %s tsig to list %s",
                       parser_str, name, (char*) expr);
                }
            }
            free((void*)name);
            free((void*)algo);
            free((void*)secret);
        }
    }
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    if (doc) {
        xmlFreeDoc(doc);
    }
    return tsig;
}


/**
 * Parse <RequestTransfer/>.
 *
 */
acl_type*
parse_addns_request_xfr(const char* filename,
    tsig_type* tsig)
{
    return parse_addns_remote(filename, tsig,
        (char *)"//Adapter/DNS/Inbound/RequestTransfer/Remote");
}


/**
 * Parse <AllowNotify/>.
 *
 */
acl_type*
parse_addns_allow_notify(const char* filename,
    tsig_type* tsig)
{
    return parse_addns_acl(filename, tsig,
        (char *)"//Adapter/DNS/Inbound/AllowNotify/Peer");
}


/**
 * Parse <ProvideTransfer/>.
 *
 */
acl_type*
parse_addns_provide_xfr(const char* filename,
    tsig_type* tsig)
{
    return parse_addns_acl(filename, tsig,
        (char *)"//Adapter/DNS/Outbound/ProvideTransfer/Peer");
}


/**
 * Parse <Notify/>.
 *
 */
acl_type*
parse_addns_do_notify(const char* filename,
    tsig_type* tsig)
{
    return parse_addns_remote(filename, tsig,
        (char *)"//Adapter/DNS/Outbound/Notify/Remote");
}


/**
 * Parse <TSIG/>.
 *
 */
tsig_type*
parse_addns_tsig(const char* filename)
{
    return parse_addns_tsig_static(filename,
        (char *)"//Adapter/DNS/TSIG");
}

