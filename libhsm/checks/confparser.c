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
#include "log.h"
#include "status.h"

#include <libxml/xpath.h>
#include <libxml/relaxng.h>
#include <libxml/xmlreader.h>
#include <string.h>
#include <stdlib.h>
#include "libhsm.h"

static const char* parser_str = "parser";

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
        }
    }

    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    if (doc) {
        xmlFreeDoc(doc);
    }
    return rlist;
}
