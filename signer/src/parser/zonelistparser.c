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
 * Parsing zonelist files.
 *
 */

#include "adapter/adapter.h"
#include "parser/zonelistparser.h"
#include "file.h"
#include "log.h"
#include "status.h"
#include "signer/zonelist.h"
#include "signer/zone.h"

#include <libxml/xpath.h>
#include <libxml/xmlreader.h>
#include <stdlib.h>
#include <string.h>

static const char* parser_str = "parser";


/**
 * Parse expr inside XPath Context.
 *
 */
static const char*
parse_zonelist_element(xmlXPathContextPtr xpathCtx, xmlChar* expr)
{
    xmlXPathObjectPtr xpathObj = NULL;
    const char* str = NULL;

    ods_log_assert(xpathCtx);
    ods_log_assert(expr);

    xpathObj = xmlXPathEvalExpression(expr, xpathCtx);
    if (xpathObj == NULL) {
        ods_log_error("[%s] unable to evaluate xpath expression %s",
            parser_str, expr);
        return NULL;
    }
    str = (const char*) xmlXPathCastToString(xpathObj);
    xmlXPathFreeObject(xpathObj);
    return str;
}


/**
 * Create adapter from configuration.
 *
 */
static adapter_type*
zlp_adapter(xmlNode* curNode, adapter_mode type, unsigned inbound)
{
    const char* file = NULL;
    adapter_type* adapter = NULL;
    file = (const char*) xmlNodeGetContent(curNode);
    if (!file) {
        ods_log_error("[%s] unable to read %s adapter", parser_str,
            inbound?"input":"output");
        return NULL;
    }
    adapter = adapter_create(file, type, inbound);
    free((void*)file);
    return adapter;
}


/**
 * Parse adapter.
 *
 */
static adapter_type*
parse_zonelist_adapter(xmlXPathContextPtr xpathCtx, xmlChar* expr,
    int inbound)
{
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode* curNode = NULL;
    xmlChar* type = NULL;
    adapter_type* adapter = NULL;
    int i = 0;

    if (!xpathCtx || !expr) {
        return NULL;
    }
    xpathObj = xmlXPathEvalExpression(expr, xpathCtx);
    if (xpathObj == NULL) {
        ods_log_error("[%s] unable to parse adapter: xmlPathEvalExpression() "
            "failed (expr %s)", parser_str, expr);
        return NULL;
    }
    if (xpathObj->nodesetval) {
        for (i=0; i < xpathObj->nodesetval->nodeNr; i++) {
            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar*)"File")) {
                    adapter = zlp_adapter(curNode, ADAPTER_FILE, inbound);
                } else if (xmlStrEqual(curNode->name,
                    (const xmlChar*)"Adapter")) {
                    type = xmlGetProp(curNode, (const xmlChar*)"type");
                    if (xmlStrEqual(type, (const xmlChar*)"File")) {
                        adapter = zlp_adapter(curNode, ADAPTER_FILE, inbound);
                    } else if (xmlStrEqual(type, (const xmlChar*)"DNS")) {
                        adapter = zlp_adapter(curNode, ADAPTER_DNS, inbound);
                    } else {
                        ods_log_error("[%s] unable to parse %s adapter: "
                            "unknown type", parser_str, (const char*) type);
                    }
                    free((void*)type);
                    type = NULL;
                }
                if (adapter) {
		    xmlXPathFreeObject(xpathObj);
		    return adapter;
                }
                curNode = curNode->next;
            }
        }
    }
    xmlXPathFreeObject(xpathObj);
    return NULL;
}


/**
 * Parse the adapters.
 *
 */
static void
parse_zonelist_adapters(xmlXPathContextPtr xpathCtx, zone_type* zone)
{
    xmlChar* i_expr = (xmlChar*) "//Zone/Adapters/Input";
    xmlChar* o_expr = (xmlChar*) "//Zone/Adapters/Output";

    if (!xpathCtx || !zone) {
        return;
    }
    zone->adinbound  = parse_zonelist_adapter(xpathCtx, i_expr, 1);
    zone->adoutbound = parse_zonelist_adapter(xpathCtx, o_expr, 0);
}


/**
 * Parse the zonelist file.
 *
 */
ods_status
parse_zonelist_zones(void* zlist, const char* zlfile)
{
    char* tag_name = NULL;
    char* zone_name = NULL;
    zone_type* new_zone = NULL;
    int ret = 0;
    int error = 0;
    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlChar* name_expr = (unsigned char*) "name";
    xmlChar* policy_expr = (unsigned char*) "//Zone/Policy";
    xmlChar* signconf_expr = (unsigned char*) "//Zone/SignerConfiguration";

    if (!zlist || !zlfile) {
        ods_log_error("[%s] unable to parse zonelist: no storage or no filename",
            parser_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    reader = xmlNewTextReaderFilename(zlfile);
    if (!reader) {
        ods_log_error("[%s] unable to parse zonelist: failed to open file %s",
            parser_str, zlfile);
        return ODS_STATUS_XML_ERR;
    }
    ret = xmlTextReaderRead(reader);
    while (ret == XML_READER_TYPE_ELEMENT) {
        tag_name = (char*) xmlTextReaderLocalName(reader);
        if (ods_strcmp(tag_name, "Zone") == 0 &&
            ods_strcmp(tag_name, "ZoneList") != 0 &&
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
            /* Found a zone */
            zone_name = (char*) xmlTextReaderGetAttribute(reader,
                name_expr);
            if (!zone_name || strlen(zone_name) <= 0) {
                ods_log_alert("[%s] unable to extract zone name from "
                    "zonelist %s, skipping...", parser_str, zlfile);
                if (zone_name) {
                    free((void*) zone_name);
                }
                free((void*) tag_name);
                ret = xmlTextReaderRead(reader);
                continue;
            }
            /* Expand this node to get the rest of the info */
            xmlTextReaderExpand(reader);
            doc = xmlTextReaderCurrentDoc(reader);
            if (doc) {
                xpathCtx = xmlXPathNewContext(doc);
            }
            if (doc == NULL || xpathCtx == NULL) {
                ods_log_alert("[%s] unable to read zone %s, skipping...",
                   parser_str, zone_name);
                ret = xmlTextReaderRead(reader);
                free((void*) zone_name);
                free((void*) tag_name);
                continue;
            }
            /* That worked, now read out the contents... */
            new_zone = zone_create(zone_name, LDNS_RR_CLASS_IN);
            if (new_zone) {
                new_zone->policy_name = parse_zonelist_element(xpathCtx,
                    policy_expr);
                new_zone->signconf_filename = parse_zonelist_element(xpathCtx,
                    signconf_expr);
                parse_zonelist_adapters(xpathCtx, new_zone);
                if (!new_zone->policy_name || !new_zone->signconf_filename ||
                    !new_zone->adinbound || !new_zone->adoutbound) {
                    zone_cleanup(new_zone);
                    new_zone = NULL;
                    ods_log_crit("[%s] unable to create zone %s", parser_str,
                        zone_name);
                    error = 1;
                } else if (zonelist_add_zone((zonelist_type*) zlist, new_zone)
                    == NULL) {
                    ods_log_crit("[%s] unable to add zone %s", parser_str,
                        zone_name);
                    zone_cleanup(new_zone);
                    new_zone = NULL;
                    error = 1;
                }
            } else {
                ods_log_crit("[%s] unable to create zone %s", parser_str,
                    zone_name);
                error = 1;
            }
            xmlXPathFreeContext(xpathCtx);
            xpathCtx = NULL;
            free((void*) zone_name);
            if (error) {
                free((void*) tag_name);
                tag_name = NULL;
                ret = 1;
                break;
            }
            ods_log_debug("[%s] zone %s added", parser_str, new_zone->name);
        }
        free((void*) tag_name);
        ret = xmlTextReaderRead(reader);
    }
    /* no more zones */
    ods_log_debug("[%s] no more zones", parser_str);
    xmlFreeTextReader(reader);
    if (doc) {
        xmlFreeDoc(doc);
    }
    if (ret != 0) {
        ods_log_error("[%s] unable to parse zonelist: parse error in %s",
            parser_str, zlfile);
        return ODS_STATUS_PARSE_ERR;
    }
    return ODS_STATUS_OK;
}
