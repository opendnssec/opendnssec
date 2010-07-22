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
 * Parsing zonelist files.
 */

#include "adapter/adapter.h"
#include "parser/zonelistparser.h"
#include "signer/zonelist.h"
#include "signer/zone.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <libxml/xpath.h> /* xmlXPath*() */
#include <libxml/xmlreader.h> /* xmlNewTextReaderFilename(), xmlTextReader*(), xmlNodeGetContent(), 
                                 xmlFreeTextReader(), xmlFreeDoc(), xmlStrEqual() */
#include <string.h> /* strlen() */


/**
 * Get the next zone from the zonelist file.
 *
 */
static const char*
parse_zonelist_element(xmlXPathContextPtr xpathCtx, xmlChar* expr)
{
    xmlXPathObjectPtr xpathObj = NULL;
    const char* str = NULL;

    se_log_assert(xpathCtx);
    se_log_assert(expr);

    xpathObj = xmlXPathEvalExpression(expr, xpathCtx);
    if (xpathObj == NULL) {
        se_log_error("unable to evaluate xpath expression %s", expr);
        return NULL;
    }
    str = (const char*) xmlXPathCastToString(xpathObj);
    xmlXPathFreeObject(xpathObj);
    return str;
}


/**
 * Parse the adapters.
 *
 */
static adapter_type*
parse_zonelist_adapters_expr(xmlXPathContextPtr xpathCtx, xmlChar* expr,
    int inbound)
{
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode* curNode = NULL;
    adapter_type* adapter = NULL;
    char* file = NULL;
    int i = 0;

    se_log_assert(xpathCtx);
    se_log_assert(expr);

    xpathObj = xmlXPathEvalExpression(expr, xpathCtx);
    if (xpathObj == NULL) {
        se_log_error("unable to evaluate xpath expression %s", expr);
        return NULL;
    }

    if (xpathObj->nodesetval) {
        for (i=0; i < xpathObj->nodesetval->nodeNr; i++) {
            file = NULL;
            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar*)"File")) {
                    if (file) {
                        se_free((void*)file);
                    }
                    file = (char*) xmlNodeGetContent(curNode);
                }
                curNode = curNode->next;
            }
            if (file) {
                if (!adapter) {
                    adapter = adapter_create(file, ADAPTER_FILE, inbound);
                } else {
                    /* [TODO] fix this ugly hack, possible bug in libxml2 ? */
                }
                se_free((void*)file);
            }
        }
    }
    xmlXPathFreeObject(xpathObj);
    return adapter;
}


/**
 * Get the next zone from the zonelist file.
 *
 */
static void
parse_zonelist_adapters(xmlXPathContextPtr xpathCtx, zone_type* zone)
{
    xmlChar* i_expr = (xmlChar*) "//Zone/Adapters/Input";
    xmlChar* o_expr = (xmlChar*) "//Zone/Adapters/Output";

    se_log_assert(xpathCtx);
    se_log_assert(zone);

    zone->inbound_adapter =
        parse_zonelist_adapters_expr(xpathCtx, i_expr, 1);
    zone->outbound_adapter =
        parse_zonelist_adapters_expr(xpathCtx, o_expr, 0);
    return;
}


/**
 * Parse the zonelist file.
 *
 */
struct zonelist_struct*
parse_zonelist_zones(const char* zlfile)
{
    char* tag_name = NULL;
    char* zone_name = NULL;
    zone_type* new_zone = NULL;
    int ret = 0;
    zonelist_type* zl = (zonelist_type*) zonelist_create();

    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;

    xmlChar* name_expr = (unsigned char*) "name";
    xmlChar* policy_expr = (unsigned char*) "//Zone/Policy";
    xmlChar* signconf_expr = (unsigned char*) "//Zone/SignerConfiguration";

    se_log_assert(zlfile);

    reader = xmlNewTextReaderFilename(zlfile);
    if (!reader) {
        se_log_error("unable to open zone list file %s", zlfile);
        zonelist_cleanup(zl);
        return NULL;
    }

    ret = xmlTextReaderRead(reader);
    while (ret == XML_READER_TYPE_ELEMENT) {
        tag_name = (char*) xmlTextReaderLocalName(reader);
        if (se_strcmp(tag_name, "Zone") == 0 &&
            se_strcmp(tag_name, "ZoneList") != 0 &&
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
            /* Found a zone */
            zone_name = (char*) xmlTextReaderGetAttribute(reader,
                name_expr);
            if (!zone_name || strlen(zone_name) <= 0) {
                se_log_error("unable to extract zone name from zonelist");
                if (zone_name) {
                    se_free((void*) zone_name);
                }
                se_free((void*) tag_name);
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
                se_log_error("unable to read zone %s; skipping",
                   zone_name);
                se_free((void*) zone_name);
                ret = xmlTextReaderRead(reader);
                se_free((void*) tag_name);
                continue;
            }

            /* That worked, now read out the contents */
            new_zone = zone_create(zone_name, LDNS_RR_CLASS_IN);
            new_zone->policy_name = parse_zonelist_element(xpathCtx,
                policy_expr);
            new_zone->signconf_filename = parse_zonelist_element(xpathCtx,
                signconf_expr);
            parse_zonelist_adapters(xpathCtx, new_zone);

            /* and add it to the list */
            if (zonelist_add_zone(zl, new_zone) == NULL) {
                se_log_error("unable to add zone '%s' to zone list",
                    zone_name);
            }
            se_free((void*) zone_name);
            xmlXPathFreeContext(xpathCtx);
        }
        se_free((void*) tag_name);
        ret = xmlTextReaderRead(reader);
    }
    /* no more zones */
    se_log_debug("no more zones");
    xmlFreeTextReader(reader);
    if (ret != 0) {
        se_log_error("error parsing zone list file %s", zlfile);
    }
    if (doc) {
        xmlFreeDoc(doc);
    }
    return zl;
}
