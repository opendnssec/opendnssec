/*
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
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
 *
 */

#include "shared/log.h"
#include "shared/str.h"
#include "utils/kc_helper.h"
#include "db/policy.h"

#include "keystate/zonelist_update.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

static int zonelist_update(int add, const char* filename, const zone_t* zone) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr node;
    xmlNodePtr node2;
    xmlNodePtr node3;
    xmlNodePtr node4;
    xmlChar* name;
    int found = 0;
    char path[PATH_MAX];
    policy_t* policy;

    if (!filename) {
        return ZONELIST_UPDATE_ERR_ARGS;
    }
    if (!zone) {
        return ZONELIST_UPDATE_ERR_ARGS;
    }

    /*
     * Validate, parse and walk the XML.
     */
    if (check_zonelist(filename, 0, NULL, 0)) {
        return ZONELIST_UPDATE_ERR_XML;
    }

    if (!(doc = xmlParseFile(filename))) {
        return ZONELIST_UPDATE_ERR_XML;
    }

    if (!(root = xmlDocGetRootElement(doc))) {
        xmlFreeDoc(doc);
        return ZONELIST_UPDATE_ERR_XML;
    }

    for (; root; root = root->next) {
        if (root->type != XML_ELEMENT_NODE) {
            continue;
        }

        if (!strcmp((char*)root->name, "ZoneList")) {
            for (node = root->children; node; node = node->next) {
                if (node->type != XML_ELEMENT_NODE) {
                    continue;
                }
                if (strcmp((char*)node->name, "Zone")) {
                    continue;
                }

                if (!(name = xmlGetProp(node, (const xmlChar*)"name"))) {
                    xmlFreeDoc(doc);
                    return ZONELIST_UPDATE_ERR_XML;
                }

                if (!strcmp(zone_name(zone), (char*)name)) {
                    if (!add) {
                        xmlUnlinkNode(node);
                        xmlFreeNode(node);
                    }
                    found = 1;
                    xmlFree(name);
                    break;
                }

                xmlFree(name);
            }

            if (add && found) {
                xmlFreeDoc(doc);
                return ZONELIST_UPDATE_ERR_XML;
            }
            if (!add && !found) {
                xmlFreeDoc(doc);
                return ZONELIST_UPDATE_OK;
            }
        }

        if (add) {
            if (!(policy = zone_get_policy(zone))
                || !(node = xmlNewChild(root, NULL, (xmlChar*)"Zone", NULL))
                || !xmlNewProp(node, (xmlChar*)"name", (xmlChar*)zone_name(zone))
                || !xmlNewChild(node, NULL, (xmlChar*)"Policy", (xmlChar*)policy_name(policy))
                || !xmlNewChild(node, NULL, (xmlChar*)"SignerConfiguration", (xmlChar*)zone_signconf_path(zone))
                || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Adapters", NULL))
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Input", NULL))
                || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Adapter", (xmlChar*)zone_input_adapter_uri(zone)))
                || !xmlNewProp(node4, (xmlChar*)"type", (xmlChar*)zone_input_adapter_type(zone))
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Output", NULL))
                || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Adapter", (xmlChar*)zone_output_adapter_uri(zone)))
                || !xmlNewProp(node4, (xmlChar*)"type", (xmlChar*)zone_output_adapter_type(zone)))
            {
                policy_free(policy);
                xmlFreeDoc(doc);
                return ZONELIST_UPDATE_ERR_XML;
            }
            policy_free(policy);
        }

        break;
    }

    if (snprintf(path, sizeof(path), "%s.update", filename) >= (int)sizeof(path)) {
        xmlFreeDoc(doc);
        return ZONELIST_UPDATE_ERR_MEMORY;
    }
    unlink(path);
    if (xmlSaveFormatFileEnc(path, doc, "UTF-8", 1) == -1) {
        xmlFreeDoc(doc);
        return ZONELIST_UPDATE_ERR_FILE;
    }
    xmlFreeDoc(doc);

    if (check_zonelist(path, 0, NULL, 0)) {
        unlink(path);
        return ZONELIST_UPDATE_ERR_XML;
    }

    if (rename(path, filename)) {
        unlink(path);
        return ZONELIST_UPDATE_ERR_FILE;
    }

    ods_log_info("[zonelist_export] zonelist %s updated successfully", filename);
    return ZONELIST_UPDATE_OK;
}

int zonelist_update_add(const char* filename, const zone_t* zone) {
    return zonelist_update(1, filename, zone);
}

int zonelist_update_delete(const char* filename, const zone_t* zone) {
    return zonelist_update(0, filename, zone);
}
