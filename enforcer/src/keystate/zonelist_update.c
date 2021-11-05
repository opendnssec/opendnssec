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

#include "log.h"
#include "str.h"
#include "utils/kc_helper.h"
#include "db/dbw.h"
#include "clientpipe.h"

#include "keystate/zonelist_update.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

static int zonelist_update(int add, int sockfd, const char* filename,
        const struct dbw_zone *zone, const char *policyname, int comment)
{
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr node;
    xmlNodePtr node2;
    xmlNodePtr node3;
    xmlNodePtr node4;
    xmlChar* name;
    int found = 0;
    char path[PATH_MAX];

    if (!filename || !zone) {
        return ZONELIST_UPDATE_ERR_ARGS;
    }

    if (!access(filename, F_OK)) {
        if (access(filename, R_OK|W_OK)) {
            client_printf_err(sockfd, "Read and/or write access to file denied!\n");
            return ZONELIST_UPDATE_ERR_FILE;
        }

        /*
         * Validate, parse and walk the XML.
         */
        if (check_zonelist(filename, 0, NULL, 0)) {
            client_printf_err(sockfd, "Unable to read XML, validation error!\n");
            return ZONELIST_UPDATE_ERR_XML;
        }

	xmlKeepBlanksDefault(0);
        if (!(doc = xmlParseFile(filename))) {
            client_printf_err(sockfd, "Unable to read XML, parse error!\n");
            return ZONELIST_UPDATE_ERR_XML;
        }

        if (!(root = xmlDocGetRootElement(doc))) {
            client_printf_err(sockfd, "Unable to get root XML element!\n");
            xmlFreeDoc(doc);
            return ZONELIST_UPDATE_ERR_XML;
        }
    }
    else {
        if (!(doc = xmlNewDoc((xmlChar*)"1.0"))
            || !(root = xmlNewNode(NULL, (xmlChar*)"ZoneList")))
        {
            client_printf_err(sockfd, "Unable to create XML elements, memory allocation error!\n");
            if (doc) {
                xmlFreeDoc(doc);
            }
            return ZONELIST_UPDATE_ERR_MEMORY;
        }

        if (comment) {
            node = xmlNewComment((xmlChar*)
                "\n\n"
                "********* Important changes to zonelist.xml in 2.0 ***************\n"
                "\n"
                "In 2.0, the zonelist.xml file is no longer automatically updated when zones\n"
                "are added or deleted  via the command line by using the 'ods-enforcer zone add'\n"
                "command. However, in 2.0 it is possible to force an update of the zonelist.xml\n"
                "file by using the new 'xml' flag. This is in contrast to the behaviour in 1.4\n"
                "where zonelist.xml was always updated, unless the 'no-xml' flag was used. \n"
                "\n");
            xmlNodeAddContent(node, (xmlChar*)
                "As a result in 2.0 the contents of the enforcer database should be considered\n"
                "the 'master' for the list of currently configured zones, not the zonelist.xml\n"
                "file as the file can easily become out of sync with the database.\n"
                "\n");
            xmlNodeAddContent(node, (xmlChar*)
                "The contents of the database can be listed using:\n"
                "  ods-enforcer zone list\n"
                "and exported using the command\n"
                "  ods-enforcer zonelist export\n"
                "The contents of the database can still be updated in bulk from the zonelist.xml\n"
                "file by using the command:\n"
                "  ods-enforcer zonelist import    (or ods-enforcer update zonelist)\n\n"
            );
            xmlAddChild(root, node);
        }
        xmlDocSetRootElement(doc, root);
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
                    client_printf_err(sockfd, "Unable to XML property, memory allocation error!\n");
                    xmlFreeDoc(doc);
                    return ZONELIST_UPDATE_ERR_XML;
                }

                if (!strcmp(zone->name, (char*)name)) {
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
                client_printf_err(sockfd, "Unable to update XML, entry already exists!\n");
                xmlFreeDoc(doc);
                return ZONELIST_UPDATE_ERR_XML;
            }
            if (!add && !found) {
                xmlFreeDoc(doc);
                return ZONELIST_UPDATE_OK;
            }
        }

        if (add) {
            if (!(node = xmlNewChild(root, NULL, (xmlChar*)"Zone", NULL))
                || !xmlNewProp(node, (xmlChar*)"name", (xmlChar*)zone->name)
                || !xmlNewChild(node, NULL, (xmlChar*)"Policy", (xmlChar*)policyname)
                || !xmlNewChild(node, NULL, (xmlChar*)"SignerConfiguration", (xmlChar*)zone->signconf_path)
                || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Adapters", NULL))
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Input", NULL))
                || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Adapter", (xmlChar*)zone->input_adapter_uri))
                || !xmlNewProp(node4, (xmlChar*)"type", (xmlChar*)zone->input_adapter_type)
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Output", NULL))
                || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Adapter", (xmlChar*)zone->output_adapter_uri))
                || !xmlNewProp(node4, (xmlChar*)"type", (xmlChar*)zone->output_adapter_type))
            {
                client_printf_err(sockfd, "Unable to create new XML element, memory allocation or internal error!\n");
                xmlFreeDoc(doc);
                return ZONELIST_UPDATE_ERR_XML;
            }
        }

        break;
    }

    if (snprintf(path, sizeof(path), "%s.update", filename) >= (int)sizeof(path)) {
        client_printf_err(sockfd, "Unable to write updated XML, path to long!\n");
        xmlFreeDoc(doc);
        return ZONELIST_UPDATE_ERR_MEMORY;
    }
    unlink(path);
    if (xmlSaveFormatFileEnc(path, doc, "UTF-8", 1) == -1) {
        client_printf_err(sockfd, "Unable to write updated XML, unknown error!\n");
        unlink(path);
        xmlFreeDoc(doc);
        return ZONELIST_UPDATE_ERR_FILE;
    }
    xmlFreeDoc(doc);

    if (check_zonelist(path, 0, NULL, 0)) {
        client_printf_err(sockfd, "Validating updated XML failed!\n");
        unlink(path);
        return ZONELIST_UPDATE_ERR_XML;
    }

    if (rename(path, filename)) {
        client_printf_err(sockfd, "Unable to write updated XML, rename failed!\n");
        unlink(path);
        return ZONELIST_UPDATE_ERR_FILE;
    }

    return ZONELIST_UPDATE_OK;
}

int zonelist_update_add(int sockfd, const char* filename,
       const struct dbw_zone* zone, const char *policyname, int comment)
{
    return zonelist_update(1, sockfd, filename, zone, policyname, comment);
}

int zonelist_update_delete(int sockfd, const char* filename,
       const struct dbw_zone* zone, const char *policyname, int comment)
{
    return zonelist_update(0, sockfd, filename, zone, policyname, comment);
}
