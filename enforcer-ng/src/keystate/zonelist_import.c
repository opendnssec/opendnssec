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

#include "daemon/engine.h"
#include "daemon/cmdhandler.h"
#include "shared/log.h"
#include "shared/str.h"
#include "daemon/clientpipe.h"
#include "db/zone.h"
#include "utils/kc_helper.h"

#include "keystate/zonelist_import.h"

int zonelist_import(int sockfd, engine_type* engine, db_connection_t *dbconn) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr node;
    xmlChar* zone_name;
    int updated;
    int database_error = 0;
    int xml_error = 0;
    zone_t* zone;

    if (!engine) {
        return ZONELIST_IMPORT_ERR_ARGS;
    }
    if (!engine->config) {
        return ZONELIST_IMPORT_ERR_ARGS;
    }
    if (!engine->config->zonelist_filename) {
        return ZONELIST_IMPORT_ERR_ARGS;
    }
    if (!dbconn) {
        return ZONELIST_IMPORT_ERR_ARGS;
    }

    if (check_zonelist(engine->config->zonelist_filename, 0)) {
        client_printf_err(sockfd, "Unable to validate the zonelist XML!\n");
        return ZONELIST_IMPORT_ERR_XML;
    }

    if (!(doc = xmlParseFile(engine->config->zonelist_filename))) {
        client_printf_err(sockfd, "Unable to read/parse zonelist XML file %s!\n",
            engine->config->zonelist_filename);
        return ZONELIST_IMPORT_ERR_XML;
    }

    if (!(root = xmlDocGetRootElement(doc))) {
        client_printf_err(sockfd, "Unable to get the root element in the zonelist XML!\n");
        xmlFreeDoc(doc);
        return ZONELIST_IMPORT_ERR_XML;
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

                if (!(zone_name = xmlGetProp(node, (const xmlChar*)"name"))) {
                    client_printf_err(sockfd, "Invalid Zone element in zonelist XML!\n");
                    xmlFreeDoc(doc);
                    return ZONELIST_IMPORT_ERR_XML;
                }

                if (!(zone = zone_new(dbconn))) {
                    client_printf_err(sockfd, "Memory allocation error!\n");
                    xmlFree(zone_name);
                    xmlFreeDoc(doc);
                    return ZONELIST_IMPORT_ERR_MEMORY;
                }

                /*
                 * Fetch the zone by name, if we can't find it create a new
                 * one otherwise update the existing one
                 */
                if (zone_get_by_name(zone, (char*)zone_name)) {
                    if (zone_create_from_xml(zone, node)) {
                        client_printf_err(sockfd,
                            "Unable to create zone %s from XML, XML content may be invalid!\n",
                            (char*)zone_name);
                        zone_free(zone);
                        xmlFree(zone_name);
                        xml_error = 1;
                        continue;
                    }

                    if (zone_create(zone)) {
                        client_printf_err(sockfd,
                            "Unable to create zone %s in the database!\n",
                            (char*)zone_name);
                        zone_free(zone);
                        xmlFree(zone_name);
                        database_error = 1;
                        continue;
                    }

                    client_printf(sockfd, "Zone %s created successfully\n",
                        (char*)zone_name);
                }
                else {
                    /*
                     * Update the zone, if any data has changed then updated
                     * will be set to non-zero and if so we update the database
                     */
                    if (zone_update_from_xml(zone, node, &updated)) {
                        client_printf_err(sockfd,
                            "Unable to update zone %s from XML, XML content may be invalid!\n",
                            (char*)zone_name);
                        zone_free(zone);
                        xmlFree(zone_name);
                        xml_error = 1;
                        continue;
                    }

                    /*
                     * Update the zone in the database
                     */
                    if (updated) {
                        if (zone_update(zone)) {
                            client_printf_err(sockfd, "Unable to update zone %s in database!\n",
                                (char*)zone_name);
                            zone_free(zone);
                            xmlFree(zone_name);
                            database_error = 1;
                            continue;
                        }

                        client_printf(sockfd, "Updated zone %s successfully\n",
                            (char*)zone_name);
                    }
                    else {
                        client_printf(sockfd, "Zone %s already up-to-date\n",
                            (char*)zone_name);
                    }
                }
                zone_free(zone);
                xmlFree(zone_name);
            }
        }
    }

    xmlFreeDoc(doc);
    if (database_error) {
        return ZONELIST_IMPORT_ERR_DATABASE;
    }
    if (xml_error) {
        return ZONELIST_IMPORT_ERR_XML;
    }
    return ZONELIST_IMPORT_OK;
}
