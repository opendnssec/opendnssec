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

#include "config.h"

#include "log.h"
#include "clientpipe.h"
#include "db/zone_db.h"
#include "db/key_data.h"
#include "db/key_state.h"
#include "utils/kc_helper.h"
#include "hsmkey/hsm_key_factory.h"

#include "keystate/zonelist_import.h"

#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

static const char* module_str = "zonelist_import";

struct __zonelist_import_zone;
struct __zonelist_import_zone {
    struct __zonelist_import_zone* next;
    char* name;
    int processed;
};

int zonelist_import(int sockfd, engine_type* engine, db_connection_t *dbconn,
    int do_delete, const char* zonelist_path)
{
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr node;
    xmlChar* name;
    int updated;
    int database_error = 0;
    int xml_error = 0;
    zone_db_t* zone;
    const zone_db_t* zone_walk;
    zone_list_db_t* zone_list;
    struct __zonelist_import_zone* zones = NULL;
    struct __zonelist_import_zone* zone2;
    int successful;
    key_data_list_t* key_data_list;
    key_data_t* key_data;
    key_state_list_t* key_state_list;
    key_state_t* key_state;
    int any_update = 0;

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

    /*
     * Retrieve all the current zones so they can be marked processed later and
     * then the unprocessed can be deleted
     */
    if (!(zone_list = zone_list_db_new_get(dbconn))) {
        client_printf_err(sockfd, "Unable to fetch all the current zones in the database!\n");
        return ZONELIST_IMPORT_ERR_DATABASE;
    }
    for (zone_walk = zone_list_db_next(zone_list); zone_walk; zone_walk = zone_list_db_next(zone_list)) {
        if (!(zone2 = calloc(1, sizeof(struct __zonelist_import_zone)))
            || !(zone2->name = strdup(zone_db_name(zone_walk))))
        {
            client_printf_err(sockfd, "Memory allocation error!\n");
            zone_list_db_free(zone_list);
            if (zone2) {
                free(zone2);
            }
            for (zone2 = zones; zone2; zone2 = zones) {
                free(zone2->name);
                zones = zone2->next;
                free(zone2);
            }
            return ZONELIST_IMPORT_ERR_MEMORY;
        }

        zone2->next = zones;
        zones = zone2;
    }
    zone_list_db_free(zone_list);

    /*
     * Validate, parse and walk the XML.
     */
    if (!zonelist_path)
        zonelist_path = engine->config->zonelist_filename;
     
    if (check_zonelist(zonelist_path, 0, NULL, 0)) {
        client_printf_err(sockfd, "Unable to validate the zonelist XML!\n");
        for (zone2 = zones; zone2; zone2 = zones) {
            free(zone2->name);
            zones = zone2->next;
            free(zone2);
        }
        return ZONELIST_IMPORT_ERR_XML;
    }

    if (!(doc = xmlParseFile(zonelist_path))) {
        client_printf_err(sockfd, "Unable to read/parse zonelist XML file %s!\n",
            zonelist_path);
        for (zone2 = zones; zone2; zone2 = zones) {
            free(zone2->name);
            zones = zone2->next;
            free(zone2);
        }
        return ZONELIST_IMPORT_ERR_XML;
    }

    if (!(root = xmlDocGetRootElement(doc))) {
        client_printf_err(sockfd, "Unable to get the root element in the zonelist XML!\n");
        xmlFreeDoc(doc);
        for (zone2 = zones; zone2; zone2 = zones) {
            free(zone2->name);
            zones = zone2->next;
            free(zone2);
        }
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

                if (!(name = xmlGetProp(node, (const xmlChar*)"name"))) {
                    client_printf_err(sockfd, "Invalid Zone element in zonelist XML!\n");
                    xmlFreeDoc(doc);
                    for (zone2 = zones; zone2; zone2 = zones) {
                        free(zone2->name);
                        zones = zone2->next;
                        free(zone2);
                    }
                    return ZONELIST_IMPORT_ERR_XML;
                }

                if (!(zone = zone_db_new(dbconn))) {
                    client_printf_err(sockfd, "Memory allocation error!\n");
                    xmlFree(name);
                    xmlFreeDoc(doc);
                    for (zone2 = zones; zone2; zone2 = zones) {
                        free(zone2->name);
                        zones = zone2->next;
                        free(zone2);
                    }
                    return ZONELIST_IMPORT_ERR_MEMORY;
                }

                /*
                 * Fetch the zone by name, if we can't find it create a new
                 * one otherwise update the existing one
                 */
                if (zone_db_get_by_name(zone, (char*)name)) {
                    if (zone_db_create_from_xml(zone, node)) {
                        client_printf_err(sockfd,
                            "Unable to create zone %s from XML, XML content may be invalid!\n",
                            (char*)name);
                        zone_db_free(zone);
                        xmlFree(name);
                        xml_error = 1;
                        continue;
                    }

                    if (zone_db_create(zone)) {
                        client_printf_err(sockfd,
                            "Unable to create zone %s in the database!\n",
                            (char*)name);
                        zone_db_free(zone);
                        xmlFree(name);
                        database_error = 1;
                        continue;
                    }

		    if(!strcmp(zone_db_input_adapter_type(zone),"File")){
                        if(access(zone_db_input_adapter_uri(zone), F_OK) == -1) {
                            client_printf_err(sockfd, "WARNING: The input file %s for zone %s does not currently exist. The zone will be added to the database anyway.\n", zone_db_input_adapter_uri(zone), zone_db_name(zone));
			    ods_log_warning("[%s] WARNING: The input file %s for zone %s does not currently exist. The zone will be added to the database anyway.", module_str, zone_db_input_adapter_uri(zone), zone_db_name(zone));
                        }
                        else if (access(zone_db_input_adapter_uri(zone), R_OK)) {
                            client_printf_err(sockfd, module_str, "WARNING: Read access to input file %s for zone %s denied! \n", zone_db_input_adapter_uri(zone), zone_db_name(zone));
			    ods_log_warning("[%s] WARNING: Read access to input file %s for zone %s denied!", module_str, zone_db_input_adapter_uri(zone), zone_db_name(zone));
                        }
                    }

                    ods_log_info("[%s] zone %s created", module_str, (char*)name);
                    client_printf(sockfd, "Zone %s created successfully\n",
                        (char*)name);
                    any_update = 1;
                }
                else {
                    /*
                     * Mark it processed even if update fails so its not deleted
                     */
                    for (zone2 = zones; zone2; zone2 = zone2->next) {
                        if (zone2->processed) {
                            continue;
                        }
                        if (!strcmp(zone2->name, (char*)name)) {
                            zone2->processed = 1;
                            break;
                        }
                    }

                    /*
                     * Update the zone, if any data has changed then updated
                     * will be set to non-zero and if so we update the database
                     */
                    if (zone_db_update_from_xml(zone, node, &updated)) {
                        client_printf_err(sockfd,
                            "Unable to update zone %s from XML, XML content may be invalid!\n",
                            (char*)name);
                        zone_db_free(zone);
                        xmlFree(name);
                        xml_error = 1;
                        for (zone2 = zones; zone2; zone2 = zones) {
                            free(zone2->name);
                            zones = zone2->next;
                            free(zone2);
                        }
                        continue;
                    }

                    /*
                     * Update the zone in the database
                     */
                    if (updated) {
                        if (zone_db_update(zone)) {
                            client_printf_err(sockfd, "Unable to update zone %s in database!\n",
                                (char*)name);
                            zone_db_free(zone);
                            xmlFree(name);
                            database_error = 1;
                            continue;
                        }

                        ods_log_info("[%s] zone %s updated", module_str, (char*)name);
                        client_printf(sockfd, "Updated zone %s successfully\n",
                            (char*)name);
                        any_update = 1;
                    }
                    else {
                        client_printf(sockfd, "Zone %s already up-to-date\n",
                            (char*)name);
                    }
                }
                zone_db_free(zone);
                xmlFree(name);
            }
        }
    }

    if (do_delete) {
        /*
         * Delete zones that have not been processed
         */
        for (zone2 = zones; zone2; zone2 = zone2->next) {
            if (zone2->processed) {
                continue;
            }

            if (!(zone = zone_db_new(dbconn))) {
                client_printf_err(sockfd, "Memory allocation error!\n");
                xmlFreeDoc(doc);
                for (zone2 = zones; zone2; zone2 = zones) {
                    free(zone2->name);
                    zones = zone2->next;
                    free(zone2);
                }
                return ZONELIST_IMPORT_ERR_MEMORY;
            }

            /*
             * Fetch the zone by name, if it exists we try and delete it
             */
            if (!zone_db_get_by_name(zone, zone2->name)) {
                /*
                 * Get key data for the zone and for each key data get the key state
                 * and try to delete all key state then the key data
                 */
                if (!(key_data_list = key_data_list_new_get_by_zone_id(dbconn, zone_db_id(zone)))) {
                    client_printf_err(sockfd, "Unable to get key data for zone %s from database!\n", zone2->name);
                    zone_db_free(zone);
                    database_error = 1;
                    continue;
                }
                successful = 1;
                for (key_data = key_data_list_get_next(key_data_list); key_data; key_data_free(key_data), key_data = key_data_list_get_next(key_data_list)) {
                    if (!(key_state_list = key_state_list_new_get_by_key_data_id(dbconn, key_data_id(key_data)))) {
                        client_printf_err(sockfd, "Unable to get key states for key data %s of zone %s from database!\n", key_data_role_text(key_data), zone2->name);
                        database_error = 1;
                        successful = 0;
                        continue;
                    }

                    for (key_state = key_state_list_get_next(key_state_list); key_state; key_state_free(key_state), key_state = key_state_list_get_next(key_state_list)) {
                        if (key_state_delete(key_state)) {
                            client_printf_err(sockfd, "Unable to delete key state %s for key data %s of zone %s from database!\n", key_state_type_text(key_state), key_data_role_text(key_data), zone2->name);
                            database_error = 1;
                            successful = 0;
                            continue;
                        }
                    }
                    key_state_list_free(key_state_list);

                    if (key_data_delete(key_data)) {
                        client_printf_err(sockfd, "Unable to delete key data %s of zone %s from database!\n", key_data_role_text(key_data), zone2->name);
                        database_error = 1;
                        successful = 0;
                        continue;
                    }

                    if (hsm_key_factory_release_key_id(key_data_hsm_key_id(key_data), dbconn)) {
                        client_printf_err(sockfd, "Unable to release HSM key for key data %s of zone %s from database!\n", key_data_role_text(key_data), zone2->name);
                        successful = 0;
                        continue;
                    }
                }
                key_data_list_free(key_data_list);

                if (!successful) {
                    zone_db_free(zone);
                    continue;
                }
                if (zone_db_delete(zone)) {
                    client_printf_err(sockfd, "Unable to delete zone %s from database!\n", zone2->name);
                    zone_db_free(zone);
                    database_error = 1;
                    continue;
                }

                ods_log_info("[%s] zone %s deleted", module_str, zone2->name);
                client_printf(sockfd, "Deleted zone %s successfully\n", zone2->name);
            }
            else {
                client_printf_err(sockfd, "Unable to delete zone %s from database!\n", zone2->name);
                database_error = 1;
            }
            zone_db_free(zone);
        }
    }

    if (any_update && !engine->config->manual_keygen) {
        hsm_key_factory_schedule_generate_all(engine, 0);
    }

    for (zone2 = zones; zone2; zone2 = zones) {
        free(zone2->name);
        zones = zone2->next;
        free(zone2);
    }
    xmlFreeDoc(doc);
    if (database_error) {
        return ZONELIST_IMPORT_ERR_DATABASE;
    }
    if (xml_error) {
        return ZONELIST_IMPORT_ERR_XML;
    }
    if (!any_update) {
        return ZONELIST_IMPORT_NO_CHANGE;
    }
    return ZONELIST_IMPORT_OK;
}
