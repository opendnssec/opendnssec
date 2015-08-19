/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
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

#include "zone.h"

#include "db_error.h"
#include "log.h"
#include "policy.h"

#include <string.h>

key_data_list_t* zone_get_keys(const zone_t* zone) {
    if (!zone) {
        return NULL;
    }
    if (!zone->dbo) {
        return NULL;
    }
    if (db_value_not_empty(&(zone->id))) {
        return NULL;
    }

    return key_data_list_new_get_by_zone_id(db_object_connection(zone->dbo),
        &(zone->id));

    /*
     * TODO: associated
    return key_data_list_new_copy(zone_key_data_list(zone));
     */
}

key_dependency_list_t* zone_get_key_dependencies(const zone_t* zone) {
    if (!zone) {
        return NULL;
    }
    if (!zone->dbo) {
        return NULL;
    }
    if (db_value_not_empty(&(zone->id))) {
        return NULL;
    }

    return key_dependency_list_new_get_by_zone_id(db_object_connection(zone->dbo),
        &(zone->id));

    /*
     * TODO: associated
    return key_dependency_list_new_copy(zone_key_dependency_list(zone));
    */
}

static int __xmlNode2zone(zone_t* zone, xmlNodePtr zone_node, int* updated) {
    xmlNodePtr node;
    xmlNodePtr node2;
    xmlNodePtr node3;
    xmlChar* xml_text = NULL;
    int check_if_updated = 0;
    int update_this = 1;
    policy_t* policy = NULL;
    int ret;

    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone_node) {
        return DB_ERROR_UNKNOWN;
    }

    /*
     * If updated is set we will check if the content is changed and set the
     * integer pointed by updated to non-zero.
     */
    if (updated) {
        *updated = 0;
        check_if_updated = 1;
    }

    if (!(xml_text = xmlGetProp(zone_node, (xmlChar*)"name"))) {
        return DB_ERROR_UNKNOWN;
    }
    ods_log_deeebug("[zone_*_from_xml] zone %s", (char*)xml_text);
    if (check_if_updated) {
        update_this = 0;
        if (!zone_name(zone)) {
            *updated = 1;
            update_this = 1;
        }
        else if (strcmp(zone_name(zone), (char*)xml_text)) {
            *updated = 1;
            update_this = 1;
        }
    }
    if (update_this) {
        if (zone_set_name(zone, (char*)xml_text)) {
            if (xml_text) {
                xmlFree(xml_text);
            }
            return DB_ERROR_UNKNOWN;
        }
    }
    if (xml_text) {
        xmlFree(xml_text);
        xml_text = NULL;
    }

    for (node = zone_node->children; node; node = node->next) {
        if (node->type != XML_ELEMENT_NODE) {
            continue;
        }

        if (!strcmp((char*)node->name, "Policy")) {
            if (!(xml_text = xmlNodeGetContent(node))) {
                policy_free(policy);
                return DB_ERROR_UNKNOWN;
            }
            if (policy) {
                if (strcmp(policy_name(policy), (char*)xml_text)
                    && policy_get_by_name(policy, (char*)xml_text))
                {
                    policy_free(policy);
                    if (xml_text) {
                        xmlFree(xml_text);
                    }
                    return DB_ERROR_UNKNOWN;
                }
            }
            else {
                if (!(policy = policy_new(db_object_connection(zone->dbo)))
                    || policy_get_by_name(policy, (char*)xml_text))
                {
                    policy_free(policy);
                    if (xml_text) {
                        xmlFree(xml_text);
                    }
                    return DB_ERROR_UNKNOWN;
                }
            }
            ods_log_deeebug("[zone_*_from_xml] policy %s", (char*)xml_text);
            if (check_if_updated) {
                update_this = 0;
                if (db_value_cmp(zone_policy_id(zone), policy_id(policy), &ret)) {
                    policy_free(policy);
                    if (xml_text) {
                        xmlFree(xml_text);
                    }
                    return DB_ERROR_UNKNOWN;
                }
                if (ret) {
                    *updated = 1;
                    update_this = 1;
                }
            }
            if (update_this) {
                if (zone_set_policy_id(zone, policy_id(policy))) {
                    policy_free(policy);
                    if (xml_text) {
                        xmlFree(xml_text);
                    }
                    return DB_ERROR_UNKNOWN;
                }
            }
            if (xml_text) {
                xmlFree(xml_text);
                xml_text = NULL;
            }
        }
        else if (!strcmp((char*)node->name, "SignerConfiguration")) {
            if (!(xml_text = xmlNodeGetContent(node))) {
                policy_free(policy);
                return DB_ERROR_UNKNOWN;
            }
            ods_log_deeebug("[zone_*_from_xml] signconf path %s", (char*)xml_text);
            if (check_if_updated) {
                update_this = 0;
                if (!zone_signconf_path(zone)) {
                    *updated = 1;
                    update_this = 1;
                }
                else if (strcmp(zone_signconf_path(zone), (char*)xml_text)) {
                    *updated = 1;
                    update_this = 1;
                }
            }
            if (update_this) {
                if (zone_set_signconf_path(zone, (char*)xml_text)) {
                    if (xml_text) {
                        xmlFree(xml_text);
                    }
                    policy_free(policy);
                    return DB_ERROR_UNKNOWN;
                }
            }
            if (xml_text) {
                xmlFree(xml_text);
                xml_text = NULL;
            }
        }
        else if (!strcmp((char*)node->name, "Adapters")) {
            for (node2 = node->children; node2; node2 = node2->next) {
                if (node2->type != XML_ELEMENT_NODE) {
                    continue;
                }

                if (!strcmp((char*)node2->name, "Input")) {
                    for (node3 = node2->children; node3; node3 = node3->next) {
                        if (node3->type != XML_ELEMENT_NODE) {
                            continue;
                        }

                        if (!strcmp((char*)node3->name, "File")) {
                            ods_log_deeebug("[zone_*_from_xml] input adapter type File");
                            if (check_if_updated) {
                                update_this = 0;
                                if (!zone_input_adapter_type(zone)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                                else if (strcmp(zone_input_adapter_type(zone), "File")) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                            }
                            if (update_this) {
                                if (zone_set_input_adapter_type(zone, "File")) {
                                    if (xml_text) {
                                        xmlFree(xml_text);
                                    }
                                    policy_free(policy);
                                    return DB_ERROR_UNKNOWN;
                                }
                            }
                            if (xml_text) {
                                xmlFree(xml_text);
                                xml_text = NULL;
                            }

                            if (!(xml_text = xmlNodeGetContent(node3))) {
                                policy_free(policy);
                                return DB_ERROR_UNKNOWN;
                            }
                            ods_log_deeebug("[zone_*_from_xml] input adapter uri %s", (char*)xml_text);
                            if (check_if_updated) {
                                update_this = 0;
                                if (!zone_input_adapter_uri(zone)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                                else if (strcmp(zone_input_adapter_uri(zone), (char*)xml_text)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                            }
                            if (update_this) {
                                if (zone_set_input_adapter_uri(zone, (char*)xml_text)) {
                                    if (xml_text) {
                                        xmlFree(xml_text);
                                    }
                                    policy_free(policy);
                                    return DB_ERROR_UNKNOWN;
                                }
                            }
                            if (xml_text) {
                                xmlFree(xml_text);
                                xml_text = NULL;
                            }
                        }
                        else if (!strcmp((char*)node3->name, "Adapter")) {
                            if (!(xml_text = xmlGetProp(node3, (xmlChar*)"type"))) {
                                policy_free(policy);
                                return DB_ERROR_UNKNOWN;
                            }
                            ods_log_deeebug("[zone_*_from_xml] input adapter type %s", (char*)xml_text);
                            if (check_if_updated) {
                                update_this = 0;
                                if (!zone_input_adapter_type(zone)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                                else if (strcmp(zone_input_adapter_type(zone), (char*)xml_text)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                            }
                            if (update_this) {
                                if (zone_set_input_adapter_type(zone, (char*)xml_text)) {
                                    if (xml_text) {
                                        xmlFree(xml_text);
                                    }
                                    policy_free(policy);
                                    return DB_ERROR_UNKNOWN;
                                }
                            }
                            if (xml_text) {
                                xmlFree(xml_text);
                                xml_text = NULL;
                            }

                            if (!(xml_text = xmlNodeGetContent(node3))) {
                                policy_free(policy);
                                return DB_ERROR_UNKNOWN;
                            }
                            ods_log_deeebug("[zone_*_from_xml] input adapter uri %s", (char*)xml_text);
                            if (check_if_updated) {
                                update_this = 0;
                                if (!zone_input_adapter_uri(zone)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                                else if (strcmp(zone_input_adapter_uri(zone), (char*)xml_text)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                            }
                            if (update_this) {
                                if (zone_set_input_adapter_uri(zone, (char*)xml_text)) {
                                    if (xml_text) {
                                        xmlFree(xml_text);
                                    }
                                    policy_free(policy);
                                    return DB_ERROR_UNKNOWN;
                                }
                            }
                            if (xml_text) {
                                xmlFree(xml_text);
                                xml_text = NULL;
                            }
                        }
                        else {
                            ods_log_deeebug("[zone_*_from_xml] unknown %s", (char*)node3->name);
                            policy_free(policy);
                            return DB_ERROR_UNKNOWN;
                        }
                    }
                }
                else if (!strcmp((char*)node2->name, "Output")) {
                    for (node3 = node2->children; node3; node3 = node3->next) {
                        if (node3->type != XML_ELEMENT_NODE) {
                            continue;
                        }

                        if (!strcmp((char*)node3->name, "File")) {
                            ods_log_deeebug("[zone_*_from_xml] output adapter type File");
                            if (check_if_updated) {
                                update_this = 0;
                                if (!zone_output_adapter_type(zone)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                                else if (strcmp(zone_output_adapter_type(zone), "File")) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                            }
                            if (update_this) {
                                if (zone_set_output_adapter_type(zone, "File")) {
                                    if (xml_text) {
                                        xmlFree(xml_text);
                                    }
                                    policy_free(policy);
                                    return DB_ERROR_UNKNOWN;
                                }
                            }
                            if (xml_text) {
                                xmlFree(xml_text);
                                xml_text = NULL;
                            }

                            if (!(xml_text = xmlNodeGetContent(node3))) {
                                policy_free(policy);
                                return DB_ERROR_UNKNOWN;
                            }
                            ods_log_deeebug("[zone_*_from_xml] output adapter uri %s", (char*)xml_text);
                            if (check_if_updated) {
                                update_this = 0;
                                if (!zone_output_adapter_uri(zone)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                                else if (strcmp(zone_output_adapter_uri(zone), (char*)xml_text)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                            }
                            if (update_this) {
                                if (zone_set_output_adapter_uri(zone, (char*)xml_text)) {
                                    if (xml_text) {
                                        xmlFree(xml_text);
                                    }
                                    policy_free(policy);
                                    return DB_ERROR_UNKNOWN;
                                }
                            }
                            if (xml_text) {
                                xmlFree(xml_text);
                                xml_text = NULL;
                            }
                        }
                        else if (!strcmp((char*)node3->name, "Adapter")) {
                            if (!(xml_text = xmlGetProp(node3, (xmlChar*)"type"))) {
                                policy_free(policy);
                                return DB_ERROR_UNKNOWN;
                            }
                            ods_log_deeebug("[zone_*_from_xml] output adapter type %s", (char*)xml_text);
                            if (check_if_updated) {
                                update_this = 0;
                                if (!zone_output_adapter_type(zone)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                                else if (strcmp(zone_output_adapter_type(zone), (char*)xml_text)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                            }
                            if (update_this) {
                                if (zone_set_output_adapter_type(zone, (char*)xml_text)) {
                                    if (xml_text) {
                                        xmlFree(xml_text);
                                    }
                                    policy_free(policy);
                                    return DB_ERROR_UNKNOWN;
                                }
                            }
                            if (xml_text) {
                                xmlFree(xml_text);
                                xml_text = NULL;
                            }

                            if (!(xml_text = xmlNodeGetContent(node3))) {
                                policy_free(policy);
                                return DB_ERROR_UNKNOWN;
                            }
                            ods_log_deeebug("[zone_*_from_xml] output adapter uri %s", (char*)xml_text);
                            if (check_if_updated) {
                                update_this = 0;
                                if (!zone_output_adapter_uri(zone)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                                else if (strcmp(zone_output_adapter_uri(zone), (char*)xml_text)) {
                                    *updated = 1;
                                    update_this = 1;
                                }
                            }
                            if (update_this) {
                                if (zone_set_output_adapter_uri(zone, (char*)xml_text)) {
                                    if (xml_text) {
                                        xmlFree(xml_text);
                                    }
                                    policy_free(policy);
                                    return DB_ERROR_UNKNOWN;
                                }
                            }
                            if (xml_text) {
                                xmlFree(xml_text);
                                xml_text = NULL;
                            }
                        }
                        else {
                            ods_log_deeebug("[zone_*_from_xml] unknown %s", (char*)node3->name);
                            policy_free(policy);
                            return DB_ERROR_UNKNOWN;
                        }
                    }
                }
                else {
                    ods_log_deeebug("[zone_*_from_xml] unknown %s", (char*)node2->name);
                    policy_free(policy);
                    return DB_ERROR_UNKNOWN;
                }
            }
        }
        else {
            ods_log_deeebug("[zone_*_from_xml] unknown %s", (char*)node->name);
            policy_free(policy);
            return DB_ERROR_UNKNOWN;
        }
    }

    if (xml_text) {
        xmlFree(xml_text);
        xml_text = NULL;
    }
    policy_free(policy);
    return DB_OK;
}

int zone_create_from_xml(zone_t* zone, xmlNodePtr zone_node) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone_node) {
        return DB_ERROR_UNKNOWN;
    }

    return __xmlNode2zone(zone, zone_node, NULL);
}

int zone_update_from_xml(zone_t* zone, xmlNodePtr zone_node, int* updated) {
    if (!zone) {
        return DB_ERROR_UNKNOWN;
    }
    if (!zone_node) {
        return DB_ERROR_UNKNOWN;
    }
    if (!updated) {
        return DB_ERROR_UNKNOWN;
    }

    return __xmlNode2zone(zone, zone_node, updated);
}
