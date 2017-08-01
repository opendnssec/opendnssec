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
#include "clientpipe.h"
#include "db/policy.h"
#include "db/policy_key.h"
#include "utils/kc_helper.h"
#include "db/zone_db.h"
#include "db/hsm_key.h"
#include "hsmkey/hsm_key_factory.h"
#include "signconf/signconf_task.h"

#include "policy/policy_import.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

struct __policy_import_policy_key;
struct __policy_import_policy_key {
    struct __policy_import_policy_key* next;
    policy_key_t *policy_key;
    int processed;
};

struct __policy_import_policy;
struct __policy_import_policy {
    struct __policy_import_policy* next;
    char* name;
    int processed;
};

static void __policy_import_cleanup(struct __policy_import_policy_key** policy_keys_db, struct __policy_import_policy_key** policy_keys_xml, struct __policy_import_policy** policies) {
    struct __policy_import_policy_key* policy_key_db;
    struct __policy_import_policy_key* policy_key_xml;
    struct __policy_import_policy* policy2;

    for (policy_key_db = *policy_keys_db; policy_key_db; policy_key_db = *policy_keys_db) {
        *policy_keys_db = policy_key_db->next;
        if (policy_key_db->policy_key) {
            policy_key_free(policy_key_db->policy_key);
        }
        free(policy_key_db);
    }
    for (policy_key_xml = *policy_keys_xml; policy_key_xml; policy_key_xml = *policy_keys_xml) {
        *policy_keys_xml = policy_key_xml->next;
        if (policy_key_xml->policy_key) {
            policy_key_free(policy_key_xml->policy_key);
        }
        free(policy_key_xml);
        policy_key_xml = *policy_keys_xml;
    }
    for (policy2 = *policies; policy2; policy2 = *policies) {
        *policies = policy2->next;
        free(policy2->name);
        free(policy2);
    }
}

static int check_duplicated_policy_keys(db_connection_t *dbconn, xmlNodePtr node) {
    xmlNodePtr node2;
    xmlNodePtr node3;
    xmlNodePtr* keys;
    size_t count = 0, i, j, found;
    policy_key_t *A, *B = NULL;

    /*
     * Count the keys in the XML
     */
    for (node2 = node->children; node2; node2 = node2->next) {
        if (node2->type != XML_ELEMENT_NODE) {
            continue;
        }
        if (strcmp((char*)node2->name, "Keys")) {
            continue;
        }

        for (node3 = node2->children; node3; node3 = node3->next) {
            if (node3->type != XML_ELEMENT_NODE) {
                continue;
            }
            if (strcmp((char*)node3->name, "KSK")
                && strcmp((char*)node3->name, "ZSK")
                && strcmp((char*)node3->name, "CSK"))
            {
                continue;
            }
            count++;
        }
        break; /* Look no further, there is only one 'Keys' section */
    }

    if (!count) {
        return 0;
    }

    /*
     * Allocate an array of nodes and put all keys in it
     */
    if (!(keys = (xmlNodePtr*)calloc(count, sizeof(xmlNodePtr)))) {
        return -1;
    }
    for (i = 0, node2 = node->children; node2; node2 = node2->next) {
        if (node2->type != XML_ELEMENT_NODE) {
            continue;
        }
        if (strcmp((char*)node2->name, "Keys")) {
            continue;
        }

        for (node3 = node2->children; node3; node3 = node3->next) {
            if (node3->type != XML_ELEMENT_NODE) {
                continue;
            }
            if (strcmp((char*)node3->name, "KSK")
                && strcmp((char*)node3->name, "ZSK")
                && strcmp((char*)node3->name, "CSK"))
            {
                continue;
            }

            if (i >= count) {
                free(keys);
                return -1;
            }

            keys[i] = node3;
            i++;
        }
    }

    /*
     * Walk the array and check for duplicated keys
     *
     * TODO: this could be optimized by creating all the policy_key objects
     * before checking them.
     */
    if (!(A = policy_key_new(dbconn))
        || !(B = policy_key_new(dbconn)))
    {
        policy_key_free(A);
        policy_key_free(B);
        free(keys);
        return -1;
    }
    for (found = 0, i = 0; i < count && !found; i++) {
        policy_key_reset(A);
        if (policy_key_create_from_xml(A, keys[i])) {
            found = -1;
            break;
        }
        for (j = i + 1; j < count && !found; j++) {
            policy_key_reset(B);
            if (policy_key_create_from_xml(B, keys[j])) {
                found = -1;
                break;
            }
            if (!policy_key_cmp(A, B)) {
                found = 1;
                break;
            }
        }
    }

    policy_key_free(A);
    policy_key_free(B);
    free(keys);
    return found;
}

int policy_import(int sockfd, engine_type* engine, db_connection_t *dbconn,
    int do_delete)
{
    xmlDocPtr doc;
    xmlNodePtr real_root;
    xmlNodePtr root;
    xmlNodePtr node;
    xmlNodePtr node2;
    xmlNodePtr node3;
    xmlChar* name;
    policy_t* policy;
    policy_key_t* policy_key;
    const policy_key_t* policy_key2;
    int updated;
    int successful;
    struct __policy_import_policy_key* policy_keys_db = NULL;
    struct __policy_import_policy_key* policy_key_db;
    struct __policy_import_policy_key* policy_keys_xml = NULL;
    struct __policy_import_policy_key* policy_key_xml;
    policy_key_list_t* policy_key_list;
    int keys_updated;
    int database_error = 0;
    int xml_error = 0;
    char **repositories = NULL;
    int repository_count = 0;
    struct engineconfig_repository* hsm;
    int i;
    struct __policy_import_policy* policies = NULL;
    struct __policy_import_policy* policy2;
    policy_list_t* policy_list;
    const policy_t* policy_walk;
    zone_list_db_t* zone_list;
    hsm_key_list_t* hsm_key_list;
    int any_update = 0;

    if (!engine) {
        return POLICY_IMPORT_ERR_ARGS;
    }
    if (!engine->config) {
        return POLICY_IMPORT_ERR_ARGS;
    }
    if (!engine->config->policy_filename) {
        return POLICY_IMPORT_ERR_ARGS;
    }
    if (!dbconn) {
        return POLICY_IMPORT_ERR_ARGS;
    }

    /*
     * Retrieve all the current policies so they can be marked processed later
     * and then the unprocessed can be deleted
     */
    if (!(policy_list = policy_list_new_get(dbconn))) {
        client_printf_err(sockfd, "Unable to fetch all the current policies in the database!\n");
        return POLICY_IMPORT_ERR_DATABASE;
    }
    for (policy_walk = policy_list_next(policy_list); policy_walk; policy_walk = policy_list_next(policy_list)) {
        if (!(policy2 = calloc(1, sizeof(struct __policy_import_policy)))
            || !(policy2->name = strdup(policy_name(policy_walk))))
        {
            client_printf_err(sockfd, "Memory allocation error!\n");
            policy_list_free(policy_list);
            if (policy2) {
                free(policy2);
            }
            for (policy2 = policies; policy2; policy2 = policies) {
                free(policy2->name);
                policies = policy2->next;
                free(policy2);
            }
            return POLICY_IMPORT_ERR_MEMORY;
        }

        policy2->next = policies;
        policies = policy2;
    }
    policy_list_free(policy_list);

    /*
     * Get HSM Repositories
     */
    if (engine->config->repositories) {
        for (hsm = engine->config->repositories; hsm; hsm = hsm->next, repository_count++)
            ;
        if (!(repositories = calloc(repository_count, sizeof(char*)))) {
            __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
            return POLICY_IMPORT_ERR_MEMORY;
        }
        for (i = 0, hsm = engine->config->repositories; hsm && i<repository_count; hsm = hsm->next, i++)
            repositories[i] = hsm->name;
    }

    /*
     * Validate KASP
     */
    if (check_kasp(engine->config->policy_filename, repositories, repository_count, 0, NULL, NULL)) {
        client_printf_err(sockfd, "Unable to validate the KASP XML, please run ods-kaspcheck for more details!\n");
        if (repositories) {
            free(repositories);
        }
        __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
        return POLICY_IMPORT_ERR_XML;
    }

    if (repositories) {
        free(repositories);
    }

    if (!(doc = xmlParseFile(engine->config->policy_filename))) {
        client_printf_err(sockfd, "Unable to read/parse KASP XML file %s!\n",
            engine->config->policy_filename);
        __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
        return POLICY_IMPORT_ERR_XML;
    }

    if (!(real_root = xmlDocGetRootElement(doc))) {
        client_printf_err(sockfd, "Unable to get the root element in the KASP XML!\n");
        xmlFreeDoc(doc);
        __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
        return POLICY_IMPORT_ERR_XML;
    }

    /*
     * Check for duplicated policy keys
     */
    for (root = real_root; root; root = root->next) {
        if (root->type != XML_ELEMENT_NODE) {
            continue;
        }

        if (!strcmp((char*)root->name, "KASP")) {
            for (node = root->children; node; node = node->next) {
                if (node->type != XML_ELEMENT_NODE) {
                    continue;
                }
                if (strcmp((char*)node->name, "Policy")) {
                    continue;
                }

                if (!(name = xmlGetProp(node, (const xmlChar*)"name"))) {
                    client_printf_err(sockfd, "Invalid Policy element in KASP XML!\n");
                    xmlFreeDoc(doc);
                    __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
                    return POLICY_IMPORT_ERR_XML;
                }

                if (check_duplicated_policy_keys(dbconn, node)) {
                    client_printf_err(sockfd, "Duplicated Policy Key elements in KASP XML is not allowed!\n");
                    xmlFree(name);
                    xmlFreeDoc(doc);
                    __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
                    return POLICY_IMPORT_ERR_XML;
                }
                xmlFree(name);
            }
        }
    }

    /*
     * Process XML
     */
    for (root = real_root; root; root = root->next) {
        if (root->type != XML_ELEMENT_NODE) {
            continue;
        }

        if (!strcmp((char*)root->name, "KASP")) {
            for (node = root->children; node; node = node->next) {
                if (node->type != XML_ELEMENT_NODE) {
                    continue;
                }
                if (strcmp((char*)node->name, "Policy")) {
                    continue;
                }

                if (!(name = xmlGetProp(node, (const xmlChar*)"name"))) {
                    client_printf_err(sockfd, "Invalid Policy element in KASP XML!\n");
                    xmlFreeDoc(doc);
                    __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
                    return POLICY_IMPORT_ERR_XML;
                }

                if (!(policy = policy_new(dbconn))) {
                    client_printf_err(sockfd, "Memory allocation error!\n");
                    xmlFree(name);
                    xmlFreeDoc(doc);
                    __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
                    return POLICY_IMPORT_ERR_MEMORY;
                }

                /*
                 * Fetch the policy by name, if we can't find it create a new
                 * one otherwise update the existing one
                 */
                if (policy_get_by_name(policy, (char*)name)) {
                    if (policy_create_from_xml(policy, node)) {
                        client_printf_err(sockfd,
                            "Unable to create policy %s from XML, XML content may be invalid!\n",
                            (char*)name);
                        policy_free(policy);
                        xmlFree(name);
                        xml_error = 1;
                        continue;
                    }

                    if (policy_create(policy)) {
                        client_printf_err(sockfd,
                            "Unable to create policy %s in the database!\n",
                            (char*)name);
                        policy_free(policy);
                        xmlFree(name);
                        database_error = 1;
                        continue;
                    }

                    if (policy_get_by_name(policy, (char*)name)) {
                        client_printf_err(sockfd,
                            "Unable to get policy %s from the database after creation, the policy may be corrupt in the database now!\n",
                            (char*)name);
                        policy_free(policy);
                        xmlFree(name);
                        database_error = 1;
                        continue;
                    }

                    /*
                     * Walk deeper into the XML and create all the keys we find
                     */
                    successful = 1;
                    for (node2 = node->children; node2; node2 = node2->next) {
                        if (node2->type != XML_ELEMENT_NODE) {
                            continue;
                        }
                        if (strcmp((char*)node2->name, "Keys")) {
                            continue;
                        }

                        for (node3 = node2->children; node3; node3 = node3->next) {
                            if (node3->type != XML_ELEMENT_NODE) {
                                continue;
                            }
                            if (strcmp((char*)node3->name, "KSK")
                                && strcmp((char*)node3->name, "ZSK")
                                && strcmp((char*)node3->name, "CSK"))
                            {
                                continue;
                            }

                            /*
                             * Create the policy key
                             */
                            if (!(policy_key = policy_key_new(dbconn))) {
                                client_printf_err(sockfd, "Memory allocation error!\n");
                                policy_free(policy);
                                policy_key_free(policy_key);
                                xmlFree(name);
                                xmlFreeDoc(doc);
                                __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
                                return POLICY_IMPORT_ERR_MEMORY;
                            }
                            if (policy_key_create_from_xml(policy_key, node3)) {
                                client_printf_err(sockfd,
                                    "Unable to create %s key for policy %s from XML!\n",
                                    (char*)node3->name, (char*)name);
                                policy_key_free(policy_key);
                                successful = 0;
                                xml_error = 1;
                                continue;
                            }
                            if (policy_key_set_policy_id(policy_key, policy_id(policy))
                                || policy_key_create(policy_key))
                            {
                                client_printf_err(sockfd,
                                    "Unable to create %s key for policy %s in the database, the policy is not complete in the database now!\n",
                                    (char*)node3->name, (char*)name);
                                policy_key_free(policy_key);
                                successful = 0;
                                database_error = 1;
                                continue;
                            }
                            policy_key_free(policy_key);
                        }
                    }

                    if (successful) {
                        ods_log_info("[policy_import] policy %s created", (char*)name);
                        client_printf(sockfd, "Created policy %s successfully\n", (char*)name);
                        any_update = 1;
                    }
                }
                else {
                    /*
                     * Mark it processed even if update fails so its not deleted
                     */
                    for (policy2 = policies; policy2; policy2 = policy2->next) {
                        if (policy2->processed) {
                            continue;
                        }
                        if (!strcmp(policy2->name, (char*)name)) {
                            policy2->processed = 1;
                            break;
                        }
                    }

                    /*
                     * Fetch all current keys, put them in a list for later
                     * processing
                     */
                    if (!(policy_key_list = policy_key_list_new(dbconn))
                        || policy_key_list_get_by_policy_id(policy_key_list, policy_id(policy)))
                    {
                        client_printf_err(sockfd,
                            "Unable to retrieve policy keys for policy %s, unknown database error!\n",
                            (char*)name);
                        policy_key_list_free(policy_key_list);
                        policy_free(policy);
                        xmlFree(name);
                        database_error = 1;
                        continue;
                    }

                    /*
                     * Clear the list if its been used before
                     */
                    for (policy_key_db = policy_keys_db; policy_key_db; policy_key_db = policy_keys_db) {
                        policy_keys_db = policy_key_db->next;
                        if (policy_key_db->policy_key) {
                            policy_key_free(policy_key_db->policy_key);
                        }
                        free(policy_key_db);
                    }

                    policy_key2 = policy_key_list_next(policy_key_list);
                    while (policy_key2) {
                        if (!(policy_key_db = calloc(1, sizeof(struct __policy_import_policy_key)))
                            || !(policy_key_db->policy_key = policy_key_new(dbconn))
                            || policy_key_copy(policy_key_db->policy_key, policy_key2))
                        {
                            client_printf_err(sockfd, "Memory allocation or internal error!\n");
                            if (policy_key_db->policy_key) {
                                policy_key_free(policy_key_db->policy_key);
                            }
                            free(policy_key_db);
                            policy_key_list_free(policy_key_list);
                            policy_free(policy);
                            xmlFree(name);
                            xmlFreeDoc(doc);
                            __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
                            return POLICY_IMPORT_ERR_MEMORY;
                        }

                        policy_key_db->next = policy_keys_db;
                        policy_keys_db = policy_key_db;

                        policy_key2 = policy_key_list_next(policy_key_list);
                    }
                    policy_key_list_free(policy_key_list);

                    /*
                     * Update the policy, if any data has changed then updated
                     * will be set to non-zero and if so we update the database
                     */
                    if (policy_update_from_xml(policy, node, &updated)) {
                        client_printf_err(sockfd,
                            "Unable to update policy %s from XML, XML content may be invalid!\n",
                            (char*)name);
                        policy_free(policy);
                        xmlFree(name);
                        xml_error = 1;
                        continue;
                    }

                    /*
                     * Walk deeper into the XML and create objects for all the
                     * keys we find but do not update the database yet
                     */

                    /*
                     * Clear the list if its been used before
                     */
                    for (policy_key_xml = policy_keys_xml; policy_key_xml; policy_key_xml = policy_keys_xml) {
                        policy_keys_xml = policy_key_xml->next;
                        if (policy_key_xml->policy_key) {
                            policy_key_free(policy_key_xml->policy_key);
                        }
                        free(policy_key_xml);
                        policy_key_xml = policy_keys_xml;
                    }

                    successful = 1;
                    for (node2 = node->children; node2; node2 = node2->next) {
                        if (node2->type != XML_ELEMENT_NODE) {
                            continue;
                        }
                        if (strcmp((char*)node2->name, "Keys")) {
                            continue;
                        }

                        for (node3 = node2->children; node3; node3 = node3->next) {
                            if (node3->type != XML_ELEMENT_NODE) {
                                continue;
                            }
                            if (strcmp((char*)node3->name, "KSK")
                                && strcmp((char*)node3->name, "ZSK")
                                && strcmp((char*)node3->name, "CSK"))
                            {
                                continue;
                            }

                            if (!(policy_key_xml = calloc(1, sizeof(struct __policy_import_policy_key)))
                                || !(policy_key_xml->policy_key = policy_key_new(dbconn)))
                            {
                                client_printf_err(sockfd, "Memory allocation or internal error!\n");
                                if (policy_key_xml->policy_key) {
                                    policy_key_free(policy_key_xml->policy_key);
                                }
                                free(policy_key_xml);
                                policy_free(policy);
                                xmlFree(name);
                                xmlFreeDoc(doc);
                                __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
                                return POLICY_IMPORT_ERR_MEMORY;
                            }

                            if (policy_key_set_policy_id(policy_key_xml->policy_key, policy_id(policy))
                                || policy_key_create_from_xml(policy_key_xml->policy_key, node3))
                            {
                                client_printf_err(sockfd,
                                    "Unable to create %s key for policy %s from XML, XML content may be invalid!\n",
                                    (char*)node3->name, (char*)name);
                                successful = 0;
                                if (policy_key_xml->policy_key) {
                                    policy_key_free(policy_key_xml->policy_key);
                                }
                                free(policy_key_xml);
                                xml_error = 1;
                                continue;
                            }

                            policy_key_xml->next = policy_keys_xml;
                            policy_keys_xml = policy_key_xml;
                        }
                    }

                    if (!successful) {
                        client_printf_err(sockfd,
                            "Unable to update policy %s from XML because of previous policy key error!\n",
                            (char*)name);
                        policy_free(policy);
                        xmlFree(name);
                        xml_error = 1;
                        continue;
                    }

                    /*
                     * Compare the two lists, one from the database and the
                     * other from the XML. If the policy key objects match then
                     * mark them processed in both lists.
                     */
                    policy_key_xml = policy_keys_xml;
                    while (policy_key_xml) {
                        if (policy_key_xml->processed) {
                            policy_key_xml = policy_key_xml->next;
                            continue;
                        }

                        policy_key_db = policy_keys_db;
                        while (policy_key_db) {
                            if (policy_key_db->processed) {
                                policy_key_db = policy_key_db->next;
                                continue;
                            }

                            if (!policy_key_cmp(policy_key_xml->policy_key, policy_key_db->policy_key)) {
                                policy_key_xml->processed = 1;
                                policy_key_db->processed = 1;
                                break;
                            }

                            policy_key_db = policy_key_db->next;
                        }

                        policy_key_xml = policy_key_xml->next;
                    }

                    keys_updated = 0;

                    /*
                     * For each object in XML list that has not been processed,
                     * create it in the database
                     */
                    successful = 1;
                    policy_key_xml = policy_keys_xml;
                    while (policy_key_xml) {
                        if (policy_key_xml->processed) {
                            policy_key_xml = policy_key_xml->next;
                            continue;
                        }

                        keys_updated = 1;

                        if (policy_key_create(policy_key_xml->policy_key)) {
                            client_printf_err(sockfd,
                                "Unable to create %s key for policy %s in database!\n",
                                policy_key_role_text(policy_key_xml->policy_key),
                                (char*)name);
                            successful = 0;
                            database_error = 1;
                            continue;
                        }

                        policy_key_xml = policy_key_xml->next;
                    }

                    if (!successful) {
                        client_printf_err(sockfd,
                            "Unable to update policy %s in the database because of previous policy key creation error, policy is not complete in the database now!\n",
                            (char*)name);
                        policy_free(policy);
                        xmlFree(name);
                        database_error = 1;
                        continue;
                    }

                    /*
                     * For each object in the database list that has not been
                     * processed, delete it from the database
                     */
                    policy_key_db = policy_keys_db;
                    while (policy_key_db) {
                        if (policy_key_db->processed) {
                            policy_key_db = policy_key_db->next;
                            continue;
                        }

                        keys_updated = 1;

                        if (policy_key_delete(policy_key_db->policy_key)) {
                            client_printf_err(sockfd,
                                "Unable to delete %s key for policy %s from database!\n",
                                policy_key_role_text(policy_key_db->policy_key),
                                (char*)name);
                            successful = 0;
                            database_error = 1;
                            continue;
                        }

                        policy_key_db = policy_key_db->next;
                    }

                    if (!successful) {
                        client_printf_err(sockfd,
                            "Unable to update policy %s in the database because of previous policy key deletion error, policy is invalid in the database now!\n",
                            (char*)name);
                        policy_free(policy);
                        xmlFree(name);
                        database_error = 1;
                        continue;
                    }

                    /*
                     * Update the policy in the database
                     */
                    if (updated) {
                        if (policy_update(policy)) {
                            client_printf_err(sockfd, "Unable to update policy %s in database!\n",
                                (char*)name);
                            policy_free(policy);
                            xmlFree(name);
                            database_error = 1;
                            continue;
                        }

                        ods_log_info("[policy_import] policy %s updated", (char*)name);
                        client_printf(sockfd, "Updated policy %s successfully\n",
                            (char*)name);
                        any_update = 1;
                    }
                    else if (keys_updated) {
                        ods_log_info("[policy_import] policy %s updated", (char*)name);
                        client_printf(sockfd, "Updated policy %s successfully\n",
                            (char*)name);
                        any_update = 1;
                    }
                    else {
                        client_printf(sockfd, "Policy %s already up-to-date\n",
                            (char*)name);
                    }
                }
                policy_free(policy);
                xmlFree(name);
            }
        }
    }
    signconf_task_flush_all(engine, dbconn);

    if (do_delete) {
        /*
         * Delete policies that has not been processed
         */
        for (policy2 = policies; policy2; policy2 = policy2->next) {
            if (policy2->processed) {
                continue;
            }

            if (!(policy = policy_new(dbconn))) {
                client_printf_err(sockfd, "Memory allocation error!\n");
                xmlFreeDoc(doc);
                for (policy2 = policies; policy2; policy2 = policies) {
                    free(policy2->name);
                    policies = policy2->next;
                    free(policy2);
                }
                __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
                return POLICY_IMPORT_ERR_MEMORY;
            }

            if (!policy_get_by_name(policy, policy2->name)) {
                /*
                 * Check if there are still zones or hsm keys using this policy and
                 * abort if there is
                 */
                if (!(zone_list = zone_list_db_new_get_by_policy_id(dbconn, policy_id(policy)))) {
                    client_printf_err(sockfd, "Unable to check for zones using policy %s from database!\n", policy2->name);
                    policy_free(policy);
                    database_error = 1;
                    continue;
                }
                if (zone_list_db_next(zone_list)) {
                    zone_list_db_free(zone_list);
                    client_printf_err(sockfd, "Unable to delete policy %s, there are still zones using this policy!\n", policy2->name);
                    policy_free(policy);
                    database_error = 1;
                    continue;
                }
                zone_list_db_free(zone_list);
                if (!(hsm_key_list = hsm_key_list_new_get_by_policy_id(dbconn, policy_id(policy)))) {
                    client_printf_err(sockfd, "Unable to check for hsm keys using policy %s from database!\n", policy2->name);
                    policy_free(policy);
                    database_error = 1;
                    continue;
                }
                if (hsm_key_list_next(hsm_key_list)) {
                    hsm_key_list_free(hsm_key_list);
                    client_printf_err(sockfd, "Unable to delete policy %s, there are still hsm keys using this policy!\n", policy2->name);
                    policy_free(policy);
                    database_error = 1;
                    continue;
                }
                hsm_key_list_free(hsm_key_list);

                /*
                 * Try and delete all the policy keys for this policy
                 */
                if (!(policy_key_list = policy_key_list_new_get_by_policy_id(dbconn, policy_id(policy)))) {
                    client_printf_err(sockfd, "Unable to get policy keys for policy %s from database!\n", policy2->name);
                    policy_free(policy);
                    database_error = 1;
                    continue;
                }
                successful = 1;
                for (policy_key = policy_key_list_get_next(policy_key_list); policy_key; policy_key_free(policy_key), policy_key = policy_key_list_get_next(policy_key_list)) {
                    if (policy_key_delete(policy_key)) {
                        client_printf_err(sockfd, "Unable to delete policy key %s in policy %s from database!\n", policy_key_role_text(policy_key), policy2->name);
                        database_error = 1;
                        successful = 0;
                        continue;
                    }
                }
                policy_key_list_free(policy_key_list);

                if (!successful) {
                    policy_free(policy);
                    continue;
                }
                if (policy_delete(policy)) {
                    client_printf_err(sockfd, "Unable to delete policy %s from database!\n", policy2->name);
                    policy_free(policy);
                    database_error = 1;
                    continue;
                }

                ods_log_info("[policy_import] policy %s deleted", policy2->name);
                client_printf(sockfd, "Deleted policy %s successfully\n", policy2->name);
            }
            else {
                client_printf_err(sockfd, "Unable to delete policy %s from database!\n", policy2->name);
                database_error = 1;
            }
            policy_free(policy);
        }
    }

    if (any_update && !engine->config->manual_keygen) {
        hsm_key_factory_schedule_generate_all(engine, 0);
    }

    __policy_import_cleanup(&policy_keys_db, &policy_keys_xml, &policies);
    xmlFreeDoc(doc);
    if (database_error) {
        return POLICY_IMPORT_ERR_DATABASE;
    }
    if (xml_error) {
        return POLICY_IMPORT_ERR_XML;
    }
    return POLICY_IMPORT_OK;
}
