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
#include "db/policy.h"
#include "db/policy_key.h"

#include "policy/update_kasp_cmd.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

static const char *module_str = "update_kasp_cmd";

struct __update_kasp_policy_key;
struct __update_kasp_policy_key {
    struct __update_kasp_policy_key* next;
    policy_key_t *policy_key;
    int processed;
};

static void database_error_help(int sockfd) {
    client_printf_err(sockfd,
        "\nThe information in the database may have been changed during KASP update"
        "and caused an update error, try rerunning update kasp. If the problem persists"
        "please check logs and database setup and after correcting the problem rerun update kasp.\n"
    );
}

static void
usage(int sockfd)
{
    client_printf(sockfd,
        "update kasp            Import policies from kasp.xml into the enforcer.\n"
    );
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Import policies from kasp.xml into the enforcer\n"
    );
}

static int
handles(const char *cmd, ssize_t n)
{
    return ods_check_command(cmd, n, update_kasp_funcblock()->cmdname) ? 1 : 0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
    db_connection_t *dbconn)
{
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr node;
    xmlNodePtr node2;
    xmlNodePtr node3;
    xmlChar* policy_name;
    policy_t* policy;
    policy_key_t* policy_key;
    const policy_key_t* policy_key2;
    int updated;
    int successful;
    struct __update_kasp_policy_key* policy_keys_db = NULL;
    struct __update_kasp_policy_key* policy_key_db;
    struct __update_kasp_policy_key* policy_keys_xml = NULL;
    struct __update_kasp_policy_key* policy_key_xml;
    policy_key_list_t* policy_key_list;
    int keys_updated;
    int database_error = 0;

    (void)cmd; (void)n;

    if (!engine) {
        return 1;
    }
    if (!engine->config) {
        return 1;
    }
    if (!engine->config->policy_filename) {
        return 1;
    }
    if (!dbconn) {
        return 1;
    }

    ods_log_debug("[%s] %s command", module_str, update_kasp_funcblock()->cmdname);

    if (!(doc = xmlParseFile(engine->config->policy_filename))) {
        client_printf_err(sockfd,
            "Unable to read/parse KASP XML file %s!\n",
            engine->config->policy_filename);
        return 1;
    }

    if (!(root = xmlDocGetRootElement(doc))) {
        client_printf_err(sockfd, "Unable to get the root element in the KASP XML!\n");
        xmlFreeDoc(doc);
        return 1;
    }

    for (; root; root = root->next) {
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

                if (!(policy_name = xmlGetProp(node, (const xmlChar*)"name"))) {
                    client_printf_err(sockfd, "Invalid Policy element in KASP XML!\n");
                    xmlFreeDoc(doc);
                    return 1;
                }

                if (!(policy = policy_new(dbconn))) {
                    client_printf_err(sockfd, "Memory allocation error!\n");
                    xmlFree(policy_name);
                    xmlFreeDoc(doc);
                    return 1;
                }

                /*
                 * Fetch the policy by name, if we can't find it create a new
                 * one otherwise update the existing one
                 */
                if (policy_get_by_name(policy, (char*)policy_name)) {
                    if (policy_create_from_xml(policy, node)
                        || policy_create(policy))
                    {
                        client_printf_err(sockfd,
                            "Unable to create policy %s in the database!\n",
                            (char*)policy_name);
                        policy_free(policy);
                        xmlFree(policy_name);
                        continue;
                    }

                    if (policy_get_by_name(policy, (char*)policy_name)) {
                        client_printf_err(sockfd,
                            "Unable to get policy %s from the database after creation, "
                            "the policy may be corrupt in the database now!\n",
                            (char*)policy_name);
                        policy_free(policy);
                        xmlFree(policy_name);
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
                                xmlFree(policy_name);
                                xmlFreeDoc(doc);
                                return 1;
                            }
                            if (policy_key_set_policy_id(policy_key, policy_id(policy))
                                || policy_key_create_from_xml(policy_key, node3)
                                || policy_key_create(policy_key))
                            {
                                client_printf_err(sockfd,
                                    "Unable to create %s key for policy %s in the database, "
                                    "the policy is not complete in the database now!\n",
                                    (char*)node3->name, (char*)policy_name);
                                policy_key_free(policy_key);
                                successful = 0;
                                database_error = 1;
                                continue;
                            }
                            policy_key_free(policy_key);
                        }
                    }

                    if (successful) {
                        client_printf(sockfd, "Created policy %s successfully\n", (char*)policy_name);
                    }
                }
                else {
                    /*
                     * Fetch all current keys, put them in a list for later
                     * processing
                     */
                    if (!(policy_key_list = policy_key_list_new(dbconn))
                        || policy_key_list_get_by_policy_id(policy_key_list, policy_id(policy)))
                    {
                        client_printf_err(sockfd,
                            "Unable to retrieve policy keys for policy %s, "
                            "unknown database error!\n", (char*)policy_name);
                        policy_key_list_free(policy_key_list);
                        policy_free(policy);
                        xmlFree(policy_name);
                        continue;
                    }

                    policy_key2 = policy_key_list_begin(policy_key_list);
                    while (policy_key2) {
                        if (!(policy_key_db = calloc(1, sizeof(struct __update_kasp_policy_key)))
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
                            xmlFree(policy_name);
                            xmlFreeDoc(doc);
                            policy_key_db = policy_keys_db;
                            while (policy_key_db) {
                                policy_keys_db = policy_key_db->next;
                                if (policy_key_db->policy_key) {
                                    policy_key_free(policy_key_db->policy_key);
                                }
                                free(policy_key_db);
                                policy_key_db = policy_keys_db;
                            }
                            return 1;
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
                            "Unable to update policy %s from XML, "
                            "XML content may be invalid!\n", (char*)policy_name);
                        policy_free(policy);
                        xmlFree(policy_name);
                        policy_key_db = policy_keys_db;
                        while (policy_key_db) {
                            policy_keys_db = policy_key_db->next;
                            if (policy_key_db->policy_key) {
                                policy_key_free(policy_key_db->policy_key);
                            }
                            free(policy_key_db);
                            policy_key_db = policy_keys_db;
                        }
                        continue;
                    }

                    /*
                     * Walk deeper into the XML and create objects for all the
                     * keys we find but do not update the database yet
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

                            if (!(policy_key_xml = calloc(1, sizeof(struct __update_kasp_policy_key)))
                                || !(policy_key_xml->policy_key = policy_key_new(dbconn)))
                            {
                                client_printf_err(sockfd, "Memory allocation or internal error!\n");
                                if (policy_key_xml->policy_key) {
                                    policy_key_free(policy_key_xml->policy_key);
                                }
                                free(policy_key_xml);
                                policy_free(policy);
                                xmlFree(policy_name);
                                xmlFreeDoc(doc);
                                policy_key_db = policy_keys_db;
                                while (policy_key_db) {
                                    policy_keys_db = policy_key_db->next;
                                    if (policy_key_db->policy_key) {
                                        policy_key_free(policy_key_db->policy_key);
                                    }
                                    free(policy_key_db);
                                    policy_key_db = policy_keys_db;
                                }
                                policy_key_xml = policy_keys_xml;
                                while (policy_key_xml) {
                                    policy_keys_xml = policy_key_xml->next;
                                    if (policy_key_xml->policy_key) {
                                        policy_key_free(policy_key_xml->policy_key);
                                    }
                                    free(policy_key_xml);
                                    policy_key_xml = policy_keys_xml;
                                }
                                return 1;
                            }

                            if (policy_key_set_policy_id(policy_key_xml->policy_key, policy_id(policy))
                                || policy_key_create_from_xml(policy_key_xml->policy_key, node3))
                            {
                                client_printf_err(sockfd,
                                    "Unable to create %s key for policy %s from XML, "
                                    "XML content may be invalid!\n",
                                    (char*)node3->name, (char*)policy_name);
                                successful = 0;
                                if (policy_key_xml->policy_key) {
                                    policy_key_free(policy_key_xml->policy_key);
                                }
                                free(policy_key_xml);
                                continue;
                            }

                            policy_key_xml->next = policy_keys_xml;
                            policy_keys_xml = policy_key_xml;
                        }
                    }

                    if (!successful) {
                        client_printf_err(sockfd,
                            "Unable to update policy %s from XML because of previous policy key error!\n",
                            (char*)policy_name);
                        policy_free(policy);
                        xmlFree(policy_name);
                        policy_key_db = policy_keys_db;
                        while (policy_key_db) {
                            policy_keys_db = policy_key_db->next;
                            if (policy_key_db->policy_key) {
                                policy_key_free(policy_key_db->policy_key);
                            }
                            free(policy_key_db);
                            policy_key_db = policy_keys_db;
                        }
                        policy_key_xml = policy_keys_xml;
                        while (policy_key_xml) {
                            policy_keys_xml = policy_key_xml->next;
                            if (policy_key_xml->policy_key) {
                                policy_key_free(policy_key_xml->policy_key);
                            }
                            free(policy_key_xml);
                            policy_key_xml = policy_keys_xml;
                        }
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
                                (char*)policy_name);
                            successful = 0;
                            database_error = 1;
                            continue;
                        }

                        policy_key_xml = policy_key_xml->next;
                    }

                    if (!successful) {
                        client_printf_err(sockfd,
                            "Unable to update policy %s in the database because of previous policy key creation error, "
                            "policy is not complete in the database now!\n",
                            (char*)policy_name);
                        policy_free(policy);
                        xmlFree(policy_name);
                        policy_key_db = policy_keys_db;
                        while (policy_key_db) {
                            policy_keys_db = policy_key_db->next;
                            if (policy_key_db->policy_key) {
                                policy_key_free(policy_key_db->policy_key);
                            }
                            free(policy_key_db);
                            policy_key_db = policy_keys_db;
                        }
                        policy_key_xml = policy_keys_xml;
                        while (policy_key_xml) {
                            policy_keys_xml = policy_key_xml->next;
                            if (policy_key_xml->policy_key) {
                                policy_key_free(policy_key_xml->policy_key);
                            }
                            free(policy_key_xml);
                            policy_key_xml = policy_keys_xml;
                        }
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
                                (char*)policy_name);
                            successful = 0;
                            database_error = 1;
                            continue;
                        }

                        policy_key_db = policy_key_db->next;
                    }

                    if (!successful) {
                        client_printf_err(sockfd,
                            "Unable to update policy %s in the database because of previous policy key deletion error, "
                            "policy is invalid in the database now!\n",
                            (char*)policy_name);
                        policy_free(policy);
                        xmlFree(policy_name);
                        policy_key_db = policy_keys_db;
                        while (policy_key_db) {
                            policy_keys_db = policy_key_db->next;
                            if (policy_key_db->policy_key) {
                                policy_key_free(policy_key_db->policy_key);
                            }
                            free(policy_key_db);
                            policy_key_db = policy_keys_db;
                        }
                        policy_key_xml = policy_keys_xml;
                        while (policy_key_xml) {
                            policy_keys_xml = policy_key_xml->next;
                            if (policy_key_xml->policy_key) {
                                policy_key_free(policy_key_xml->policy_key);
                            }
                            free(policy_key_xml);
                            policy_key_xml = policy_keys_xml;
                        }
                        continue;
                    }

                    /*
                     * Cleanup the lists
                     */
                    policy_key_db = policy_keys_db;
                    while (policy_key_db) {
                        policy_keys_db = policy_key_db->next;
                        if (policy_key_db->policy_key) {
                            policy_key_free(policy_key_db->policy_key);
                        }
                        free(policy_key_db);
                        policy_key_db = policy_keys_db;
                    }
                    policy_key_xml = policy_keys_xml;
                    while (policy_key_xml) {
                        policy_keys_xml = policy_key_xml->next;
                        if (policy_key_xml->policy_key) {
                            policy_key_free(policy_key_xml->policy_key);
                        }
                        free(policy_key_xml);
                        policy_key_xml = policy_keys_xml;
                    }

                    /*
                     * Update the policy in the database
                     */
                    if (updated) {
                        if (policy_update(policy)) {
                            client_printf_err(sockfd,
                                "Unable to update policy %s in database!\n",
                                (char*)policy_name);
                            policy_free(policy);
                            xmlFree(policy_name);
                            database_error = 1;
                            continue;
                        }

                        client_printf(sockfd,
                            "Updated policy %s successfully\n",
                            (char*)policy_name);
                    }
                    else if (keys_updated) {
                        client_printf(sockfd,
                            "Updated policy %s successfully\n",
                            (char*)policy_name);
                    }
                    else {
                        client_printf(sockfd,
                            "Policy %s already up-to-date\n",
                            (char*)policy_name);
                    }
                }
                policy_free(policy);
                xmlFree(policy_name);
            }
        }
    }

    if (database_error) {
        database_error_help(sockfd);
    }

    xmlFreeDoc(doc);
    return 1;
}

static struct cmd_func_block funcblock = {
    "update kasp", &usage, &help, &handles, &run
};

struct cmd_func_block*
update_kasp_funcblock(void)
{
    return &funcblock;
}
