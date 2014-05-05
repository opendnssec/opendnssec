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

#include "policy/update_kasp_cmd.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

static const char *module_str = "update_kasp_cmd";

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
    xmlChar* policy_name;
    policy_t* policy;
    int updated;

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
        client_printf_err(sockfd, "Unable to read KASP XML file %s\n", engine->config->policy_filename);
        return 1;
    }

    if (!(root = xmlDocGetRootElement(doc))) {
        client_printf_err(sockfd, "Unable to get the root element in the KASP XML\n");
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
                    client_printf_err(sockfd, "Invalid Policy element in KASP XML\n");
                    xmlFreeDoc(doc);
                    return 1;
                }

                client_printf(sockfd, "Policy %s\n", (char*)policy_name);
                if (!(policy = policy_new(dbconn))) {
                    client_printf_err(sockfd, "Memory allocation error\n");
                    xmlFree(policy_name);
                    xmlFreeDoc(doc);
                    return 1;
                }

                if (policy_get_by_name(policy, (char*)policy_name)) {
                    if (policy_create_from_xmlNode(policy, node)
                        || policy_create(policy))
                    {
                        client_printf_err(sockfd, "Unable to create policy %s in database\n", (char*)policy_name);
                        policy_free(policy);
                        xmlFree(policy_name);
                        xmlFreeDoc(doc);
                        return 1;
                    }

                    client_printf(sockfd, "Created policy %s\n", (char*)policy_name);
                }
                else {
                    if (policy_update_from_xmlNode(policy, node, &updated)) {
                        client_printf_err(sockfd, "Unable to update policy %s from XML\n", (char*)policy_name);
                        policy_free(policy);
                        xmlFree(policy_name);
                        xmlFreeDoc(doc);
                        return 1;
                    }

                    if (updated) {
                        if (policy_update(policy)) {
                            client_printf_err(sockfd, "Unable to update policy %s in database\n", (char*)policy_name);
                            policy_free(policy);
                            xmlFree(policy_name);
                            xmlFreeDoc(doc);
                            return 1;
                        }
                    }
                }
                policy_free(policy);
                xmlFree(policy_name);
            }
        }
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
