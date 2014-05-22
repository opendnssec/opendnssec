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
#include "daemon/clientpipe.h"
#include "shared/duration.h"
#include "db/key_data.h"
#include "db/hsm_key.h"

#include "signconf/signconf.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <limits.h>
#include <unistd.h>

int signconf_export_all(int sockfd, engine_type* engine, db_connection_t* connection, int force) {
    zone_list_t* zone_list;
    const zone_t* zone;
    int ret;
    policy_t* policy = NULL;
    int cmp;
    int change = 0;

    if (!engine) {
        return SIGNCONF_EXPORT_ERR_ARGS;
    }
    if (!connection) {
        return SIGNCONF_EXPORT_ERR_ARGS;
    }

    if (!(zone_list = zone_list_new(connection))
        || zone_list_get(zone_list))
    {
        if (zone_list) {
            zone_list_free(zone_list);
            return SIGNCONF_EXPORT_ERR_DATABASE;
        }
        return SIGNCONF_EXPORT_ERR_MEMORY;
    }

    for (zone = zone_list_next(zone_list); zone; zone = zone_list_next(zone_list)) {
        if (policy) {
            /*
             * If we already have a policy object; If policy_id compare fails
             * or if they are not the same free the policy object to we will
             * later retrieve the correct policy
             */
            if (db_value_cmp(policy_id(policy), zone_policy_id(zone), &cmp)
                || cmp)
            {
                policy_free(policy);
                policy = NULL;
            }
        }
        if (!policy) {
            if (!(policy = zone_get_policy(zone))) {
                zone_list_free(zone_list);
                return SIGNCONF_EXPORT_ERR_DATABASE;
            }
        }

        ret = signconf_export(sockfd, engine, policy, zone, force);
        if (ret == SIGNCONF_EXPORT_OK) {
            change = 1;
        }
        else if (ret != SIGNCONF_EXPORT_NO_CHANGE) {
            zone_list_free(zone_list);
            return ret;
        }
    }
    zone_list_free(zone_list);

    if (change) {
        return SIGNCONF_EXPORT_OK;
    }
    return SIGNCONF_EXPORT_NO_CHANGE;
}

int signconf_export_policy(int sockfd, engine_type* engine, db_connection_t* connection, const policy_t* policy, int force) {
    zone_list_t* zone_list;
    const zone_t* zone;
    int ret;
    int change = 0;

    if (!engine) {
        return SIGNCONF_EXPORT_ERR_ARGS;
    }
    if (!connection) {
        return SIGNCONF_EXPORT_ERR_ARGS;
    }
    if (!policy) {
        return SIGNCONF_EXPORT_ERR_ARGS;
    }

    if (!(zone_list = zone_list_new(connection))
        || zone_list_get_by_policy_id(zone_list, policy_id(policy)))
    {
        if (zone_list) {
            zone_list_free(zone_list);
            return SIGNCONF_EXPORT_ERR_DATABASE;
        }
        return SIGNCONF_EXPORT_ERR_MEMORY;
    }

    for (zone = zone_list_next(zone_list); zone; zone = zone_list_next(zone_list)) {
        ret = signconf_export(sockfd, engine, policy, zone, force);
        if (ret == SIGNCONF_EXPORT_OK) {
            change = 1;
        }
        else if (ret != SIGNCONF_EXPORT_NO_CHANGE) {
            zone_list_free(zone_list);
            return ret;
        }
    }
    zone_list_free(zone_list);

    if (change) {
        return SIGNCONF_EXPORT_OK;
    }
    return SIGNCONF_EXPORT_NO_CHANGE;
}

static int __free(void *p) {
    if (!p) {
        return 1;
    }
    free(p);
    return 0;
}

int signconf_export(int sockfd, engine_type* engine, const policy_t* policy, const zone_t* zone, int force) {
    char path[PATH_MAX];
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr node;
    xmlNodePtr node2;
    xmlNodePtr node3;
    xmlNodePtr node4;
    xmlNodePtr node5;
    xmlNodePtr keys;
    duration_type* duration;
    char* duration_text;
    char text[1024];
    key_data_list_t* key_data_list;
    const key_data_t* key_data;
    hsm_key_t* hsm_key;

    if (!engine) {
        return SIGNCONF_EXPORT_ERR_ARGS;
    }
    if (!policy) {
        return SIGNCONF_EXPORT_ERR_ARGS;
    }
    if (!zone) {
        return SIGNCONF_EXPORT_ERR_ARGS;
    }

    if (!force && !zone_signconf_needs_writing(zone)) {
        return SIGNCONF_EXPORT_NO_CHANGE;
    }

    if (snprintf(path, sizeof(path), "%s.new", zone_signconf_path(zone)) >= (int)sizeof(path)) {
        client_printf_err(sockfd, "Unable to write updated XML, path to long!\n");
        return SIGNCONF_EXPORT_ERR_MEMORY;
    }

    if (!(duration = duration_create())) {
        client_printf_err(sockfd, "Memory allocation error!\n");
        return SIGNCONF_EXPORT_ERR_MEMORY;
    }

    if (!(doc = xmlNewDoc((xmlChar*)"1.0"))
        || !(root = xmlNewNode(NULL, (xmlChar*)"SignerConfiguration"))
        || !(node = xmlNewChild(root, NULL, (xmlChar*)"Zone", NULL)))
    {
        client_printf_err(sockfd, "Unable to create XML elements, memory allocation error!\n");
        if (doc) {
            xmlFreeDoc(doc);
        }
        duration_cleanup(duration);
        return SIGNCONF_EXPORT_ERR_MEMORY;
    }

    xmlDocSetRootElement(doc, root);

    if (!(node2 = xmlNewChild(node, NULL, (xmlChar*)"Signatures", NULL))
        || !(duration_set_time(duration, policy_signatures_resign(policy)))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Resign", (xmlChar*)duration_text))
        || __free(duration_text)
        || !(duration_set_time(duration, policy_signatures_refresh(policy)))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Refresh", (xmlChar*)duration_text))
        || __free(duration_text)
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Validity", NULL))
        || !(duration_set_time(duration, policy_signatures_validity_default(policy)))
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Default", (xmlChar*)duration_text))
        || __free(duration_text)
        || !(duration_set_time(duration, policy_signatures_validity_denial(policy)))
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Denial", (xmlChar*)duration_text))
        || __free(duration_text)
        || !(duration_set_time(duration, policy_signatures_jitter(policy)))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Jitter", (xmlChar*)duration_text))
        || __free(duration_text)
        || !(duration_set_time(duration, policy_signatures_inception_offset(policy)))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"InceptionOffset", (xmlChar*)duration_text))
        || __free(duration_text)
        || (policy_signatures_max_zone_ttl(policy)
            && (!(duration_set_time(duration, policy_signatures_max_zone_ttl(policy)))
                || !(duration_text = duration2string(duration))
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"MaxZoneTTL", (xmlChar*)duration_text))
                || __free(duration_text)))

        || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Denial", NULL))
        || (policy_denial_type(policy) == POLICY_DENIAL_TYPE_NSEC
            && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"NSEC", NULL)))
        || (policy_denial_type(policy) == POLICY_DENIAL_TYPE_NSEC3
            && (!(node3 = xmlNewChild(node2, NULL, (xmlChar*)"NSEC3", NULL))
                || (policy_denial_ttl(policy)
                    && (!(duration_set_time(duration, policy_denial_ttl(policy)))
                        || !(duration_text = duration2string(duration))
                        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
                        || __free(duration_text)))
                || (policy_denial_optout(policy)
                    && !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"OptOut", NULL)))
                || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Hash", NULL))
                || snprintf(text, sizeof(text), "%u", policy_denial_algorithm(policy)) >= (int)sizeof(text)
                || !(node5 = xmlNewChild(node4, NULL, (xmlChar*)"Algorithm", (xmlChar*)text))
                || snprintf(text, sizeof(text), "%u", policy_denial_iterations(policy)) >= (int)sizeof(text)
                || !(node5 = xmlNewChild(node4, NULL, (xmlChar*)"Iterations", (xmlChar*)text))
                || !(node5 = xmlNewChild(node4, NULL, (xmlChar*)"Salt", (xmlChar*)policy_denial_salt(policy)))))

        || !(keys = xmlNewChild(node, NULL, (xmlChar*)"Keys", NULL))
        || !(duration_set_time(duration, policy_keys_ttl(policy)))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(keys, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
        || __free(duration_text)

        || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"SOA", NULL))
        || !(duration_set_time(duration, policy_zone_soa_ttl(policy)))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
        || __free(duration_text)
        || !(duration_set_time(duration, policy_zone_soa_minimum(policy)))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Minimum", (xmlChar*)duration_text))
        || __free(duration_text)
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Serial", (xmlChar*)policy_zone_soa_serial_text(policy)))
        )
    {
        client_printf_err(sockfd, "Unable to create XML elements for zone %s!\n", zone_name(zone));
        xmlFreeDoc(doc);
        return SIGNCONF_EXPORT_ERR_XML;
    }

    if (!(key_data_list = zone_get_keys(zone))) {
        client_printf_err(sockfd, "Unable to get keys for zone %s!\n", zone_name(zone));
        xmlFreeDoc(doc);
        return SIGNCONF_EXPORT_ERR_DATABASE;
    }

    for (key_data = key_data_list_next(key_data_list); key_data; key_data = key_data_list_next(key_data_list)) {
        if (!(hsm_key = key_data_get_hsm_key(key_data))) {
            client_printf_err(sockfd, "Unable to get HSM key from database!\n");
            key_data_list_free(key_data_list);
            xmlFreeDoc(doc);
            return SIGNCONF_EXPORT_ERR_DATABASE;
        }
        if (!(node2 = xmlNewChild(keys, NULL, (xmlChar*)"Key", NULL))
            || (key_data_role(key_data) == KEY_DATA_ROLE_ZSK
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Flags", (xmlChar*)"256")))
            || (key_data_role(key_data) != KEY_DATA_ROLE_ZSK
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Flags", (xmlChar*)"257")))
            || snprintf(text, sizeof(text), "%u", key_data_algorithm(key_data)) >= (int)sizeof(text)
            || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Algorithm", (xmlChar*)text))
            || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Locator",(xmlChar*)hsm_key_locator(hsm_key)))
            || (key_data_active_ksk(key_data)
                && (key_data_role(key_data) == KEY_DATA_ROLE_KSK
                    || key_data_role(key_data) == KEY_DATA_ROLE_CSK)
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"KSK", NULL)))
            || (key_data_active_zsk(key_data)
                && (key_data_role(key_data) == KEY_DATA_ROLE_ZSK
                    || key_data_role(key_data) == KEY_DATA_ROLE_CSK)
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"ZSK", NULL)))
            || (key_data_publish(key_data)
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Publish", NULL)))
            /* TODO:
             * What about <Deactivate/> ?
             */
            )
        {
            client_printf_err(sockfd, "Unable to create key XML elements for zone %s!\n", zone_name(zone));
            hsm_key_free(hsm_key);
            key_data_list_free(key_data_list);
            xmlFreeDoc(doc);
            return SIGNCONF_EXPORT_ERR_XML;
        }
        hsm_key_free(hsm_key);
    }
    key_data_list_free(key_data_list);

    /* TODO: write and verify XML */

    return SIGNCONF_EXPORT_OK;
}
