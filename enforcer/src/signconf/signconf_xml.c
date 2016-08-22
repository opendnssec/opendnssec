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
#include "clientpipe.h"
#include "duration.h"
#include "db/key_data.h"
#include "db/hsm_key.h"
#include "utils/kc_helper.h"

#include "signconf/signconf_xml.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <limits.h>
#include <unistd.h>

/**
 * Export the signconf XML for the given zone that uses the given policy.
 * \param[in] sockfd a socket fd.
 * \param[in] policy a policy_t pointer.
 * \param[in] zone a zone_db_t pointer.
 * \param[in] force if non-zero it will force the export for all zones even if
 * there are no updates for the zones.
 * \return SIGNCONF_EXPORT_ERR_* on error, otherwise SIGNCONF_EXPORT_OK or
 * SIGNCONF_EXPORT_NO_CHANGE.
 */
static int signconf_xml_export(int sockfd, const policy_t* policy, zone_db_t* zone, int force);

int
signconf_export_zone(char const *zonename, db_connection_t* dbconn)
{
    zone_db_t* zone;
    int ret;
    policy_t* policy;

    zone = zone_db_new_get_by_name(dbconn, zonename);
    if (!zone) {
        ods_log_error("[signconf_export] Unable to fetch zone %s from"
            " database", zonename);
        return SIGNCONF_EXPORT_ERR_DATABASE;
    }
    policy = zone_db_get_policy(zone);
    if (!policy) {
        ods_log_error("[signconf_export] Unable to fetch policy for zone"
            " %s from database", zonename);
        zone_db_free(zone);
        return SIGNCONF_EXPORT_ERR_DATABASE;
    }

    /* We always force. Since now it is scheduled per zone */
    ret = signconf_xml_export(-1, policy, zone, 1);
    policy_free(policy);
    zone_db_free(zone);
    return ret;
}

int signconf_export_all(int sockfd, const db_connection_t* connection, int force) {
    zone_list_db_t* zone_list;
    zone_db_t* zone;
    int ret;
    policy_t *policy = NULL;
    int cmp;
    int change = 0;

    if (!connection) {
        return SIGNCONF_EXPORT_ERR_ARGS;
    }

    if (!(zone_list = zone_list_db_new(connection))
        || zone_list_db_get(zone_list))
    {
        if (zone_list) {
            zone_list_db_free(zone_list);
            return SIGNCONF_EXPORT_ERR_DATABASE;
        }
        return SIGNCONF_EXPORT_ERR_MEMORY;
    }

    for (zone = zone_list_db_get_next(zone_list); zone; zone = zone_list_db_get_next(zone_list)) {
        if (policy) {
            /*
             * If we already have a policy object; If policy_id compare fails
             * or if they are not the same, free the policy object so we will
             * later retrieve the correct policy
             */
            if (db_value_cmp(policy_id(policy), zone_db_policy_id(zone), &cmp)
                || cmp)
            {
                policy_free(policy);
                policy = NULL;
            }
        }
        if (!policy) {
            if (!(policy = zone_db_get_policy(zone))) {
                zone_db_free(zone);
                zone_list_db_free(zone_list);
                return SIGNCONF_EXPORT_ERR_DATABASE;
            }
        }

        ret = signconf_xml_export(sockfd, policy, zone, force);
        if (ret == SIGNCONF_EXPORT_OK) {
            change = 1;
        }
        else if (ret != SIGNCONF_EXPORT_NO_CHANGE) {
            zone_db_free(zone);
            zone_list_db_free(zone_list);
            return ret;
        }
        zone_db_free(zone);
    }
    policy_free(policy);
    zone_list_db_free(zone_list);

    if (change) {
        return SIGNCONF_EXPORT_OK;
    }
    return SIGNCONF_EXPORT_NO_CHANGE;
}

static int __free(char **p) {
    if (!p || !*p) {
        return 1;
    }
    free(*p);
    *p = NULL;
    return 0;
}

static int signconf_xml_export(int sockfd, const policy_t* policy, zone_db_t* zone, int force) {
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
    char* duration_text = NULL;
    char text[1024];
    key_data_list_t* key_data_list;
    const key_data_t* key_data;
    hsm_key_t* hsm_key;
    int error;

    if (!policy) {
        return SIGNCONF_EXPORT_ERR_ARGS;
    }
    if (!zone) {
        return SIGNCONF_EXPORT_ERR_ARGS;
    }

    if (!force && !zone_db_signconf_needs_writing(zone)) {
        return SIGNCONF_EXPORT_NO_CHANGE;
    }

    if (snprintf(path, sizeof(path), "%s.new", zone_db_signconf_path(zone)) >= (int)sizeof(path)) {
        ods_log_error("[signconf_export] Unable to write updated XML for zone %s, path to long!", zone_db_name(zone));
        if (sockfd > -1) client_printf_err(sockfd, "Unable to write updated XML for zone %s, path to long!\n", zone_db_name(zone));
        return SIGNCONF_EXPORT_ERR_MEMORY;
    }

    if (!(duration = duration_create())) {
        ods_log_error("[signconf_export] Unable to process signconf for zone %s, memory allocation error!", zone_db_name(zone));
        if (sockfd > -1) client_printf_err(sockfd, "Unable to process signconf for zone %s, memory allocation error!\n", zone_db_name(zone));
        return SIGNCONF_EXPORT_ERR_MEMORY;
    }

    if (!(doc = xmlNewDoc((xmlChar*)"1.0"))
        || !(root = xmlNewNode(NULL, (xmlChar*)"SignerConfiguration"))
        || !(node = xmlNewChild(root, NULL, (xmlChar*)"Zone", NULL)))
    {
        ods_log_error("[signconf_export] Unable to create XML elements for zone %s, memory allocation error!", zone_db_name(zone));
        if (sockfd > -1) client_printf_err(sockfd, "Unable to create XML elements for zone %s, memory allocation error!\n", zone_db_name(zone));
        if (doc) {
            xmlFreeDoc(doc);
        }
        duration_cleanup(duration);
        return SIGNCONF_EXPORT_ERR_MEMORY;
    }

    xmlDocSetRootElement(doc, root);

    error = 1;
    if (!xmlNewProp(node, (xmlChar*)"name", (xmlChar*)zone_db_name(zone))
        || !(error = 26)
        || (policy_passthrough(policy) && !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Passthrough", NULL)))
        || !(error = 2)
        || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Signatures", NULL))
        || !(error = 3)
        || duration_set_time(duration, policy_signatures_resign(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Resign", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 4)
        || duration_set_time(duration, policy_signatures_refresh(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Refresh", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 5)
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Validity", NULL))
        || !(error = 6)
        || duration_set_time(duration, policy_signatures_validity_default(policy))
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Default", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 7)
        || duration_set_time(duration, policy_signatures_validity_denial(policy))
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Denial", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 8)
        || (policy_signatures_validity_keyset(policy) > 0 ?
             duration_set_time(duration, policy_signatures_validity_keyset(policy))
          || !(duration_text = duration2string(duration))
          || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Keyset", (xmlChar*)duration_text))
          || __free(&duration_text)
          || !(error = 100) : 0)
        || duration_set_time(duration, policy_signatures_jitter(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Jitter", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 9)
        || duration_set_time(duration, policy_signatures_inception_offset(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"InceptionOffset", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 10)
        || (policy_signatures_max_zone_ttl(policy)
            && (duration_set_time(duration, policy_signatures_max_zone_ttl(policy))
                || !(duration_text = duration2string(duration))
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"MaxZoneTTL", (xmlChar*)duration_text))
                || __free(&duration_text)))

        || !(error = 11)
        || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Denial", NULL))
        || !(error = 12)
        || (policy_denial_type(policy) == POLICY_DENIAL_TYPE_NSEC
            && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"NSEC", NULL)))
        || !(error = 13)
        || (policy_denial_type(policy) == POLICY_DENIAL_TYPE_NSEC3
            && (!(node3 = xmlNewChild(node2, NULL, (xmlChar*)"NSEC3", NULL))
                || !(error = 14)
                || (policy_denial_ttl(policy)
                    && (duration_set_time(duration, policy_denial_ttl(policy))
                        || !(duration_text = duration2string(duration))
                        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
                        || __free(&duration_text)))
                || !(error = 15)
                || (policy_denial_optout(policy)
                    && !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"OptOut", NULL)))
                || !(error = 16)
                || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Hash", NULL))
                || !(error = 17)
                || snprintf(text, sizeof(text), "%u", policy_denial_algorithm(policy)) >= (int)sizeof(text)
                || !(node5 = xmlNewChild(node4, NULL, (xmlChar*)"Algorithm", (xmlChar*)text))
                || !(error = 18)
                || snprintf(text, sizeof(text), "%u", policy_denial_iterations(policy)) >= (int)sizeof(text)
                || !(node5 = xmlNewChild(node4, NULL, (xmlChar*)"Iterations", (xmlChar*)text))
                || !(error = 19)
                || !(node5 = xmlNewChild(node4, NULL, (xmlChar*)"Salt", (xmlChar*)policy_denial_salt(policy)))))

        || !(error = 20)
        || !(keys = xmlNewChild(node, NULL, (xmlChar*)"Keys", NULL))
        || !(error = 21)
        || duration_set_time(duration, policy_keys_ttl(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(keys, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
        || __free(&duration_text)

        || !(error = 22)
        || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"SOA", NULL))
        || !(error = 23)
        || duration_set_time(duration, policy_zone_soa_ttl(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 24)
        || duration_set_time(duration, policy_zone_soa_minimum(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Minimum", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 25)
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Serial", (xmlChar*)policy_zone_soa_serial_text(policy)))
        )
    {
        ods_log_error("[signconf_export] Unable to create XML elements for zone %s! [%d]", zone_db_name(zone), error);
        if (sockfd > -1) client_printf_err(sockfd, "Unable to create XML elements for zone %s!\n", zone_db_name(zone));
        __free(&duration_text);
        duration_cleanup(duration);
        xmlFreeDoc(doc);
        return SIGNCONF_EXPORT_ERR_XML;
    }
    __free(&duration_text);
    duration_cleanup(duration);

    if (!(key_data_list = zone_db_get_keys(zone))) {
        ods_log_error("[signconf_export] Unable to get keys for zone %s!", zone_db_name(zone));
        if (sockfd > -1) client_printf_err(sockfd, "Unable to get keys for zone %s!\n", zone_db_name(zone));
        xmlFreeDoc(doc);
        return SIGNCONF_EXPORT_ERR_DATABASE;
    }

    for (key_data = key_data_list_next(key_data_list); key_data; key_data = key_data_list_next(key_data_list)) {
        if (!(hsm_key = key_data_get_hsm_key(key_data))) {
            ods_log_error("[signconf_export] Unable to get HSM key from database for zone %s!", zone_db_name(zone));
            if (sockfd > -1) client_printf_err(sockfd, "Unable to get HSM key from database for zone %s!\n", zone_db_name(zone));
            key_data_list_free(key_data_list);
            xmlFreeDoc(doc);
            return SIGNCONF_EXPORT_ERR_DATABASE;
        }
        error = 100;
        if (!(node2 = xmlNewChild(keys, NULL, (xmlChar*)"Key", NULL))
            || !(error = 101)
            || (key_data_role(key_data) == KEY_DATA_ROLE_ZSK
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Flags", (xmlChar*)"256")))
            || !(error = 102)
            || (key_data_role(key_data) != KEY_DATA_ROLE_ZSK
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Flags", (xmlChar*)"257")))
            || !(error = 103)
            || snprintf(text, sizeof(text), "%u", key_data_algorithm(key_data)) >= (int)sizeof(text)
            || !(error = 104)
            || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Algorithm", (xmlChar*)text))
            || !(error = 105)
            || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Locator",(xmlChar*)hsm_key_locator(hsm_key)))
            || !(error = 106)
            || (key_data_active_ksk(key_data)
                && (key_data_role(key_data) == KEY_DATA_ROLE_KSK
                    || key_data_role(key_data) == KEY_DATA_ROLE_CSK)
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"KSK", NULL)))
            || !(error = 107)
            || (key_data_active_zsk(key_data)
                && (key_data_role(key_data) == KEY_DATA_ROLE_ZSK
                    || key_data_role(key_data) == KEY_DATA_ROLE_CSK)
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"ZSK", NULL)))
            || !(error = 108)
            || (key_data_publish(key_data)
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Publish", NULL)))
            /* TODO:
             * What about <Deactivate/> ?
             */
            )
        {
            ods_log_error("[signconf_export] Unable to create key XML elements for zone %s! [%d]", zone_db_name(zone), error);
            if (sockfd > -1) client_printf_err(sockfd, "Unable to create key XML elements for zone %s!\n", zone_db_name(zone));
            hsm_key_free(hsm_key);
            key_data_list_free(key_data_list);
            xmlFreeDoc(doc);
            return SIGNCONF_EXPORT_ERR_XML;
        }
        hsm_key_free(hsm_key);
    }
    key_data_list_free(key_data_list);

    unlink(path);
    if (xmlSaveFormatFileEnc(path, doc, "UTF-8", 1) == -1) {
        ods_log_error("[signconf_export] Unable to write signconf for zone %s, LibXML error!", zone_db_name(zone));
        if (sockfd > -1) client_printf_err(sockfd, "Unable to write signconf for zone %s, LibXML error!\n", zone_db_name(zone));
        xmlFreeDoc(doc);
        return SIGNCONF_EXPORT_ERR_FILE;
    }
    xmlFreeDoc(doc);

    if (check_rng(path, OPENDNSSEC_SCHEMA_DIR "/signconf.rng", 0)) {
        ods_log_error("[signconf_export] Unable to validate the exported signconf XML for zone %s!", zone_db_name(zone));
        if (sockfd > -1) client_printf_err(sockfd, "Unable to validate the exported signconf XML for zone %s!\n", zone_db_name(zone));
        return SIGNCONF_EXPORT_ERR_XML;
    }

    if (rename(path, zone_db_signconf_path(zone))) {
        ods_log_error("[signconf_export] Unable to write signconf for zone %s, rename failed!", zone_db_name(zone));
        if (sockfd > -1) client_printf_err(sockfd, "Unable to write signconf for zone %s, rename failed!\n", zone_db_name(zone));
        unlink(path);
        return SIGNCONF_EXPORT_ERR_FILE;
    }

    zone_db_set_signconf_needs_writing(zone, 0);
    zone_db_update(zone);

    return SIGNCONF_EXPORT_OK;
}
