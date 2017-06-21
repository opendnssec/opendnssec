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
#include "db/dbw.h"
#include "utils/kc_helper.h"

#include "signconf/signconf_xml.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <limits.h>
#include <unistd.h>

static int __free(char **p) {
    if (!p || !*p) {
        return 1;
    }
    free(*p);
    *p = NULL;
    return 0;
}

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
static int
signconf_xml_export(int sockfd, struct dbw_zone *zone, int force)
{
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
    int error;
    struct dbw_policy *policy = zone->policy;

    if (!force && !zone->signconf_needs_writing) return SIGNCONF_EXPORT_NO_CHANGE;

    if (snprintf(path, sizeof(path), "%s.new", zone->signconf_path) >= (int)sizeof(path)) {
        ods_log_error("[signconf_export] Unable to write updated XML for"
            " zone %s, path to long!", zone->name);
        if (sockfd > -1)
            client_printf_err(sockfd, "Unable to write updated XML for zone"
                " %s, path to long!\n", zone->name);
        return SIGNCONF_EXPORT_ERR_MEMORY;
    }

    if (!(duration = duration_create())) {
        ods_log_error("[signconf_export] Unable to process signconf for zone"
            " %s, memory allocation error!", zone->name);
        if (sockfd > -1)
            client_printf_err(sockfd, "Unable to process signconf for zone"
                " %s, memory allocation error!\n", zone->name);
        return SIGNCONF_EXPORT_ERR_MEMORY;
    }

    if (!(doc = xmlNewDoc((xmlChar*)"1.0"))
        || !(root = xmlNewNode(NULL, (xmlChar*)"SignerConfiguration"))
        || !(node = xmlNewChild(root, NULL, (xmlChar*)"Zone", NULL)))
    {
        ods_log_error("[signconf_export] Unable to create XML elements for"
            " zone %s, memory allocation error!", zone->name);
        if (sockfd > -1)
            client_printf_err(sockfd, "Unable to create XML elements for zone"
                " %s, memory allocation error!\n", zone->name);
        if (doc) xmlFreeDoc(doc);
        duration_cleanup(duration);
        return SIGNCONF_EXPORT_ERR_MEMORY;
    }

    xmlDocSetRootElement(doc, root);

    error = 1;
    if (!xmlNewProp(node, (xmlChar*)"name", (xmlChar*)zone->name)
        || !(error = 26)
        || (policy->passthrough && !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Passthrough", NULL)))
        || !(error = 2)
        || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Signatures", NULL))
        || !(error = 3)
        || duration_set_time(duration, policy->signatures_resign)
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Resign", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 4)
        || duration_set_time(duration, policy->signatures_refresh)
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Refresh", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 5)
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Validity", NULL))
        || !(error = 6)
        || duration_set_time(duration, policy->signatures_validity_default)
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Default", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 7)
        || duration_set_time(duration, policy->signatures_validity_denial)
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Denial", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 8)
        || (policy->signatures_validity_keyset > 0 ?
             duration_set_time(duration, policy->signatures_validity_keyset)
          || !(duration_text = duration2string(duration))
          || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Keyset", (xmlChar*)duration_text))
          || __free(&duration_text)
          || !(error = 100) : 0)
        || duration_set_time(duration, policy->signatures_jitter)
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Jitter", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 9)
        || duration_set_time(duration, policy->signatures_inception_offset)
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"InceptionOffset", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 10)
        || (policy->signatures_max_zone_ttl
            && (duration_set_time(duration, policy->signatures_max_zone_ttl)
                || !(duration_text = duration2string(duration))
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"MaxZoneTTL", (xmlChar*)duration_text))
                || __free(&duration_text)))

        || !(error = 11)
        || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Denial", NULL))
        || !(error = 12)
        || (policy->denial_type == POLICY_DENIAL_TYPE_NSEC
            && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"NSEC", NULL)))
        || !(error = 13)
        || (policy->denial_type == POLICY_DENIAL_TYPE_NSEC3
            && (!(node3 = xmlNewChild(node2, NULL, (xmlChar*)"NSEC3", NULL))
                || !(error = 14)
                || (policy->denial_ttl
                    && (duration_set_time(duration, policy->denial_ttl)
                        || !(duration_text = duration2string(duration))
                        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
                        || __free(&duration_text)))
                || !(error = 15)
                || (policy->denial_optout
                    && !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"OptOut", NULL)))
                || !(error = 16)
                || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Hash", NULL))
                || !(error = 17)
                || snprintf(text, sizeof(text), "%u", policy->denial_algorithm) >= (int)sizeof(text)
                || !(node5 = xmlNewChild(node4, NULL, (xmlChar*)"Algorithm", (xmlChar*)text))
                || !(error = 18)
                || snprintf(text, sizeof(text), "%u", policy->denial_iterations) >= (int)sizeof(text)
                || !(node5 = xmlNewChild(node4, NULL, (xmlChar*)"Iterations", (xmlChar*)text))
                || !(error = 19)
                || !(node5 = xmlNewChild(node4, NULL, (xmlChar*)"Salt", (xmlChar*)policy->denial_salt))))

        || !(error = 20)
        || !(keys = xmlNewChild(node, NULL, (xmlChar*)"Keys", NULL))
        || !(error = 21)
        || duration_set_time(duration, policy->keys_ttl)
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(keys, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
        || __free(&duration_text)

        || !(error = 22)
        || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"SOA", NULL))
        || !(error = 23)
        || duration_set_time(duration, policy->zone_soa_ttl)
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 24)
        || duration_set_time(duration, policy->zone_soa_minimum)
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Minimum", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 25)
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Serial", (xmlChar*)dbw_soa_serial_txt[policy->zone_soa_serial]))
        )
    {
        ods_log_error("[signconf_export] Unable to create XML elements for"
            " zone %s! [%d]", zone->name, error);
        if (sockfd > -1) client_printf_err(sockfd, "Unable to create XML"
            " elements for zone %s!\n", zone->name);
        __free(&duration_text);
        duration_cleanup(duration);
        xmlFreeDoc(doc);
        return SIGNCONF_EXPORT_ERR_XML;
    }
    __free(&duration_text);
    duration_cleanup(duration);

    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *key = zone->key[k];
        error = 100;
        if (!(node2 = xmlNewChild(keys, NULL, (xmlChar*)"Key", NULL))
            || !(error = 101)
            || (key->role == KEY_DATA_ROLE_ZSK
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Flags", (xmlChar*)"256")))
            || !(error = 102)
            || (key->role != KEY_DATA_ROLE_ZSK
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Flags", (xmlChar*)"257")))
            || !(error = 103)
            || snprintf(text, sizeof(text), "%u", key->algorithm) >= (int)sizeof(text)
            || !(error = 104)
            || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Algorithm", (xmlChar*)text))
            || !(error = 105)
            || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Locator",(xmlChar*)key->hsmkey->locator))
            || !(error = 106)
            || (key->active_ksk
                && (key->role | KEY_DATA_ROLE_KSK)
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"KSK", NULL)))
            || !(error = 107)
            || (key->active_zsk
                && (key->role | KEY_DATA_ROLE_ZSK)
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"ZSK", NULL)))
            || !(error = 108)
            || (key->publish
                && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Publish", NULL)))
            /* TODO:
             * What about <Deactivate/> ?
             */
            )
        {
            ods_log_error("[signconf_export] Unable to create key XML elements"
               " for zone %s! [%d]", zone->name, error);
            if (sockfd > -1)
                client_printf_err(sockfd, "Unable to create key XML elements"
                    " for zone %s!\n", zone->name);
            xmlFreeDoc(doc);
            return SIGNCONF_EXPORT_ERR_XML;
        }
    }

    unlink(path);
    if (xmlSaveFormatFileEnc(path, doc, "UTF-8", 1) == -1) {
        ods_log_error("[signconf_export] Unable to write signconf for zone "
            "%s, LibXML error!", zone->name);
        if (sockfd > -1)
            client_printf_err(sockfd, "Unable to write signconf for zone "
                "%s, LibXML error!\n", zone->name);
        xmlFreeDoc(doc);
        return SIGNCONF_EXPORT_ERR_FILE;
    }
    xmlFreeDoc(doc);

    if (check_rng(path, OPENDNSSEC_SCHEMA_DIR "/signconf.rng", 0)) {
        ods_log_error("[signconf_export] Unable to validate the exported "
            "signconf XML for zone %s!", zone->name);
        if (sockfd > -1)
            client_printf_err(sockfd, "Unable to validate the exported "
                "signconf XML for zone %s!\n", zone->name);
        return SIGNCONF_EXPORT_ERR_XML;
    }

    if (rename(path, zone->signconf_path)) {
        ods_log_error("[signconf_export] Unable to write signconf for zone "
            "%s, rename failed!", zone->name);
        if (sockfd > -1)
            client_printf_err(sockfd, "Unable to write signconf for zone %s, "
                "rename failed!\n", zone->name);
        unlink(path);
        return SIGNCONF_EXPORT_ERR_FILE;
    }

    zone->signconf_needs_writing = 0;
    dbw_mark_dirty((struct dbrow *)zone);

    return SIGNCONF_EXPORT_OK;
}

int
signconf_export_zone(char const *zonename, db_connection_t* dbconn)
{
    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) return SIGNCONF_EXPORT_ERR_DATABASE;
    struct dbw_zone *zone = dbw_get_zone(db, zonename);
    if (!zone) {
        ods_log_error("[signconf_export] Unable to fetch zone %s from"
            " database", zonename);
        return SIGNCONF_EXPORT_ERR_DATABASE;
    }
    /* We always force. Since now it is scheduled per zone */
    int ret = signconf_xml_export(-1, zone, 1);
    dbw_free(db);
    return ret;
}

int
signconf_export_all(int sockfd, db_connection_t* connection, int force)
{
    struct dbw_db *db = dbw_fetch(connection);
    if (!db) return SIGNCONF_EXPORT_ERR_DATABASE;
    int something_exported = 0;
    for (size_t z = 0; z < db->zones->n; z++) {
        struct dbw_zone *zone = (struct dbw_zone *)db->zones->set[z];
        int ret = signconf_xml_export(sockfd, zone, force);
        if (ret == SIGNCONF_EXPORT_OK) {
            something_exported = 1;
        } else if (ret != SIGNCONF_EXPORT_NO_CHANGE) {
            dbw_free(db);
            return ret;
        }
    }
    dbw_free(db);
    return something_exported ? SIGNCONF_EXPORT_OK : SIGNCONF_EXPORT_NO_CHANGE;
}

