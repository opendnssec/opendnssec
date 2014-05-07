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

#include "policy_key.h"

#include "db_error.h"
#include "shared/duration.h"
#include "shared/log.h"

#include <string.h>

int policy_key_create_from_xml(policy_key_t* policy_key, xmlNodePtr key_node) {
    xmlNodePtr node;
    xmlChar* xml_text;
    duration_type* duration;
    int algorithm_length = 0;
    int standby = 0;
    int manual_rollover = 0;
    int rfc5011 = 0;
    int rolltype = 0;

    if (!policy_key) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_node) {
        return DB_ERROR_UNKNOWN;
    }

    if (!strcmp((char*)key_node->name, "KSK")) {
        ods_log_deeebug("[policy_key_*_from_xml] KSK");
        policy_key_set_role(policy_key, POLICY_KEY_ROLE_KSK);
    }
    else if (!strcmp((char*)key_node->name, "ZSK")) {
        ods_log_deeebug("[policy_key_*_from_xml] ZSK");
        policy_key_set_role(policy_key, POLICY_KEY_ROLE_ZSK);
    }
    else if (!strcmp((char*)key_node->name, "CSK")) {
        ods_log_deeebug("[policy_key_*_from_xml] CSK");
        policy_key_set_role(policy_key, POLICY_KEY_ROLE_CSK);
    }
    else {
        return DB_ERROR_UNKNOWN;
    }

    for (node = key_node->children; node; node = node->next) {
        if (node->type != XML_ELEMENT_NODE) {
            continue;
        }

        if (!strcmp((char*)node->name, "Algorithm")) {
            if ((xml_text = xmlGetProp(node, (xmlChar*)"length"))) {
                algorithm_length = 1;
                ods_log_deeebug("[policy_key_*_from_xml] algorithm length %s", (char*)xml_text);
                if (policy_key_set_bits(policy_key, (unsigned int)atoi((char*)xml_text))) {
                    xmlFree(xml_text);
                    return DB_ERROR_UNKNOWN;
                }
                xmlFree(xml_text);
            }
            if (!(xml_text = xmlNodeGetContent(node))) {
                return DB_ERROR_UNKNOWN;
            }
            ods_log_deeebug("[policy_key_*_from_xml] algorithm %s", (char*)xml_text);
            if (policy_key_set_algorithm(policy_key, (unsigned int)atoi((char*)xml_text))) {
                xmlFree(xml_text);
                return DB_ERROR_UNKNOWN;
            }
            xmlFree(xml_text);
        }
        else if (!strcmp((char*)node->name, "Lifetime")) {
            if (!(xml_text = xmlNodeGetContent(node))) {
                return DB_ERROR_UNKNOWN;
            }
            ods_log_deeebug("[policy_key_*_from_xml] lifetime %s", (char*)xml_text);
            if (!(duration = duration_create_from_string((char*)xml_text))) {
                xmlFree(xml_text);
                return DB_ERROR_UNKNOWN;
            }
            xmlFree(xml_text);
            if (policy_key_set_lifetime(policy_key, duration2time(duration))) {
                duration_cleanup(duration);
                return DB_ERROR_UNKNOWN;
            }
            duration_cleanup(duration);
        }
        else if (!strcmp((char*)node->name, "Repository")) {
            if (!(xml_text = xmlNodeGetContent(node))) {
                return DB_ERROR_UNKNOWN;
            }
            ods_log_deeebug("[policy_key_*_from_xml] repository %s", (char*)xml_text);
            if (policy_key_set_repository(policy_key, (char*)xml_text)) {
                xmlFree(xml_text);
                return DB_ERROR_UNKNOWN;
            }
            xmlFree(xml_text);
        }
        else if (!strcmp((char*)node->name, "Standby")) {
            standby = 1;
            if (!(xml_text = xmlNodeGetContent(node))) {
                return DB_ERROR_UNKNOWN;
            }
            ods_log_deeebug("[policy_key_*_from_xml] standby %s", (char*)xml_text);
            if (policy_key_set_standby(policy_key, (unsigned int)atoi((char*)xml_text))) {
                xmlFree(xml_text);
                return DB_ERROR_UNKNOWN;
            }
            xmlFree(xml_text);
        }
        else if (!strcmp((char*)node->name, "ManualRollover")) {
            manual_rollover = 1;
            ods_log_deeebug("[policy_key_*_from_xml] manual rollover");
            if (policy_key_set_manual_rollover(policy_key, 1)) {
                return DB_ERROR_UNKNOWN;
            }
        }
        else if (policy_key_role(policy_key) == POLICY_KEY_ROLE_KSK
            && !strcmp((char*)node->name, "KskRollType"))
        {
            rolltype = 1;
            if (!(xml_text = xmlNodeGetContent(node))) {
                return DB_ERROR_UNKNOWN;
            }
            ods_log_deeebug("[policy_key_*_from_xml] KSK rolltype %s", (char*)xml_text);
            if (!strcmp((char*)xml_text, "KskDoubleRRset")) {
                xmlFree(xml_text);
                if (policy_key_set_minimize(policy_key, POLICY_KEY_MINIMIZE_NONE)) {
                    return DB_ERROR_UNKNOWN;
                }
            }
            else if (!strcmp((char*)xml_text, "KskDoubleDS")) {
                xmlFree(xml_text);
                if (policy_key_set_minimize(policy_key, POLICY_KEY_MINIMIZE_DNSKEY)) {
                    return DB_ERROR_UNKNOWN;
                }
            }
            else if (!strcmp((char*)xml_text, "KskDoubleSignature")) {
                xmlFree(xml_text);
                if (policy_key_set_minimize(policy_key, POLICY_KEY_MINIMIZE_DS)) {
                    return DB_ERROR_UNKNOWN;
                }
            }
            else {
                xmlFree(xml_text);
                return DB_ERROR_UNKNOWN;
            }
        }
        else if (policy_key_role(policy_key) == POLICY_KEY_ROLE_ZSK
            && !strcmp((char*)node->name, "ZskRollType"))
        {
            rolltype = 1;
            if (!(xml_text = xmlNodeGetContent(node))) {
                return DB_ERROR_UNKNOWN;
            }
            ods_log_deeebug("[policy_key_*_from_xml] ZSK rolltype %s", (char*)xml_text);
            if (!strcmp((char*)xml_text, "ZskDoubleSignature")) {
                xmlFree(xml_text);
                if (policy_key_set_minimize(policy_key, POLICY_KEY_MINIMIZE_NONE)) {
                    return DB_ERROR_UNKNOWN;
                }
            }
            else if (!strcmp((char*)xml_text, "ZskPrePublication")) {
                xmlFree(xml_text);
                if (policy_key_set_minimize(policy_key, POLICY_KEY_MINIMIZE_RRSIG)) {
                    return DB_ERROR_UNKNOWN;
                }
            }
            else if (!strcmp((char*)xml_text, "ZskDoubleRRsig")) {
                xmlFree(xml_text);
                if (policy_key_set_minimize(policy_key, POLICY_KEY_MINIMIZE_DNSKEY)) {
                    return DB_ERROR_UNKNOWN;
                }
            }
            else {
                xmlFree(xml_text);
                return DB_ERROR_UNKNOWN;
            }
        }
        else if (policy_key_role(policy_key) == POLICY_KEY_ROLE_CSK
            && !strcmp((char*)node->name, "CskRollType"))
        {
            rolltype = 1;
            if (!(xml_text = xmlNodeGetContent(node))) {
                return DB_ERROR_UNKNOWN;
            }
            ods_log_deeebug("[policy_key_*_from_xml] CSK rolltype %s", (char*)xml_text);
            if (!strcmp((char*)xml_text, "CskDoubleRRset")) {
                xmlFree(xml_text);
                if (policy_key_set_minimize(policy_key, POLICY_KEY_MINIMIZE_NONE)) {
                    return DB_ERROR_UNKNOWN;
                }
            }
            else if (!strcmp((char*)xml_text, "CskSingleSignature")) {
                xmlFree(xml_text);
                if (policy_key_set_minimize(policy_key, POLICY_KEY_MINIMIZE_RRSIG)) {
                    return DB_ERROR_UNKNOWN;
                }
            }
            else if (!strcmp((char*)xml_text, "CskDoubleDS")) {
                xmlFree(xml_text);
                if (policy_key_set_minimize(policy_key, POLICY_KEY_MINIMIZE_DNSKEY)) {
                    return DB_ERROR_UNKNOWN;
                }
            }
            else if (!strcmp((char*)xml_text, "CskDoubleSignature")) {
                xmlFree(xml_text);
                if (policy_key_set_minimize(policy_key, POLICY_KEY_MINIMIZE_DS)) {
                    return DB_ERROR_UNKNOWN;
                }
            }
            else if (!strcmp((char*)xml_text, "CskPrePublication")) {
                xmlFree(xml_text);
                if (policy_key_set_minimize(policy_key, POLICY_KEY_MINIMIZE_DS_AND_RRSIG)) {
                    return DB_ERROR_UNKNOWN;
                }
            }
            else {
                xmlFree(xml_text);
                return DB_ERROR_UNKNOWN;
            }
        }
        else if ((policy_key_role(policy_key) == POLICY_KEY_ROLE_KSK
                || policy_key_role(policy_key) == POLICY_KEY_ROLE_CSK)
            && !strcmp((char*)node->name, "RFC5011"))
        {
            rfc5011 = 1;
            ods_log_deeebug("[policy_key_*_from_xml] rfc5011");
            if (policy_key_set_rfc5011(policy_key, 1)) {
                return DB_ERROR_UNKNOWN;
            }
        }
        else {
            return DB_ERROR_UNKNOWN;
        }
    }

    /*
     * If we did not find these XML elements we need to disable them
     */
    if (!algorithm_length) {
        ods_log_deeebug("[policy_key_*_from_xml] - algorithm length");
        if (policy_key_set_bits(policy_key, 0)) {
            return DB_ERROR_UNKNOWN;
        }
    }
    if (!standby) {
        ods_log_deeebug("[policy_key_*_from_xml] - standby");
        if (policy_key_set_standby(policy_key, 0)) {
            return DB_ERROR_UNKNOWN;
        }
    }
    if (!manual_rollover) {
        ods_log_deeebug("[policy_key_*_from_xml] - manual rollover");
        if (policy_key_set_manual_rollover(policy_key, 0)) {
            return DB_ERROR_UNKNOWN;
        }
    }
    if (!rolltype) {
        ods_log_deeebug("[policy_key_*_from_xml] - minimize");
        if (policy_key_set_minimize(policy_key, POLICY_KEY_MINIMIZE_NONE)) {
            return DB_ERROR_UNKNOWN;
        }
    }
    if ((policy_key_role(policy_key) == POLICY_KEY_ROLE_KSK
            || policy_key_role(policy_key) == POLICY_KEY_ROLE_CSK)
        && !rfc5011)
    {
        ods_log_deeebug("[policy_key_*_from_xml] - rfc5011");
        if (policy_key_set_rfc5011(policy_key, 0)) {
            return DB_ERROR_UNKNOWN;
        }
    }

    return DB_OK;
}
