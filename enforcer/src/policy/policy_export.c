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
#include "db/policy_key.h"
#include "utils/kc_helper.h"

#include "policy/policy_export.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define POLICY_EXPORT_MAX_LENGHT 1000

static int __free(char **p) {
    if (!p || !*p) {
        return 1;
    }
    free(*p);
    *p = NULL;
    return 0;
}

static int __policy_export(int sockfd, const policy_t* policy, xmlNodePtr root) {
    xmlNodePtr node;
    xmlNodePtr node2;
    xmlNodePtr node3;
    xmlNodePtr node4;
    xmlNodePtr node5;
    xmlNodePtr keys;
    int error;
    duration_type* duration;
    char* duration_text = NULL;
    char text[1024];
    policy_key_list_t* policy_key_list;
    const policy_key_t* policy_key;

    if (!(duration = duration_create())) {
        client_printf_err(sockfd, "Unable to export KASP XML, memory allocation error!\n");
        return POLICY_EXPORT_ERR_MEMORY;
    }

    error = 1;
    if (!(node = xmlNewChild(root, NULL, (xmlChar*)"Policy", NULL))
        || !(error = 2)
        || !xmlNewProp(node, (xmlChar*)"name", (xmlChar*)policy_name(policy))
        || !(error = 3)
        || !xmlNewChild(node, NULL, (xmlChar*)"Description", (xmlChar*)policy_description(policy))

        || !(error = 4)
        || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Signatures", NULL))
        || !(error = 5)
        || duration_set_time(duration, policy_signatures_resign(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Resign", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 6)
        || duration_set_time(duration, policy_signatures_refresh(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Refresh", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 7)
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Validity", NULL))
        || !(error = 8)
        || duration_set_time(duration, policy_signatures_validity_default(policy))
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Default", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 9)
        || duration_set_time(duration, policy_signatures_validity_denial(policy))
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Denial", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 10)
        || !( policy_signatures_validity_keyset(policy) == 0 ||
             !(duration_set_time(duration, policy_signatures_validity_keyset(policy))
               || !(duration_text = duration2string(duration))
               || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Keyset", (xmlChar*)duration_text))
               || __free(&duration_text)
               || !(error = 10)))
        || duration_set_time(duration, policy_signatures_jitter(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Jitter", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 11)
        || duration_set_time(duration, policy_signatures_inception_offset(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"InceptionOffset", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 12)
        || (policy_signatures_max_zone_ttl(policy)
            && (duration_set_time(duration, policy_signatures_max_zone_ttl(policy))
                || !(duration_text = duration2string(duration))
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"MaxZoneTTL", (xmlChar*)duration_text))
                || __free(&duration_text)))

        || !(error = 13)
        || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Denial", NULL))
        || !(error = 14)
        || (policy_denial_type(policy) == POLICY_DENIAL_TYPE_NSEC
            && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"NSEC", NULL)))
        || !(error = 15)
        || (policy_denial_type(policy) == POLICY_DENIAL_TYPE_NSEC3
            && (!(node3 = xmlNewChild(node2, NULL, (xmlChar*)"NSEC3", NULL))
                || !(error = 16)
                || (policy_denial_ttl(policy)
                    && (duration_set_time(duration, policy_denial_ttl(policy))
                        || !(duration_text = duration2string(duration))
                        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
                        || __free(&duration_text)))
                || !(error = 17)
                || (policy_denial_optout(policy)
                    && !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"OptOut", NULL)))
                || !(error = 18)
		|| (policy_denial_resalt(policy)
		    && (duration_set_time(duration, policy_denial_resalt(policy))
		    || !(duration_text = duration2string(duration))
		    || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Resalt", (xmlChar*)duration_text))
		    || __free(&duration_text)))
		|| !(error = 19)
                || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Hash", NULL))
                || !(error = 20)
                || snprintf(text, sizeof(text), "%u", policy_denial_algorithm(policy)) >= (int)sizeof(text)
                || !(node5 = xmlNewChild(node4, NULL, (xmlChar*)"Algorithm", (xmlChar*)text))
                || !(error = 21)
                || snprintf(text, sizeof(text), "%u", policy_denial_iterations(policy)) >= (int)sizeof(text)
                || !(node5 = xmlNewChild(node4, NULL, (xmlChar*)"Iterations", (xmlChar*)text))
                || !(error = 22)
                || !(node5 = xmlNewChild(node4, NULL, (xmlChar*)"Salt", NULL))
                || !(error = 23)
                || snprintf(text, sizeof(text), "%u", policy_denial_salt_length(policy)) >= (int)sizeof(text)
                || !xmlNewProp(node5, (xmlChar*)"length", (xmlChar*)text)))

        || !(error = 24)
        || !(keys = xmlNewChild(node, NULL, (xmlChar*)"Keys", NULL))
        || !(error = 25)
        || duration_set_time(duration, policy_keys_ttl(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(keys, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 26)
        || duration_set_time(duration, policy_keys_retire_safety(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(keys, NULL, (xmlChar*)"RetireSafety", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 27)
        || duration_set_time(duration, policy_keys_publish_safety(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(keys, NULL, (xmlChar*)"PublishSafety", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 28)
        || (policy_keys_shared(policy)
            && !(node3 = xmlNewChild(keys, NULL, (xmlChar*)"ShareKeys", NULL)))
        || !(error = 29)
        || (policy_keys_purge_after(policy)
            && (duration_set_time(duration, policy_keys_purge_after(policy))
                || !(duration_text = duration2string(duration))
                || !(node3 = xmlNewChild(keys, NULL, (xmlChar*)"Purge", (xmlChar*)duration_text))
                || __free(&duration_text)))

        || !(error = 30)
        || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Zone", NULL))
        || !(error = 31)
        || duration_set_time(duration, policy_zone_propagation_delay(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"PropagationDelay", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 32)
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"SOA", NULL))
        || !(error = 33)
        || duration_set_time(duration, policy_zone_soa_ttl(policy))
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 34)
        || duration_set_time(duration, policy_zone_soa_minimum(policy))
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Minimum", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 35)
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Serial", (xmlChar*)policy_zone_soa_serial_text(policy)))

        || !(error = 36)
        || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Parent", NULL))
        || !(error = 37)
	|| (policy_parent_registration_delay(policy)
	    && (duration_set_time(duration, policy_parent_registration_delay(policy))
                || !(duration_text = duration2string(duration))
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"RegistrationDelay", (xmlChar*)duration_text))
                || __free(&duration_text)))
        || !(error = 38)
        || duration_set_time(duration, policy_parent_propagation_delay(policy))
        || !(duration_text = duration2string(duration))
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"PropagationDelay", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 39)
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"DS", NULL))
        || !(error = 40)
        || duration_set_time(duration, policy_parent_ds_ttl(policy))
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 41)
        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"SOA", NULL))
        || !(error = 42)
        || duration_set_time(duration, policy_parent_soa_ttl(policy))
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"TTL", (xmlChar*)duration_text))
        || __free(&duration_text)
        || !(error = 43)
        || duration_set_time(duration, policy_parent_soa_minimum(policy))
        || !(duration_text = duration2string(duration))
        || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Minimum", (xmlChar*)duration_text))
        || __free(&duration_text)
        )
    {
        client_printf_err(sockfd, "Unable to create XML elements, error code %d!\n", error);
        __free(&duration_text);
        return POLICY_EXPORT_ERR_XML;
    }
    __free(&duration_text);

    if (!(policy_key_list = policy_get_policy_keys(policy))) {
        return POLICY_EXPORT_ERR_DATABASE;
    }

    for (policy_key = policy_key_list_next(policy_key_list); policy_key; policy_key = policy_key_list_next(policy_key_list)) {
        switch (policy_key_role(policy_key)) {
        case POLICY_KEY_ROLE_ZSK:
            error = 100;
            if (!(node2 = xmlNewChild(keys, NULL, (xmlChar*)"ZSK", NULL))
                || !(error = 101)
                || snprintf(text, sizeof(text), "%u", policy_key_algorithm(policy_key)) >= (int)sizeof(text)
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Algorithm", (xmlChar*)text))
                || !(error = 102)
                || snprintf(text, sizeof(text), "%u", policy_key_bits(policy_key)) >= (int)sizeof(text)
                || !xmlNewProp(node3, (xmlChar*)"length", (xmlChar*)text)
                || !(error = 103)
                || duration_set_time(duration, policy_key_lifetime(policy_key))
                || !(duration_text = duration2string(duration))
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Lifetime", (xmlChar*)duration_text))
                || __free(&duration_text)
                || !(error = 104)
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Repository", (xmlChar*)policy_key_repository(policy_key)))
                || !(error = 105)
                || (policy_key_standby(policy_key) != -1
                    && (snprintf(text, sizeof(text), "%u", policy_key_standby(policy_key)) >= (int)sizeof(text)
                        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Standby", (xmlChar*)text))))
                || !(error = 106)
                || (policy_key_manual_rollover(policy_key)
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"ManualRollover", NULL)))
                || !(error = 107)
                || (policy_key_minimize(policy_key) == POLICY_KEY_MINIMIZE_NONE
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"ZskRollType", (xmlChar*)"ZskDoubleSignature")))
                || !(error = 108)
                || (policy_key_minimize(policy_key) == POLICY_KEY_MINIMIZE_RRSIG
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"ZskRollType", (xmlChar*)"ZskPrePublication")))
                || !(error = 109)
                || (policy_key_minimize(policy_key) == POLICY_KEY_MINIMIZE_DNSKEY
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"ZskRollType", (xmlChar*)"ZskDoubleRRsig")))
                )
            {
                client_printf_err(sockfd, "Unable to create XML elements, error code %d!\n", error);
                __free(&duration_text);
                return POLICY_EXPORT_ERR_XML;
            }
            __free(&duration_text);
            break;

        case POLICY_KEY_ROLE_KSK:
            error = 200;
            if (!(node2 = xmlNewChild(keys, NULL, (xmlChar*)"KSK", NULL))
                || !(error = 201)
                || snprintf(text, sizeof(text), "%u", policy_key_algorithm(policy_key)) >= (int)sizeof(text)
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Algorithm", (xmlChar*)text))
                || !(error = 202)
                || snprintf(text, sizeof(text), "%u", policy_key_bits(policy_key)) >= (int)sizeof(text)
                || !xmlNewProp(node3, (xmlChar*)"length", (xmlChar*)text)
                || !(error = 203)
                || duration_set_time(duration, policy_key_lifetime(policy_key))
                || !(duration_text = duration2string(duration))
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Lifetime", (xmlChar*)duration_text))
                || __free(&duration_text)
                || !(error = 204)
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Repository", (xmlChar*)policy_key_repository(policy_key)))
                || !(error = 205)
                || (policy_key_standby(policy_key) != -1
                    && (snprintf(text, sizeof(text), "%u", policy_key_standby(policy_key)) >= (int)sizeof(text)
                        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Standby", (xmlChar*)text))))
                || !(error = 206)
                || (policy_key_manual_rollover(policy_key)
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"ManualRollover", NULL)))
                || !(error = 207)
                || (policy_key_minimize(policy_key) == POLICY_KEY_MINIMIZE_NONE
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"KskRollType", (xmlChar*)"KskDoubleRRset")))
                || !(error = 208)
                || (policy_key_minimize(policy_key) == POLICY_KEY_MINIMIZE_DNSKEY
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"KskRollType", (xmlChar*)"KskDoubleDS")))
                || !(error = 209)
                || (policy_key_minimize(policy_key) == POLICY_KEY_MINIMIZE_DS
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"KskRollType", (xmlChar*)"KskDoubleSignature")))
                || !(error = 210)
                || (policy_key_rfc5011(policy_key)
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"RFC5011", NULL)))
                )
            {
                client_printf_err(sockfd, "Unable to create XML elements, error code %d!\n", error);
                __free(&duration_text);
                return POLICY_EXPORT_ERR_XML;
            }
            __free(&duration_text);
            break;

        case POLICY_KEY_ROLE_CSK:
            error = 300;
            if (!(node2 = xmlNewChild(keys, NULL, (xmlChar*)"CSK", NULL))
                || !(error = 301)
                || snprintf(text, sizeof(text), "%u", policy_key_algorithm(policy_key)) >= (int)sizeof(text)
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Algorithm", (xmlChar*)text))
                || !(error = 302)
                || snprintf(text, sizeof(text), "%u", policy_key_bits(policy_key)) >= (int)sizeof(text)
                || !xmlNewProp(node3, (xmlChar*)"length", (xmlChar*)text)
                || !(error = 303)
                || duration_set_time(duration, policy_key_lifetime(policy_key))
                || !(duration_text = duration2string(duration))
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Lifetime", (xmlChar*)duration_text))
                || __free(&duration_text)
                || !(error = 304)
                || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Repository", (xmlChar*)policy_key_repository(policy_key)))
                || !(error = 305)
                || (policy_key_standby(policy_key)
                    && (snprintf(text, sizeof(text), "%u", policy_key_standby(policy_key)) >= (int)sizeof(text)
                        || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Standby", (xmlChar*)text))))
                || !(error = 306)
                || (policy_key_manual_rollover(policy_key)
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"ManualRollover", NULL)))
                || !(error = 307)
                || (policy_key_minimize(policy_key) == POLICY_KEY_MINIMIZE_NONE
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"CskRollType", (xmlChar*)"CskDoubleRRset")))
                || !(error = 308)
                || (policy_key_minimize(policy_key) == POLICY_KEY_MINIMIZE_RRSIG
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"CskRollType", (xmlChar*)"CskSingleSignature")))
                || !(error = 309)
                || (policy_key_minimize(policy_key) == POLICY_KEY_MINIMIZE_DNSKEY
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"CskRollType", (xmlChar*)"CskDoubleDS")))
                || !(error = 310)
                || (policy_key_minimize(policy_key) == POLICY_KEY_MINIMIZE_DS
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"CskRollType", (xmlChar*)"CskDoubleSignature")))
                || !(error = 311)
                || (policy_key_minimize(policy_key) == POLICY_KEY_MINIMIZE_DS_AND_RRSIG
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"CskRollType", (xmlChar*)"CskPrePublication")))
                || !(error = 312)
                || (policy_key_rfc5011(policy_key)
                    && !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"RFC5011", NULL)))
                )
            {
                client_printf_err(sockfd, "Unable to create XML elements, error code %d!\n", error);
                __free(&duration_text);
                return POLICY_EXPORT_ERR_XML;
            }
            __free(&duration_text);
            break;

        default:
            policy_key_list_free(policy_key_list);
            return POLICY_EXPORT_ERR_DATABASE;
        }
    }
    policy_key_list_free(policy_key_list);

    return POLICY_EXPORT_OK;
}

int policy_export_all(int sockfd, const db_connection_t* connection, const char* filename) {
    policy_list_t* policy_list;
    const policy_t* policy;
    xmlDocPtr doc;
    xmlNodePtr root = NULL;
    int ret;
    char path[PATH_MAX];
    xmlChar* xml = NULL;
    char* xml_out;
    int xml_length = 0;
    int xml_write;
    char* dirname, *dirlast;

    if (!connection) {
        return POLICY_EXPORT_ERR_ARGS;
    }

    if (filename) {
        if (access(filename, W_OK)) {
            if (errno == ENOENT) {
                if ((dirname = strdup(filename))) {
                    if ((dirlast = strrchr(dirname, '/'))) {
                        *dirlast = 0;
                        if (access(dirname, W_OK)) {
                            client_printf_err(sockfd, "Write access to directory denied: %s\n", strerror(errno));
                            free(dirname);
                            return POLICY_EXPORT_ERR_FILE;
                        }
                    }
                    free(dirname);
                }
            }
            else {
                client_printf_err(sockfd, "Write access to file denied!\n");
                return POLICY_EXPORT_ERR_FILE;
            }
        }

        if (snprintf(path, sizeof(path), "%s.new", filename) >= (int)sizeof(path)) {
            client_printf_err(sockfd, "Unable to write XML to %s, path to long!\n", filename);
            return POLICY_EXPORT_ERR_MEMORY;
        }
    }

    if (!(doc = xmlNewDoc((xmlChar*)"1.0"))
        || !(root = xmlNewNode(NULL, (xmlChar*)"KASP")))
    {
        client_printf_err(sockfd, "Unable to create XML elements, memory allocation error!\n");
        if (doc) {
            xmlFreeDoc(doc);
        }
        return POLICY_EXPORT_ERR_MEMORY;
    }

    xmlDocSetRootElement(doc, root);

    if (!(policy_list = policy_list_new(connection))
        || policy_list_get(policy_list))
    {
        xmlFreeDoc(doc);
        if (policy_list) {
            policy_list_free(policy_list);
            return POLICY_EXPORT_ERR_DATABASE;
        }
        return POLICY_EXPORT_ERR_MEMORY;
    }

    for (policy = policy_list_next(policy_list); policy; policy = policy_list_next(policy_list)) {
        ret = __policy_export(sockfd, policy, root);
        if (ret != POLICY_EXPORT_OK) {
            policy_list_free(policy_list);
            xmlFreeDoc(doc);
            return ret;
        }
    }
    policy_list_free(policy_list);

    if (filename) {
        unlink(path);
        if (xmlSaveFormatFileEnc(path, doc, "UTF-8", 1) == -1) {
            client_printf_err(sockfd, "Unable to write policy, LibXML error!\n");
            xmlFreeDoc(doc);
            return POLICY_EXPORT_ERR_FILE;
        }
        xmlFreeDoc(doc);

        if (check_kasp(path, NULL, 0, 0, NULL, NULL)) {
            client_printf_err(sockfd, "Unable to validate the exported policy XML!\n");
            unlink(path);
            return POLICY_EXPORT_ERR_XML;
        }

        if (rename(path, filename)) {
            client_printf_err(sockfd, "Unable to write policy, rename failed!\n");
            unlink(path);
            return POLICY_EXPORT_ERR_FILE;
        }
    }
    else {
        xmlDocDumpFormatMemoryEnc(doc, &xml, &xml_length, "UTF-8", 1);
        xmlFreeDoc(doc);
        if (xml && xml_length) {
            for (xml_out = (char*)xml, xml_write = xml_length; xml_write > POLICY_EXPORT_MAX_LENGHT; xml_write -= POLICY_EXPORT_MAX_LENGHT, xml_out += POLICY_EXPORT_MAX_LENGHT) {
                client_printf(sockfd, "%.*s", POLICY_EXPORT_MAX_LENGHT, xml_out);
            }
            if (xml_write) {
                client_printf(sockfd, "%.*s", xml_write, xml_out);
            }
            xmlFree(xml);
        }
        else {
            client_printf_err(sockfd, "Unable to create policy XML, LibXML error!\n");
            return POLICY_EXPORT_ERR_XML;
        }
    }

    return POLICY_EXPORT_OK;
}

int policy_export(int sockfd, const policy_t* policy, const char* filename) {
    xmlDocPtr doc;
    xmlNodePtr root = NULL;
    int ret;
    char path[PATH_MAX];
    xmlChar* xml = NULL;
    char* xml_out;
    int xml_length = 0;
    int xml_write;
    char* dirname, *dirlast;

    if (!policy) {
        return POLICY_EXPORT_ERR_ARGS;
    }

    if (filename) {
        if (access(filename, W_OK)) {
            if (errno == ENOENT) {
                if ((dirname = strdup(filename))) {
                    if ((dirlast = strrchr(dirname, '/'))) {
                        *dirlast = 0;
                        if (access(dirname, W_OK)) {
                            client_printf_err(sockfd, "Write access to directory denied: %s\n", strerror(errno));
                            free(dirname);
                            return POLICY_EXPORT_ERR_FILE;
                        }
                    }
                    free(dirname);
                }
            }
            else {
                client_printf_err(sockfd, "Write access to file denied!\n");
                return POLICY_EXPORT_ERR_FILE;
            }
        }

        if (snprintf(path, sizeof(path), "%s.new", filename) >= (int)sizeof(path)) {
            client_printf_err(sockfd, "Unable to write XML to %s, path to long!\n", filename);
            return POLICY_EXPORT_ERR_MEMORY;
        }
    }

    if (!(doc = xmlNewDoc((xmlChar*)"1.0"))
        || !(root = xmlNewNode(NULL, (xmlChar*)"KASP")))
    {
        client_printf_err(sockfd, "Unable to create XML elements, memory allocation error!\n");
        if (doc) {
            xmlFreeDoc(doc);
        }
        return POLICY_EXPORT_ERR_MEMORY;
    }

    xmlDocSetRootElement(doc, root);

    ret = __policy_export(sockfd, policy, root);
    if (ret != POLICY_EXPORT_OK) {
        xmlFreeDoc(doc);
        return ret;
    }

    if (filename) {
        unlink(path);
        if (xmlSaveFormatFileEnc(path, doc, "UTF-8", 1) == -1) {
            client_printf_err(sockfd, "Unable to write policy, LibXML error!\n");
            xmlFreeDoc(doc);
            return POLICY_EXPORT_ERR_FILE;
        }
        xmlFreeDoc(doc);

        if (check_kasp(path, NULL, 0, 0, NULL, NULL)) {
            client_printf_err(sockfd, "Unable to validate the exported policy XML!\n");
            unlink(path);
            return POLICY_EXPORT_ERR_XML;
        }

        if (rename(path, filename)) {
            client_printf_err(sockfd, "Unable to write policy, rename failed!\n");
            unlink(path);
            return POLICY_EXPORT_ERR_FILE;
        }
    }
    else {
        xmlDocDumpFormatMemoryEnc(doc, &xml, &xml_length, "UTF-8", 1);
        xmlFreeDoc(doc);
        if (xml && xml_length) {
            for (xml_out = (char*)xml, xml_write = xml_length; xml_write > POLICY_EXPORT_MAX_LENGHT; xml_write -= POLICY_EXPORT_MAX_LENGHT, xml_out += POLICY_EXPORT_MAX_LENGHT) {
                client_printf(sockfd, "%.*s", POLICY_EXPORT_MAX_LENGHT, xml_out);
            }
            if (xml_write) {
                client_printf(sockfd, "%.*s", xml_write, xml_out);
            }
            xmlFree(xml);
        }
        else {
            client_printf_err(sockfd, "Unable to create policy XML, LibXML error!\n");
            return POLICY_EXPORT_ERR_XML;
        }
    }

    return POLICY_EXPORT_OK;
}
