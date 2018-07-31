/*
 * Copyright (c) 2009-2018 NLNet Labs.
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
 */

/**
 * Parsing signer configuration files.
 *
 */

#include "confparser.h"
#include "parser/signconfparser.h"
#include "duration.h"
#include "log.h"

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/xmlreader.h>
#include <stdlib.h>

static const char* parser_str = "parser";


/**
 * Parse keys from the signer configuration file.
 *
 */
keylist_type*
parse_sc_keys(void* sc, const char* cfgfile)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode* curNode = NULL;
    xmlChar* xexpr = NULL;
    key_type* new_key = NULL;
    keylist_type* kl = NULL;
    char* resourcerecord;
    char* locator;
    char* flags;
    char* algorithm;
    int configerr;
    int ksk, zsk, publish, i;

    if (!cfgfile || !sc) {
        return NULL;
    }
    /* Load XML document */
    doc = xmlParseFile(cfgfile);
    if (doc == NULL) {
        ods_log_error("[%s] unable to parse <Keys>: "
            "xmlParseFile() failed", parser_str);
        return NULL;
    }
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
        ods_log_error("[%s] unable to parse <Keys>: "
            "xmlXPathNewContext() failed", parser_str);
        return NULL;
    }
    /* Evaluate xpath expression */
    xexpr = (xmlChar*) "//SignerConfiguration/Zone/Keys/Key";
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        ods_log_error("[%s] unable to parse <Keys>: "
            "xmlXPathEvalExpression() failed", parser_str);
        return NULL;
    }
    /* Parse keys */
    kl = keylist_create(sc);
    ods_log_assert(kl);
    if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
            resourcerecord = NULL;
            locator = NULL;
            flags = NULL;
            algorithm = NULL;
            ksk = 0;
            zsk = 0;
            publish = 0;
            configerr = 0;

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Locator")) {
                    locator = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name, (const xmlChar *)"Algorithm")) {
                    algorithm = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name, (const xmlChar *)"Flags")) {
                    flags = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name, (const xmlChar *)"KSK")) {
                    ksk = 1;
                } else if (xmlStrEqual(curNode->name, (const xmlChar *)"ZSK")) {
                    zsk = 1;
                } else if (xmlStrEqual(curNode->name, (const xmlChar *)"Publish")) {
                    publish = 1;
                } else if (xmlStrEqual(curNode->name, (const xmlChar *)"ResourceRecord")) {
                    resourcerecord = (char *) xmlNodeGetContent(curNode);
                }
                curNode = curNode->next;
            }
            if (!algorithm)
                configerr = 1;
            if (!flags)
                configerr = 1;
            if (!locator && !resourcerecord)
                configerr = 1;
            if (!configerr) {
                /* search for duplicates */
                new_key = keylist_lookup_by_locator(kl, locator);
                if (new_key &&
                    new_key->algorithm == (uint8_t) atoi(algorithm) &&
                    new_key->flags == (uint32_t) atoi(flags) &&
                    new_key->publish == publish &&
                    new_key->ksk == ksk &&
                    new_key->zsk == zsk) {
                    /* duplicate */
                    ods_log_warning("[%s] unable to push duplicate key %s "
                        "to keylist, skipping", parser_str, locator);
                } else {
                    (void) keylist_push(kl, locator, resourcerecord,
                        (uint8_t) atoi(algorithm), (uint32_t) atoi(flags),
                        publish, ksk, zsk);
                }
            } else {
                ods_log_error("[%s] unable to push key to keylist: <Key> "
                    "is missing required elements, skipping",
                    parser_str);
            }
            free((void*)algorithm);
            free((void*)flags);
        }
    }
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    if (doc) {
        xmlFreeDoc(doc);
    }
    return kl;
}


/**
 * Parse elements from the configuration file.
 *
 */
duration_type*
parse_sc_sig_resign_interval(const char* cfgfile)
{
    duration_type* duration = NULL;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Signatures/Resign",
        1);
    if (!str) {
        return NULL;
    }
    duration = duration_create_from_string(str);
    free((void*)str);
    return duration;
}


duration_type*
parse_sc_sig_refresh_interval(const char* cfgfile)
{
    duration_type* duration = NULL;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Signatures/Refresh",
        1);
    if (!str) {
        return NULL;
    }
    duration = duration_create_from_string(str);
    free((void*)str);
    return duration;
}


duration_type*
parse_sc_sig_validity_default(const char* cfgfile)
{
    duration_type* duration = NULL;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Signatures/Validity/Default",
        1);
    if (!str) {
        return NULL;
    }
    duration = duration_create_from_string(str);
    free((void*)str);
    return duration;
}


duration_type*
parse_sc_sig_validity_denial(const char* cfgfile)
{
    duration_type* duration = NULL;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Signatures/Validity/Denial",
        1);
    if (!str) {
        return NULL;
    }
    duration = duration_create_from_string(str);
    free((void*)str);
    return duration;
}


duration_type*
parse_sc_sig_validity_keyset(const char* cfgfile)
{
    duration_type* duration = NULL;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Signatures/Validity/Keyset",
        0);
    /* Even if the value is 0 or NULL we want to write it in duration format. 
       The value is written in backup file and read during startup*/
    /*if (!str || *str == 0 || *str == '0') {
        return NULL;
    }*/
    duration = duration_create_from_string(str);
    free((void*)str);
    return duration;
}


duration_type*
parse_sc_sig_jitter(const char* cfgfile)
{
    duration_type* duration = NULL;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Signatures/Jitter",
        1);
    if (!str) {
        return NULL;
    }
    duration = duration_create_from_string(str);
    free((void*)str);
    return duration;
}


duration_type*
parse_sc_sig_inception_offset(const char* cfgfile)
{
    duration_type* duration = NULL;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Signatures/InceptionOffset",
        1);
    if (!str) {
        return NULL;
    }
    duration = duration_create_from_string(str);
    free((void*)str);
    return duration;
}


duration_type*
parse_sc_dnskey_ttl(const char* cfgfile)
{
    duration_type* duration = NULL;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Keys/TTL",
        1);
    if (!str) {
        return NULL;
    }
    duration = duration_create_from_string(str);
    free((void*)str);
    return duration;
}


const char**
parse_sc_dnskey_sigrrs(const char* cfgfile)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode* curNode = NULL;
    xmlChar* xexpr = NULL;
    const char **signatureresourcerecords;
    int i;

    if (!cfgfile) {
        return NULL;
    }
    /* Load XML document */
    doc = xmlParseFile(cfgfile);
    if (doc == NULL) {
        ods_log_error("[%s] unable to parse <Keys>: "
            "xmlParseFile() failed", parser_str);
        return NULL;
    }
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
        ods_log_error("[%s] unable to parse <Keys>: "
            "xmlXPathNewContext() failed", parser_str);
        return NULL;
    }
    /* Evaluate xpath expression */
    xexpr = (xmlChar*) "//SignerConfiguration/Zone/Keys/SignatureResourceRecord";
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        ods_log_error("[%s] unable to parse <Keys>: "
            "xmlXPathEvalExpression() failed", parser_str);
        return NULL;
    }
    /* Parse keys */
    if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
        signatureresourcerecords = malloc(sizeof(char*) * (xpathObj->nodesetval->nodeNr + 1));
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
            curNode = xpathObj->nodesetval->nodeTab[i];
            signatureresourcerecords[i] = (char *) xmlNodeGetContent(curNode);
        }
        signatureresourcerecords[i] = NULL;
    } else {
        signatureresourcerecords = NULL;
    }
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    if (doc) {
        xmlFreeDoc(doc);
    }
    return signatureresourcerecords;
}



duration_type*
parse_sc_nsec3param_ttl(const char* cfgfile)
{
    duration_type* duration = NULL;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Denial/NSEC3/TTL",
        0);
    if (!str) {
        return NULL;
    }
    duration = duration_create_from_string(str);
    free((void*)str);
    return duration;
}


duration_type*
parse_sc_soa_ttl(const char* cfgfile)
{
    duration_type* duration = NULL;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/SOA/TTL",
        1);
    if (!str) {
        return NULL;
    }
    duration = duration_create_from_string(str);
    free((void*)str);
    return duration;
}


duration_type*
parse_sc_soa_min(const char* cfgfile)
{
    duration_type* duration = NULL;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/SOA/Minimum",
        1);
    if (!str) {
        return NULL;
    }
    duration = duration_create_from_string(str);
    free((void*)str);
    return duration;
}


duration_type*
parse_sc_max_zone_ttl(const char* cfgfile)
{
    duration_type* duration = NULL;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Signatures/MaxZoneTTL",
        0);
    if (!str) {
        return NULL;
    }
    duration = duration_create_from_string(str);
    free((void*)str);
    return duration;
}


/**
 * Parse elements from the configuration file.
 *
 */
ldns_rr_type
parse_sc_nsec_type(const char* cfgfile)
{
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Denial/NSEC3",
        0);
    if (str) {
        free((void*)str);
        return LDNS_RR_TYPE_NSEC3;
    }
    str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Denial/NSEC",
        0);
    if (str) {
        free((void*)str);
        return LDNS_RR_TYPE_NSEC;
    }
    return LDNS_RR_TYPE_FIRST;
}


/**
 * Parse elements from the configuration file.
 *
 */
uint32_t
parse_sc_nsec3_algorithm(const char* cfgfile)
{
    int ret = 0;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Denial/NSEC3/Hash/Algorithm",
        1);
    if (str) {
        if (strlen(str) > 0) {
            ret = atoi(str);
        }
        free((void*)str);
    }
    return ret;
}


uint32_t
parse_sc_nsec3_iterations(const char* cfgfile)
{
    int ret = 0;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Denial/NSEC3/Hash/Iterations",
        1);
    if (str) {
        if (strlen(str) > 0) {
            ret = atoi(str);
        }
        free((void*)str);
    }
    return ret;
}


int
parse_sc_nsec3_optout(const char* cfgfile)
{
    int ret = 0;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Denial/NSEC3/OptOut",
        0);
    if (str) {
        ret = 1;
        free((void*)str);
    }
    return ret;
}

int
parse_sc_passthrough(const char* cfgfile)
{
    int ret = 0;
    const char* str = parse_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Passthrough",
        0);
    if (str) {
        ret = 1;
        free((void*)str);
    }
    return ret;
}

/**
 * Parse elements from the configuration file.
 *
 */
const char*
parse_sc_soa_serial(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(
        cfgfile,
        "//SignerConfiguration/Zone/SOA/Serial",
        1);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}


const char*
parse_sc_nsec3_salt(const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parse_conf_string(
        cfgfile,
        "//SignerConfiguration/Zone/Denial/NSEC3/Hash/Salt",
        1);

    if (str) {
        dup = strdup(str);
        free((void*)str);
    }
    return dup;
}
