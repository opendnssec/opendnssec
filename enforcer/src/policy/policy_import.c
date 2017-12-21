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
#include "utils/kc_helper.h"
#include "db/dbw.h"
#include "duration.h"
#include "hsmkey/hsm_key_factory.h"
#include "signconf/signconf_task.h"

#include "policy/policy_import.h"
#include "policy/policy_resalt_task.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

#define MAX_ZONE_TTL 86400

struct xml_policykey {
    char* repository;
    unsigned int role;
    unsigned int algorithm;
    unsigned int bits;
    unsigned int lifetime;
    unsigned int standby;
    unsigned int manual_rollover;
    unsigned int rfc5011;
    unsigned int minimize;
};

struct xml_policy {
    char *name;
    char *description;
    char* denial_salt;
    unsigned int passthrough;
    unsigned int signatures_resign;
    unsigned int signatures_refresh;
    unsigned int signatures_jitter;
    unsigned int signatures_inception_offset;
    unsigned int signatures_validity_default;
    unsigned int signatures_validity_denial;
    unsigned int signatures_validity_keyset;
    unsigned int signatures_max_zone_ttl;
    unsigned int denial_type;
    unsigned int denial_optout;
    unsigned int denial_ttl;
    unsigned int denial_resalt;
    unsigned int denial_algorithm;
    unsigned int denial_iterations;
    unsigned int denial_salt_length;
    /*unsigned int denial_salt_last_change;*/
    unsigned int keys_ttl;
    unsigned int keys_retire_safety;
    unsigned int keys_publish_safety;
    unsigned int keys_shared;
    unsigned int keys_purge_after;
    unsigned int zone_propagation_delay;
    unsigned int zone_soa_ttl;
    unsigned int zone_soa_minimum;
    unsigned int zone_soa_serial;
    unsigned int parent_registration_delay;
    unsigned int parent_propagation_delay;
    unsigned int parent_ds_ttl;
    unsigned int parent_soa_ttl;
    unsigned int parent_soa_minimum;

    int policykey_count;
    struct xml_policykey **policykey;
};

static xmlNodePtr
xml_find_node(xmlNodePtr root, char const *path)
{
    xmlXPathContextPtr ctx = xmlXPathNewContext(root->doc);
    xmlXPathObjectPtr obj = xmlXPathNodeEval(root, (xmlChar*)path, ctx);
    xmlXPathFreeContext(ctx);
    if (!obj || xmlXPathNodeSetIsEmpty(obj->nodesetval)) {
        xmlXPathFreeObject(obj);
        return NULL;
    }
    /* we know we have at least one node */
    xmlNodePtr node = obj->nodesetval->nodeTab[0];
    xmlXPathFreeObject(obj);
    return node;
}

static void
xml_try_read_content(xmlNodePtr root, char const *path, char **target)
{
    xmlNodePtr node = xml_find_node(root, path);
    if (!node) return;
    *target = ods_str_trim((char *)xmlNodeGetContent(node), 0);
}

static void
xml_try_read_bool(xmlNodePtr root, char const *path, unsigned int *target)
{
    xmlNodePtr node = xml_find_node(root, path);
    if (!node) return;
    *target = 1;
}

static void
xml_try_read_duration(xmlNodePtr root, char const *path, unsigned int *target)
{
    xmlNodePtr node = xml_find_node(root, path);
    if (!node) return;
    xmlChar *txt = xmlNodeGetContent(node);
    if (!txt) return;
    duration_type *duration = duration_create_from_string((char *)txt);
    xmlFree(txt);
    if (!duration) return;
    *target = duration2time(duration);
    duration_cleanup(duration);
}

static void
xml_try_read_int(xmlNodePtr root, char const *path, unsigned int *target)
{
    xmlNodePtr node = xml_find_node(root, path);
    if (!node) return;
    xmlChar *txt = xmlNodeGetContent(node);
    if (!txt) return;
    *target = atoi((const char *)txt);
    xmlFree(txt);
}

static void
xml_try_read_prop_int(xmlNodePtr root, char const *path, char const *prop, unsigned int *target)
{
    xmlNodePtr node = xml_find_node(root, path);
    if (!node) return;
    xmlChar *txt = xmlGetProp(node, (xmlChar *)prop);
    if (!txt) return;
    *target = atoi((const char *)txt);
    xmlFree(txt);
}

struct xml_policykey *
xml_read_key(xmlNodePtr node, int role)
{
    struct xml_policykey *pk = calloc(1, sizeof(struct xml_policykey));
    if (!pk) return NULL;
    pk->role = role;
    xml_try_read_int(node,       "./Algorithm", &pk->algorithm);
    xml_try_read_prop_int(node,  "./Algorithm" , "length", &pk->bits);
    xml_try_read_duration(node,  "./Lifetime", &pk->lifetime);
    xml_try_read_content(node,   "./Repository", &pk->repository);
    xml_try_read_int(node,       "./Standby", &pk->standby);
    xml_try_read_bool(node,      "./ManualRollover", &pk->manual_rollover);
    xml_try_read_bool(node,      "./RFC5011", &pk->rfc5011);

    char *rolltype_str = NULL;
    xml_try_read_content(node,   "./KskRollType", &rolltype_str);
    xml_try_read_content(node,   "./ZskRollType", &rolltype_str);
    xml_try_read_content(node,   "./CskRollType", &rolltype_str);
    rolltype_str = ods_str_trim(rolltype_str, 0);
    int minimize;
    if (!rolltype_str) {
        switch (role) {
            case DBW_KSK: minimize = DBW_MINIMIZE_DS; break;
            case DBW_ZSK: minimize = DBW_MINIMIZE_RRSIG; break;
            case DBW_CSK: minimize = DBW_MINIMIZE_DS_RRSIG; break;
            default: minimize = DBW_MINIMIZE_NONE;
        }
    } else if (!strcasecmp(rolltype_str, "KskDoubleRRset"    )) minimize = DBW_MINIMIZE_NONE;
    else if (!strcasecmp(rolltype_str, "KskDoubleDS"       )) minimize = DBW_MINIMIZE_DNSKEY;
    else if (!strcasecmp(rolltype_str, "KskDoubleSignature")) minimize = DBW_MINIMIZE_DS;
    else if (!strcasecmp(rolltype_str, "ZskDoubleSignature")) minimize = DBW_MINIMIZE_NONE;
    else if (!strcasecmp(rolltype_str, "ZskPrePublication" )) minimize = DBW_MINIMIZE_RRSIG;
    else if (!strcasecmp(rolltype_str, "ZskDoubleRRsig"    )) minimize = DBW_MINIMIZE_DNSKEY;
    else if (!strcasecmp(rolltype_str, "CskDoubleRRset"    )) minimize = DBW_MINIMIZE_NONE;
    else if (!strcasecmp(rolltype_str, "CskSingleSignature")) minimize = DBW_MINIMIZE_RRSIG;
    else if (!strcasecmp(rolltype_str, "CskDoubleDS"       )) minimize = DBW_MINIMIZE_DNSKEY;
    else if (!strcasecmp(rolltype_str, "CskDoubleSignature")) minimize = DBW_MINIMIZE_DS;
    else if (!strcasecmp(rolltype_str, "CskPrePublication" )) minimize = DBW_MINIMIZE_DS_RRSIG;
    else minimize = DBW_MINIMIZE_NONE;
    pk->minimize = minimize;
    free(rolltype_str);

    return pk;
}

static int
xml_read_policy(xmlNodePtr node, struct xml_policy *policy)
{
    if (strcmp((char*)node->name, "Policy")) return 1;

    policy->name = (char *)xmlGetProp(node, (xmlChar *)"name");

    xml_try_read_bool(node,     "./Passthrough", &policy->passthrough);
    xml_try_read_content(node,  "./Description", &policy->description);

    xml_try_read_duration(node, "./Signatures/Resign", &policy->signatures_resign);
    xml_try_read_duration(node, "./Signatures/Refresh", &policy->signatures_refresh);
    xml_try_read_duration(node, "./Signatures/Validity/Default", &policy->signatures_validity_default);
    xml_try_read_duration(node, "./Signatures/Validity/Denial", &policy->signatures_validity_denial);
    xml_try_read_duration(node, "./Signatures/Validity/Keyset", &policy->signatures_validity_keyset);
    xml_try_read_duration(node, "./Signatures/Jitter", &policy->signatures_jitter);
    xml_try_read_duration(node, "./Signatures/InceptionOffset", &policy->signatures_inception_offset);
    xml_try_read_duration(node, "./Signatures/MaxZoneTTL", &policy->signatures_max_zone_ttl);

    unsigned int use_nsec3 = 0;
    xml_try_read_bool(node,     "./Denial/NSEC3", &use_nsec3);
    policy->denial_type = use_nsec3 ? DBW_NSEC3 : DBW_NSEC;

    xml_try_read_duration(node, "./Denial/NSEC3/TTL", &policy->denial_ttl);
    xml_try_read_bool(node,     "./Denial/NSEC3/OptOut", &policy->denial_optout);
    xml_try_read_duration(node, "./Denial/NSEC3/Resalt", &policy->denial_resalt);
    xml_try_read_int(node,      "./Denial/NSEC3/Hash/Algorithm", &policy->denial_algorithm);
    xml_try_read_int(node,      "./Denial/NSEC3/Hash/Iterations", &policy->denial_iterations);
    xml_try_read_prop_int(node, "./Denial/NSEC3/Hash/Salt", "length", &policy->denial_salt_length);

    xml_try_read_duration(node, "./Keys/TTL", &policy->keys_ttl);
    xml_try_read_duration(node, "./Keys/RetireSafety", &policy->keys_retire_safety);
    xml_try_read_duration(node, "./Keys/PublishSafety", &policy->keys_publish_safety);
    xml_try_read_bool(node,     "./Keys/ShareKeys", &policy->keys_shared);
    xml_try_read_duration(node, "./Keys/Purge", &policy->keys_purge_after);

    xml_try_read_duration(node, "./Zone/PropagationDelay", &policy->zone_propagation_delay);
    xml_try_read_duration(node,      "./Zone/SOA/TTL", &policy->zone_soa_ttl);
    xml_try_read_duration(node, "./Zone/SOA/Minimum", &policy->zone_soa_minimum);
    char *serial = NULL;
    xml_try_read_content(node,  "./Zone/SOA/Serial", &serial);
    policy->zone_soa_serial = serial?dbw_txt2enum(dbw_soa_serial_txt, serial):0;
    free(serial);

    xml_try_read_duration(node, "./Parent/PropagationDelay", &policy->parent_propagation_delay);
    xml_try_read_duration(node,      "./Parent/DS/TTL", &policy->parent_ds_ttl);
    xml_try_read_duration(node,      "./Parent/SOA/TTL", &policy->parent_soa_ttl);
    xml_try_read_duration(node, "./Parent/SOA/Minimum", &policy->parent_soa_minimum);
    xml_try_read_duration(node, "./Parent/RegistrationDelay", &policy->parent_registration_delay);

    /* find number of keys */
    xmlXPathContextPtr ctx = xmlXPathNewContext(node->doc);
    xmlXPathObjectPtr ksks = xmlXPathNodeEval(node, (xmlChar*)"./Keys/KSK", ctx);
    xmlXPathObjectPtr zsks = xmlXPathNodeEval(node, (xmlChar*)"./Keys/ZSK", ctx);
    xmlXPathObjectPtr csks = xmlXPathNodeEval(node, (xmlChar*)"./Keys/CSK", ctx);
    xmlXPathFreeContext(ctx);
    if (!ksks || !zsks || !csks) {
        xmlXPathFreeObject(ksks);
        xmlXPathFreeObject(zsks);
        xmlXPathFreeObject(csks);
        return 1;
    }
    policy->policykey_count = ksks->nodesetval->nodeNr + zsks->nodesetval->nodeNr
        + csks->nodesetval->nodeNr;
    policy->policykey = calloc(policy->policykey_count, sizeof(struct xml_policykey *));

    int index = 0;
    for (int i = 0; i < ksks->nodesetval->nodeNr; i++) {
        policy->policykey[index++] = xml_read_key(ksks->nodesetval->nodeTab[i], DBW_KSK);
    }
    for (int i = 0; i < zsks->nodesetval->nodeNr; i++) {
        policy->policykey[index++] = xml_read_key(zsks->nodesetval->nodeTab[i], DBW_ZSK);
    }
    for (int i = 0; i < csks->nodesetval->nodeNr; i++) {
        policy->policykey[index++] = xml_read_key(csks->nodesetval->nodeTab[i], DBW_CSK);
    }
    xmlXPathFreeObject(ksks);
    xmlXPathFreeObject(zsks);
    xmlXPathFreeObject(csks);
    return 0;
}

static void
repository_names(hsm_repository_t* hsm, char ***list, int *count)
{
    *count = 0;
    for (hsm_repository_t *h = hsm; h; h = h->next) (*count)++;
    *list = malloc((*count) * sizeof(char *));
    if (!(*list)) *count = 0;
    for (int i = 0; i < *count; i++) {
        (*list)[i] = hsm->name;
        hsm = hsm->next;
    }
}

static void
xml_policy_set_defaults(struct xml_policy *xp)
{
    xp->signatures_max_zone_ttl = MAX_ZONE_TTL;
}

static int
policy_xml_cmp(int sockfd, struct dbw_policy *p, struct xml_policy *xp)
{
    if ((strcasecmp(p->name, xp->name))
        || (strcasecmp(p->description, xp->description))
        || (xp->denial_salt && strcmp(p->denial_salt, xp->denial_salt))
        || (p->passthrough != xp->passthrough)
        || (p->signatures_resign != xp->signatures_resign)
        || (p->signatures_refresh != xp->signatures_refresh)
        || (p->signatures_jitter != xp->signatures_jitter)
        || (p->signatures_inception_offset != xp->signatures_inception_offset)
        || (p->signatures_validity_default != xp->signatures_validity_default)
        || (p->signatures_validity_denial != xp->signatures_validity_denial)
        || (p->signatures_validity_keyset != xp->signatures_validity_keyset)
        || (p->signatures_max_zone_ttl != xp->signatures_max_zone_ttl)
        || (p->denial_type != xp->denial_type)
        || (p->denial_optout != xp->denial_optout)
        || (p->denial_ttl != xp->denial_ttl)
        || (p->denial_resalt != xp->denial_resalt)
        || (p->denial_algorithm != xp->denial_algorithm)
        || (p->denial_iterations != xp->denial_iterations)
        || (p->denial_salt_length != xp->denial_salt_length)
        || (p->keys_ttl != xp->keys_ttl)
        || (p->keys_retire_safety != xp->keys_retire_safety)
        || (p->keys_publish_safety != xp->keys_publish_safety)
        || (p->keys_shared != xp->keys_shared)
        || (p->keys_purge_after != xp->keys_purge_after)
        || (p->zone_propagation_delay != xp->zone_propagation_delay)
        || (p->zone_soa_ttl != xp->zone_soa_ttl)
        || (p->zone_soa_minimum != xp->zone_soa_minimum)
        || (p->zone_soa_serial  != xp->zone_soa_serial)
        || (p->parent_registration_delay != xp->parent_registration_delay)
        || (p->parent_propagation_delay != xp->parent_propagation_delay)
        || (p->parent_ds_ttl != xp->parent_ds_ttl)
        || (p->parent_soa_ttl != xp->parent_soa_ttl)
        || (p->parent_soa_minimum != xp->parent_soa_minimum))
        return 1;

    if (xp->policykey_count != p->policykey_count)
        return 1;

    for (int i = 0; i < xp->policykey_count; i++) {
        struct xml_policykey *xpolicykey = xp->policykey[i];
        int match = 0;
        for (int j = 0; j < p->policykey_count; j++) {
            struct dbw_policykey *policykey = p->policykey[j];
            match = (policykey->repository && !strcasecmp (policykey->repository, xpolicykey->repository)
                && (policykey->role == xpolicykey->role)
                && (policykey->algorithm == xpolicykey->algorithm)
                && (policykey->bits == xpolicykey->bits)
                && (policykey->lifetime == xpolicykey->lifetime)
                && (policykey->standby == xpolicykey->standby)
                && (policykey->manual_rollover  == xpolicykey->manual_rollover)
                && (policykey->rfc5011 == xpolicykey->rfc5011)
                && (policykey->minimize == xpolicykey->minimize));
            if (match)
                break;
        }
        if (!match)
            return 1;
    }
    return 0;
}

static int
process_xml(int sockfd, xmlNodePtr root, struct xml_policy** policies_out, int *count_out)
{
    struct xml_policy *xp;
    int count;

    xmlXPathContextPtr ctx = xmlXPathNewContext(root->doc);
    xmlXPathObjectPtr xpolicies = xmlXPathNodeEval(root, (xmlChar*)"/KASP/Policy", ctx);
    if (!xpolicies) return 1;
    count = xpolicies->nodesetval->nodeNr;
    xp = calloc(count, sizeof(struct xml_policy));
    for (int i = 0; i < count; i++) {
        xmlNodePtr node = xpolicies->nodesetval->nodeTab[i];
        xml_policy_set_defaults(xp+i);
        if (xml_read_policy(node, xp+i)) {
            client_printf_err(sockfd, "Unable to create policy from XML.");
            free(xp);
            return 1;
        }
    }
    xmlXPathFreeContext(ctx);
    xmlXPathFreeObject(xpolicies);
    *policies_out = xp;
    *count_out = count;
    return 0;
}

static void
xml2db(struct dbw_policy *p, struct xml_policy *xp)
{
    free(p->name);
    free(p->description);
    p->name                         = strdup(xp->name?xp->name:"");
    p->description                  = strdup(xp->description?xp->description:"");
    if (xp->denial_salt) {
        free(p->denial_salt);
        p->denial_salt              = strdup(xp->denial_salt);
    }
    p->passthrough                  = xp->passthrough;
    p->signatures_resign            = xp->signatures_resign;
    p->signatures_refresh           = xp->signatures_refresh;
    p->signatures_jitter            = xp->signatures_jitter;
    p->signatures_inception_offset  = xp->signatures_inception_offset;
    p->signatures_validity_default  = xp->signatures_validity_default;
    p->signatures_validity_denial   = xp->signatures_validity_denial;
    p->signatures_validity_keyset   = xp->signatures_validity_keyset;
    p->signatures_max_zone_ttl      = xp->signatures_max_zone_ttl;
    p->denial_type                  = xp->denial_type;
    p->denial_optout                = xp->denial_optout;
    p->denial_ttl                   = xp->denial_ttl;
    p->denial_resalt                = xp->denial_resalt;
    p->denial_algorithm             = xp->denial_algorithm;
    p->denial_iterations            = xp->denial_iterations;
    p->denial_salt_length           = xp->denial_salt_length;
    p->keys_ttl                     = xp->keys_ttl;
    p->keys_retire_safety           = xp->keys_retire_safety;
    p->keys_publish_safety          = xp->keys_publish_safety;
    p->keys_shared                  = xp->keys_shared;
    p->keys_purge_after             = xp->keys_purge_after;
    p->zone_propagation_delay       = xp->zone_propagation_delay;
    p->zone_soa_ttl                 = xp->zone_soa_ttl;
    p->zone_soa_minimum             = xp->zone_soa_minimum;
    p->zone_soa_serial              = xp->zone_soa_serial;
    p->parent_registration_delay    = xp->parent_registration_delay;
    p->parent_propagation_delay     = xp->parent_propagation_delay;
    p->parent_ds_ttl                = xp->parent_ds_ttl;
    p->parent_soa_ttl               = xp->parent_soa_ttl;
    p->parent_soa_minimum           = xp->parent_soa_minimum;
}

int policy_import(int sockfd, engine_type* engine, db_connection_t *dbconn,
    int do_delete)
{
    ods_log_assert(dbconn);
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_assert(engine->config->policy_filename);

    xmlDocPtr doc;
    xmlNodePtr root;
    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) return POLICY_IMPORT_ERR_DATABASE;

    char **hsm_names;
    int hsm_count;
    repository_names(engine->config->repositories, &hsm_names, &hsm_count);

    /* Validate, parse and walk the XML. */
    if (check_kasp(engine->config->policy_filename, hsm_names, hsm_count, 0, NULL, NULL)) {
        client_printf_err(sockfd, "Unable to validate the KASP XML, please run ods-kaspcheck for more details!\n");
        free(hsm_names);
        dbw_free(db);
        return POLICY_IMPORT_ERR_XML;
    }
    free(hsm_names);
    if (!(doc = xmlParseFile(engine->config->policy_filename))) {
        client_printf_err(sockfd, "Unable to read/parse KASP XML file %s!\n",
            engine->config->policy_filename);
        dbw_free(db);
        return POLICY_IMPORT_ERR_XML;
    } else if (!(root = xmlDocGetRootElement(doc))) {
        client_printf_err(sockfd, "Unable to get the root element in the KASP XML!\n");
        xmlFreeDoc(doc);
        dbw_free(db);
        return POLICY_IMPORT_ERR_XML;
    }

    struct xml_policy* xpolicies;
    int count;
    int r = process_xml(sockfd, root, &xpolicies, &count);
    xmlFreeDoc(doc);
    if (r) {
        dbw_free(db);
        return POLICY_IMPORT_ERR_XML;
    }
    for (int i = 0; i < count; i++) {
        struct dbw_policy *p = dbw_get_policy(db, (xpolicies+i)->name);
        if (p) {
            p->scratch |= POLICY_SEEN;
            if (!policy_xml_cmp(sockfd, p, xpolicies+i)) {
                client_printf(sockfd, "Policy %s already up-to-date\n", p->name);
                continue;
            }
            else {
                p->scratch |= POLICY_UPDATED;
                if (p->denial_salt_length != (xpolicies+i)->denial_salt_length) {
                    p->scratch |= POLICY_RESALT;
                }
            }
        }
        else {
           p = dbw_new_policy(db);
           p->scratch |= POLICY_SEEN|POLICY_CREATED;
        }

        xml2db(p, xpolicies+i);
        dbw_mark_dirty((struct dbrow *)p);
        /* policykeys */
        for (int pk = 0; pk < p->policykey_count; pk++) {
            p->policykey[pk]->dirty = DBW_DELETE;
        }
        for (int j = 0; j < (xpolicies+i)->policykey_count; j++) {
            struct dbw_policykey *policykey = dbw_new_policykey(db, p);
            struct xml_policykey *xpolicykey = (xpolicies+i)->policykey[j];
            policykey->repository       = strdup(xpolicykey->repository?xpolicykey->repository:"");
            policykey->role             = xpolicykey->role;
            policykey->algorithm        = xpolicykey->algorithm;
            policykey->bits             = xpolicykey->bits;
            policykey->lifetime         = xpolicykey->lifetime;
            policykey->standby          = xpolicykey->standby;
            policykey->manual_rollover  = xpolicykey->manual_rollover;
            policykey->rfc5011          = xpolicykey->rfc5011;
            policykey->minimize         = xpolicykey->minimize;
        }
    }
    for (int i = 0; i < count; i++) {
        free((xpolicies+i)->name);
        free((xpolicies+i)->description);
        free((xpolicies+i)->denial_salt);
        for (int j = 0; j < (xpolicies+i)->policykey_count; j++) {
            free((xpolicies+i)->policykey[j]->repository);
            free((xpolicies+i)->policykey[j]);
        }
        free((xpolicies+i)->policykey);
    }
    free(xpolicies);
    /* delete unseen policies */
    if (do_delete) {
        for (size_t p = 0; p < db->policies->n; p++) {
            struct dbw_policy *policy = (struct dbw_policy *)db->policies->set[p];
            if (policy->scratch || policy->dirty != DBW_CLEAN) continue;
            policy->dirty = DBW_DELETE;
            /* mark its policykeys as well */
            for (int pk = 0; pk < policy->policykey_count; pk++) {
                policy->policykey[pk]->dirty = DBW_DELETE;
            }
        }
    }
    if (dbw_commit(db)) {
        r = POLICY_IMPORT_ERR_DATABASE;
    } else {
        for (size_t p = 0; p < db->policies->n; p++) {
            struct dbw_policy *policy = (struct dbw_policy *)db->policies->set[p];
            if (!policy->scratch) {
                if (do_delete) {
                    ods_log_info("[policy_import] policy %s deleted", policy->name);
                    client_printf(sockfd, "Deleted policy %s successfully\n", policy->name);
                }
                continue;
            }
            else if (policy->scratch&POLICY_CREATED) {
                ods_log_info("[policy_import] policy %s created", policy->name);
                client_printf(sockfd, "Created policy %s successfully\n", policy->name);
            }
            else if (policy->scratch&POLICY_UPDATED){
                ods_log_info("[policy_import] policy %s updated", policy->name);
                client_printf(sockfd, "Updated policy %s successfully\n", policy->name);
            }
            if (policy->scratch&POLICY_RESALT) {
                resalt_task_flush(engine, dbconn, policy->name);
            }
        }
    }
    dbw_free(db);
    return r;
}
