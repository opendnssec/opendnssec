/*
 * Copyright (c) 2022 Berry van Halderen <berry@nlnetlabs.nl>
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


#include "config.h"
#include "log.h"
#include "clientpipe.h"
#include "utilities.h"
#include "db/policy.h"
#include "db/policy_key.h"
#include "utils/kc_helper.h"
#include "db/zone_db.h"
#include "db/hsm_key.h"
#include "hsmkey/hsm_key_factory.h"
#include "signconf/signconf_task.h"
#include "policy/policy_io.h"
#include "xmlconf.h"

static int
policyCompare(void*a, void*b)
{
    policy_t* policy1 = (policy_t*)a;
    policy_t* policy2 = (policy_t*)b;
    return strcmp(policy1->name, policy2->name);
}

static int
keyCompare(void*a, void*b)
{
    int result;
    policy_key_t* key1 = (policy_key_t*)a;
    policy_key_t* key2 = (policy_key_t*)b;
    result = key1->role - key2->role;
    if(result == 0)
        result = key1->algorithm - key2->algorithm;
    if(result == 0)
        result = key1->bits - key2->bits;
    return result;
}

static int
algoCompare(void*a, void*b)
{
    int algo1 = *(int*)a;
    int algo2 = *(int*)b;
    return algo1 - algo2;
}

static const policy_key_t* keylist_begin(policy_key_list_t* list) {
    list->object_list_position = 0;
    if(list->object_list_position < list->object_list_size)
        return list->object_list[list->object_list_position];
    else
        return NULL;
}

static const policy_key_t* keylist_next(policy_key_list_t* list) {
    if(list->object_list_position+1 < list->object_list_size) {
        list->object_list_position += 1;
        return list->object_list[list->object_list_position];
    } else
        return NULL;
}

static policy_key_t * newkey(const db_connection_t* connection, const db_value_t* policyid, const policy_key_role_t role) {
    policy_t* policy = (policy_t*)connection;
    policy_key_t* key = calloc(1, sizeof(policy_key_t));
    if(!policy->policy_key_list) {
        policy->policy_key_list = calloc(1, sizeof(policy_key_list_t));
    }
    policy->policy_key_list->object_list_size += 1;
    policy->policy_key_list->object_list = realloc(policy->policy_key_list->object_list, sizeof(policy_key_t*) * policy->policy_key_list->object_list_size);
    policy->policy_key_list->object_list[policy->policy_key_list->object_list_size - 1] = key;
    return key;
}
    policy_key_t* policy_key;

struct policylist {
    policy_t* policy;
    struct policylist* next;
};

static struct xmlconf_enum_struct kskenums[] = {
    { "KskDoubleRRset",      POLICY_KEY_MINIMIZE_NONE },
    { "KskDoubleDS",         POLICY_KEY_MINIMIZE_DNSKEY },
    { "KskDoubleSignature",  POLICY_KEY_MINIMIZE_DS },
    { NULL, POLICY_KEY_MINIMIZE_NONE }
};

static struct xmlconf_enum_struct zskenums[] = {
    { "ZskDoubleSignature",  POLICY_KEY_MINIMIZE_NONE },
    { "ZskPrePublication",   POLICY_KEY_MINIMIZE_RRSIG },
    { "ZskDoubleRRsig",      POLICY_KEY_MINIMIZE_DNSKEY },
    { NULL, POLICY_KEY_MINIMIZE_NONE }
};

static struct xmlconf_enum_struct cskenums[] = {
    { "CskDoubleRRset",      POLICY_KEY_MINIMIZE_NONE },
    { "CskSingleSignature",  POLICY_KEY_MINIMIZE_RRSIG },
    { "CskDoubleDS",         POLICY_KEY_MINIMIZE_DNSKEY },
    { "CskDoubleSignature",  POLICY_KEY_MINIMIZE_DS },
    { "CskPrePublication",   POLICY_KEY_MINIMIZE_DS_AND_RRSIG },
    { NULL, POLICY_KEY_MINIMIZE_NONE }
};
static struct xmlconf_enum_struct serialenums[] = {
    { "counter",     POLICY_ZONE_SOA_SERIAL_COUNTER },
    { "datecounter", POLICY_ZONE_SOA_SERIAL_DATECOUNTER },
    { "unixtime",    POLICY_ZONE_SOA_SERIAL_UNIXTIME },
    { "keep",        POLICY_ZONE_SOA_SERIAL_KEEP },
    { NULL,          POLICY_ZONE_SOA_SERIAL_INVALID }
};


static int
deletePolicy(int sockfd, const db_connection_t* dbconn, const char* policyname)
{
    int successful;
    hsm_key_list_t* hsm_key_list;
    zone_list_db_t* zone_list;
    policy_key_list_t* policy_key_list;
    policy_t* policy;
    policy = policy_new(dbconn);
    if(!policy_get_by_name(policy, policyname)) {
        /*
         * Check if there are still zones or hsm keys using this policy and
         * abort if there is
         */
        if(!(zone_list = zone_list_db_new_get_by_policy_id(dbconn, policy_id(policy)))) {
            client_printf_err(sockfd, "Unable to check for zones using policy %s from database!\n", policyname);
            policy_free(policy);
            return -1;
        }
        if(zone_list_db_next(zone_list)) {
            zone_list_db_free(zone_list);
            client_printf_err(sockfd, "Unable to delete policy %s, there are still zones using this policy!\n", policyname);
            policy_free(policy);
            return -1;
        }
        zone_list_db_free(zone_list);
        if(!(hsm_key_list = hsm_key_list_new_get_by_policy_id(dbconn, policy_id(policy)))) {
            client_printf_err(sockfd, "Unable to check for hsm keys using policy %s from database!\n", policyname);
            policy_free(policy);
            return -1;
        }
        if(hsm_key_list_next(hsm_key_list)) {
            hsm_key_list_free(hsm_key_list);
            client_printf_err(sockfd, "Unable to delete policy %s, there are still hsm keys using this policy!\n", policyname);
            policy_free(policy);
            return -1;
        }
        hsm_key_list_free(hsm_key_list);

        /*
         * Try and delete all the policy keys for this policy
         */
        if(!(policy_key_list = policy_key_list_new_get_by_policy_id(dbconn, policy_id(policy)))) {
            client_printf_err(sockfd, "Unable to get policy keys for policy %s from database!\n", policyname);
            policy_free(policy);
            return -1;
        }
        successful = 1;
        for(policy_key = policy_key_list_get_next(policy_key_list); policy_key; policy_key_free(policy_key), policy_key = policy_key_list_get_next(policy_key_list)) {
            if(policy_key_delete(policy_key)) {
                client_printf_err(sockfd, "Unable to delete policy key %s in policy %s from database!\n", policy_key_role_text(policy_key), policyname);
                successful = 0;
                return -1;
            }
        }
        policy_key_list_free(policy_key_list);

        if(!successful) {
            policy_free(policy);
            return 0;
        }
        if(policy_delete(policy)) {
            client_printf_err(sockfd, "Unable to delete policy %s from database!\n", policyname);
            policy_free(policy);
            return -1;
        }

        ods_log_info("[policy_import] policy %s deleted", policyname);
        client_printf(sockfd, "Deleted policy %s successfully\n", policyname);
    } else {
        client_printf_err(sockfd, "Unable to delete policy %s from database!\n", policyname);
        return -1;
    }
    policy_free(policy);
    return 0;
}

static void
transportPolicy(int sockfd, const db_connection_t* dbconn, xmlconf_type h, char* policyname)
{
    int nkeys;
    const policy_key_t** keys;
    int npolicies = 0;
    policy_t** policies = NULL;
    policy_list_t* policy_list;
    /*
    struct policylist* headPtr = NULL;
    struct policylist** tailPtr = &headPtr;
    */
    unsigned int zonemodus;

    xmlconf_compound(h, "/KASP");    

    policy_list = policy_list_new(dbconn);
    policy_list_get(policy_list);
    const policy_t* policy;
    while((policy = policy_list_next(policy_list)))
        if(policy && (!policyname || !strcmp(policyname,policy->name)))
            if(!alloc(&policies, sizeof(policy_t*), &npolicies, npolicies+1)) {
                policies[npolicies-1] = malloc(sizeof(policy_t));
                policies[npolicies-1]->name = strdup(policy->name);
            }
    policy_list_free(policy_list);
    for(xmlconf_iterator_type iter = xmlconf_iterate(h, "/KASP/Policy", &npolicies, policies); xmlconf_next(&iter); ) {
        policy_t* policy = NULL;
        policy_t template;
        template.name = NULL;
        while(xmlconf_match(&iter, &template, &policy, policyCompare)) {
            xmlconf_string(h, "@name", &template.name);
        }
        if(!policy) {
            policy = policy_new(dbconn);
            policy_get_by_name(policy, template.name);
            policy->policy_key_list = policy_key_list_new(dbconn);
            /*
            (*tailPtr) = malloc(sizeof(struct policylist));
            (*tailPtr)->policy = policy;
            (*tailPtr)->next = NULL;
            tailPtr = &((*tailPtr)->next);
            */
        } else {
            policy = policy_new_get_by_name(dbconn, policy->name);
        }
        free(template.name);
        xmlconf_string(h,   "@name", &(policy->name));
        zonemodus = (policy->zonemodus & 0x01);
        xmlconf_boolean(h,  "Passthrough", &zonemodus);
        xmlconf_string(h,   "Description", &(policy->description));
        xmlconf_compound(h, "Signatures");
        xmlconf_duration(h, "Signatures/Resign", &(policy->signatures_resign));
        xmlconf_duration(h, "Signatures/Refresh", &(policy->signatures_refresh));
        xmlconf_compound(h, "Signatures/Validity");
        xmlconf_duration(h, "Signatures/Validity/Default", &(policy->signatures_validity_default));
        xmlconf_duration(h, "Signatures/Validity/Denial",  &(policy->signatures_validity_denial));
        xmlconf_duration(h, "Signatures/Validity/Keyset",  &(policy->signatures_validity_keyset));
        xmlconf_duration(h, "Signatures/Jitter",           &(policy->signatures_jitter));
        xmlconf_duration(h, "Signatures/InceptionOffset",           &(policy->signatures_inception_offset));
        xmlconf_duration(h, "Signatures/MaxZoneTTL",           &(policy->signatures_max_zone_ttl));
        xmlconf_compound(h, "Denial");
        xmlconf_conditional(h, "Denial/NSEC", &(policy->denial_type), POLICY_DENIAL_TYPE_NSEC);
        xmlconf_conditional(h, "Denial/NSEC3", &(policy->denial_type), POLICY_DENIAL_TYPE_NSEC3);
        if(policy->denial_type == POLICY_DENIAL_TYPE_NSEC3) {
            xmlconf_duration(h, "Denial/NSEC3/TTL",    &(policy->denial_ttl));
            xmlconf_boolean(h,  "Denial/NSEC3/OptOut", &(policy->denial_optout));
            xmlconf_duration(h, "Denial/NSEC3/Resalt", &(policy->denial_resalt));
            xmlconf_compound(h, "Denial/NSEC3/Hash");
            xmlconf_uint(h,     "Denial/NSEC3/Hash/Algorithm", &(policy->denial_algorithm));
            xmlconf_uint(h,     "Denial/NSEC3/Hash/Iterations", &(policy->denial_iterations));
            xmlconf_compound(h, "Denial/NSEC3/Hash/Salt");
            xmlconf_uint(h,     "Denial/NSEC3/Hash/Salt/@length", &(policy->denial_salt_length));
            xmlconf_string(h,   "Denial/NSEC3/Hash/Salt", &(policy->denial_salt));
        }

        xmlconf_compound(h, "Zone");

        int zonemds[2];
        int nzonemds = 0;
        if(policy->zonemodus & 0x02)
            zonemds[nzonemds++] = 1;
        if(policy->zonemodus & 0x04)
            zonemds[nzonemds++] = 2;
        for(xmlconf_iterator_type zonemdIter = xmlconf_iterate(h, "ZoneMD", &nzonemds, zonemds); xmlconf_next(&zonemdIter); ) {
            unsigned int template, *ptr;
            while(xmlconf_match(&zonemdIter, &template, &ptr, algoCompare)) {
                xmlconf_optuint(h, "@algorithm", &template, 1);
            }
            if(!ptr) {
                unsigned int algorithm;
                xmlconf_optuint(h, "@algorithm", &algorithm, 1);
                switch(algorithm) {
                    case 1:
                        zonemodus |= 0x02;
                        break;
                    case 2:
                        zonemodus |= 0x04;
                        break;
                }
            } else
                xmlconf_optuint(h, "@algorithm", ptr, 1);
        }
        policy->zonemodus |= zonemodus;
        
        xmlconf_duration(h, "Zone/PropagationDelay", &(policy->zone_propagation_delay));
        xmlconf_compound(h, "Zone/SOA");
        xmlconf_duration(h, "Zone/SOA/TTL", &(policy->zone_soa_ttl));
        xmlconf_duration(h, "Zone/SOA/Minimum", &(policy->zone_soa_minimum));
        xmlconf_enum(h,     "Zone/SOA/Serial", &(policy->zone_soa_serial), serialenums);
        xmlconf_compound(h, "Parent");
        xmlconf_duration(h, "Parent/PropagationDelay", &(policy->parent_propagation_delay));
        xmlconf_compound(h, "Parent/DS");
        xmlconf_duration(h, "Parent/DS/TTL", &(policy->parent_ds_ttl));
        xmlconf_compound(h, "Parent/SOA");
        xmlconf_duration(h, "Parent/SOA/TTL", &(policy->parent_soa_ttl));
        xmlconf_duration(h, "Parent/SOA/Minimum", &(policy->parent_soa_minimum));
        xmlconf_duration(h, "Parent/RegistrationDelay", &(policy->parent_registration_delay));

        xmlconf_compound(h, "Keys");
        xmlconf_duration(h, "Keys/TTL",           &(policy->keys_ttl));
        xmlconf_duration(h, "Keys/RetireSafety",  &(policy->keys_retire_safety));
        xmlconf_duration(h, "Keys/PublishSafety", &(policy->keys_publish_safety));
        xmlconf_boolean(h,  "Keys/ShareKeys",     &(policy->keys_shared));
        xmlconf_duration(h, "Keys/Purge",         &(policy->keys_purge_after));

        if(!db_value_not_empty(&(policy->id))) {
            policy_update(policy);
        } else {
            policy_create(policy);
        }

        policy_get_by_name(policy, policy->name);
        policy->policy_key_list = policy_key_list_new_get_by_policy_id(dbconn,&(policy->id));

        nkeys = 0;
	for(const policy_key_t* pkey = policy_key_list_begin(policy->policy_key_list); pkey; pkey = policy_key_list_get_next(policy->policy_key_list))
            if(pkey->role == POLICY_KEY_ROLE_KSK)
                ++nkeys;
        keys = malloc(sizeof(policy_key_t*) * nkeys);
        nkeys = 0;
	for(const policy_key_t* pkey = policy_key_list_begin(policy->policy_key_list); pkey; pkey = policy_key_list_get_next(policy->policy_key_list))
            if(pkey->role == POLICY_KEY_ROLE_KSK)
                keys[nkeys++] = pkey;
        for(xmlconf_iterator_type keyIter = xmlconf_iterate(h, "Keys/KSK", &nkeys, keys); xmlconf_next(&keyIter); ) {
            policy_key_t* key = NULL;
            policy_key_t template;
            template.role = POLICY_KEY_ROLE_KSK;
            template.algorithm = 0;
            template.bits = 0;
            while(xmlconf_match(&keyIter, &template, &key, keyCompare)) {
                xmlconf_defuint(h,  "KSK", (unsigned int*)&(template.role), POLICY_KEY_ROLE_KSK);
                xmlconf_uint(h,     "Algorithm", &(template.algorithm));
                xmlconf_optuint(h,  "Algorithm/@length", &(template.bits), 0);
            }
            if(!key) {
                key = policy_key_new_get_by_policyid_and_role(dbconn, &policy->id, POLICY_KEY_ROLE_KSK);
                if(!key) {
                    key = policy_key_new(dbconn);
                }
            }
            xmlconf_defuint(h,  "KSK", (unsigned int*)&(key->role), POLICY_KEY_ROLE_KSK);
            xmlconf_uint(h,     "Algorithm", &(key->algorithm));
            xmlconf_optuint(h,  "Algorithm/@length", &(key->bits), 0);
            xmlconf_duration(h, "Lifetime", &(key->lifetime));
            xmlconf_string(h,   "Repository", &(key->repository));
            xmlconf_optuint(h,  "Standby", &(key->standby), 0);
            xmlconf_boolean(h,  "ManualRollover", &(key->manual_rollover));
            xmlconf_optenum(h,  "KskRollType", &(key->minimize), kskenums, POLICY_KEY_MINIMIZE_DS);
            xmlconf_boolean(h,  "RFC5011", &(key->rfc5011));
            key->policy_id = policy->id;
            policy_key_create(key);
        }

        nkeys = 0;
	for(const policy_key_t* pkey = policy_key_list_begin(policy->policy_key_list); pkey; pkey = policy_key_list_get_next(policy->policy_key_list))
            if(pkey->role == POLICY_KEY_ROLE_ZSK)
                ++nkeys;
        keys = malloc(sizeof(policy_key_t*) * nkeys);
        nkeys = 0;
	for(const policy_key_t* pkey = policy_key_list_begin(policy->policy_key_list); pkey; pkey = policy_key_list_get_next(policy->policy_key_list))
            if(pkey->role == POLICY_KEY_ROLE_ZSK)
                keys[nkeys++] = pkey;
        for(xmlconf_iterator_type keyIter = xmlconf_iterate(h, "Keys/ZSK", &nkeys, keys); xmlconf_next(&keyIter); ) {
            policy_key_t* key = NULL;
            policy_key_t template;
            template.algorithm = 0;
            template.bits = 0;
            while(xmlconf_match(&keyIter, &template, &key, keyCompare)) {
                xmlconf_defuint(h,  "ZSK", (unsigned int*)&(template.role), POLICY_KEY_ROLE_ZSK);
                xmlconf_uint(h,     "Algorithm", &(template.algorithm));
                xmlconf_optuint(h,  "Algorithm/@length", &(template.bits), 0);
            }
            if(!key) {
                key = policy_key_new_get_by_policyid_and_role(dbconn, &policy->id, POLICY_KEY_ROLE_ZSK);
                if(!key) {
                    key = policy_key_new(dbconn);
                }
            }
            xmlconf_defuint(h,  "ZSK", (unsigned int*)&(key->role), POLICY_KEY_ROLE_ZSK);
            xmlconf_uint(h,     "Algorithm", &(key->algorithm));
            xmlconf_optuint(h,  "Algorithm/@length", &(key->bits), 0);
            xmlconf_duration(h, "Lifetime", &(key->lifetime));
            xmlconf_string(h,   "Repository", &(key->repository));
            xmlconf_optuint(h,  "Standby", &(key->standby), 0);
            xmlconf_boolean(h,  "ManualRollover", &(key->manual_rollover));
            xmlconf_optenum(h,  "ZskRollType", &(key->minimize), zskenums, POLICY_KEY_MINIMIZE_RRSIG);
            key->policy_id = policy->id;
            policy_key_create(key);
        }

        nkeys = 0;
	for(const policy_key_t* pkey = policy_key_list_begin(policy->policy_key_list); pkey; pkey = policy_key_list_get_next(policy->policy_key_list))
            if(pkey->role == POLICY_KEY_ROLE_CSK)
                ++nkeys;
        keys = malloc(sizeof(policy_key_t*) * nkeys);
        nkeys = 0;
	for(const policy_key_t* pkey = policy_key_list_begin(policy->policy_key_list); pkey; pkey = policy_key_list_get_next(policy->policy_key_list))
            if(pkey->role == POLICY_KEY_ROLE_CSK)
                keys[nkeys++] = pkey;
        for(xmlconf_iterator_type keyIter = xmlconf_iterate(h, "Keys/CSK", &nkeys, keys); xmlconf_next(&keyIter); ) {
            policy_key_t* key = NULL;
            policy_key_t template;
            template.algorithm = 0;
            template.bits = 0;
            while(xmlconf_match(&keyIter, &template, &key, keyCompare)) {
                xmlconf_defuint(h,  "CSK", (unsigned int*)&(template.role), POLICY_KEY_ROLE_CSK);
                xmlconf_uint(h,     "Algorithm", &(template.algorithm));
                xmlconf_optuint(h,  "Algorithm/@length", &(template.bits), 0);
            }
            if(!key) {
                key = policy_key_new_get_by_policyid_and_role(dbconn, &policy->id, POLICY_KEY_ROLE_CSK);
            }
            xmlconf_defuint(h,  "CSK", (unsigned int*)&(key->role), POLICY_KEY_ROLE_CSK);
            xmlconf_uint(h,     "Algorithm", &(key->algorithm));
            xmlconf_optuint(h,  "Algorithm/@length", &(key->bits), 0);
            xmlconf_duration(h, "Lifetime", &(key->lifetime));
            xmlconf_string(h,   "Repository", &(key->repository));
            xmlconf_optuint(h,  "Standby", &(key->standby), 0);
            xmlconf_boolean(h,  "ManualRollover", &(key->manual_rollover));
            xmlconf_optenum(h,  "CskRollType", &(key->minimize), cskenums, POLICY_KEY_MINIMIZE_DS_AND_RRSIG);
            xmlconf_boolean(h,  "RFC5011", &(key->rfc5011));
            key->policy_id = policy->id;
            policy_key_create(key);
        }

        policy_free(policy);
    }
    while(npolicies) { // merge or delete
        --npolicies;
        deletePolicy(sockfd, dbconn, policies[npolicies]->name);
        free(policies[npolicies]->name);
        free(policies[npolicies]);
    }
    free(policies);
    /*
    while(headPtr) {
        struct policylist* next = headPtr->next;
        policy_t* policy = headPtr->policy;
        if(!db_value_not_empty(&(policy->id))) {
            policy_update(policy);
        } else {
            policy_create(policy);
        }
        policy_free(headPtr->policy);
        free(headPtr);
        headPtr = next;
    }
    */
}

policy_key_list_t*
policy_get_policy_keys(const policy_t* policy)
{
    return policy_key_list_new_get_by_policy_id(db_object_connection(policy->dbo), &(policy->id));
}

int
policy_import(int sockfd, engine_type* engine, db_connection_t *dbconn, int do_delete)
{
    int rtcode;
    xmlconf_type handle;
    rtcode = xmlconf_create(&handle);
    rtcode = xmlconf_input(handle, engine->config->policy_filename);
    transportPolicy(sockfd, dbconn, handle, NULL);
    xmlconf_dispose(&handle);
    return 0;
}

int
policy_export(int sockfd, const policy_t* policy, const char* filename)
{
    xmlconf_type handle;
    xmlconf_create(&handle);
    transportPolicy(sockfd, NULL, handle, policy->name);
    xmlDocFormatDump(stdout, handle->doc, 1);
    xmlconf_dispose(&handle);
    return 0;
}

int
policy_export_all(int sockfd, const db_connection_t* connection, const char* filename)
{
    xmlconf_type handle;
    xmlconf_create(&handle);
    transportPolicy(sockfd, connection, handle, NULL);
    xmlDocFormatDump(stdout, handle->doc, 1);
    xmlconf_dispose(&handle);
    return 0;
}
