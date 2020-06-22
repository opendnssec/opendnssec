/*
 * Copyright (c) 2016 NLNet Labs
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
#include <getopt.h>

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "duration.h"
#include "libhsm.h"
#include "libhsmdns.h"
#include "db/dbw.h"

#include "keystate/keystate_import_cmd.h"
#include "keystate/keystate_list_cmd.h"

static const char *module_str = "keystate_import_cmd";
/* 5 states are: generate, publish, ready, active and retire */
/* For every state we should specify the values of DS, DNSKEY, RRSIGDNSKEY 
   and RRSIG. These values can be HIDDEN(0),    RUMOURED(1), OMNIPRESENT(2), 
   UNRETENTIVE(3), NA(4)*/
const int ksk_mapping[5][4] = {{0,0,0,4},{0,1,1,4},{1,2,2,4},{1,2,2,4},{3,2,2,4}};
const int zsk_mapping[5][4] = {{4,0,4,0},{4,1,4,0},{4,2,4,1},{4,2,4,2},{4,2,4,3}};
const int ds_at_parent [5] = {0,0,1,3,5};

enum _state14 {
    GENERATE = 0, PUBLISH, READY, ACTIVE, RETIRE,
};

static int max(int a, int b) { return a>b?a:b; }
static int min(int a, int b) { return a<b?a:b; }

/* 0 on success */
static struct dbw_hsmkey *
perform_hsmkey_import(int sockfd, struct dbw_db *db,
    const char *ckaid, const char *rep, struct dbw_zone *zone,
    int bits, int alg, int keytype, unsigned int time)
{
  /* Create an HSM context and check that the repository exists  */
    hsm_ctx_t *hsm_ctx = hsm_create_context();
    if (!hsm_ctx) return NULL;
    if (!hsm_token_attached(hsm_ctx, rep)) {
        char *hsm_err = hsm_get_error(hsm_ctx);
        if (hsm_err) {
            ods_log_error("[%s] Error: Unable to check for the repository %s, HSM error: %s",
                module_str, rep, hsm_err);
            client_printf_err(sockfd, "Unable to check for the repository %s, HSM error: %s\n",
                rep, hsm_err);
            free(hsm_err);
        } else {
            ods_log_error("[%s] Error: Unable to find repository %s in HSM", module_str, rep);
            client_printf_err(sockfd, "Unable to find repository %s in HSM\n", rep);
        }
        hsm_destroy_context(hsm_ctx);
        return NULL;
    }

    libhsm_key_t *libhsmkey = hsm_find_key_by_id(hsm_ctx, ckaid);
    if (!libhsmkey) {
        ods_log_error("[%s] Error: Unable to find the key with this locator: %s", module_str, ckaid);
        client_printf_err(sockfd, "Unable to find the key with this locator: %s\n", ckaid);
        hsm_destroy_context(hsm_ctx);
        return NULL;
    }
    libhsm_key_free(libhsmkey);
    hsm_destroy_context(hsm_ctx);

    /* note that there was a check here to find out if there wasn't a pre-existing cka_id,
     * however this check isn't that proper.  duplicate cka_ids must exists for CSKs
     */
    
    struct dbw_hsmkey *hsmkey = calloc(1, sizeof (struct dbw_hsmkey));
    dbw_add(&zone->policy->hsmkey, &zone->policy->hsmkey_count, hsmkey);
    hsmkey->key_count = 0;
    hsmkey->key = NULL;
    hsmkey->locator = strdup(ckaid);
    hsmkey->repository = strdup(rep);
    hsmkey->state = DBW_HSMKEY_PRIVATE;
    hsmkey->bits = bits;
    hsmkey->algorithm = alg;
    hsmkey->role = keytype;
    hsmkey->inception = time;
    hsmkey->is_revoked = 0;
    hsmkey->key_type = HSM_KEY_KEY_TYPE_RSA;
    hsmkey->backup = 0;

    ods_log_debug("[%s] hsm key with this locator %s is created successfully", module_str, ckaid);
    return hsmkey;
}

static int
perform_keydata_import(int sockfd, struct dbw_db *db,
    struct dbw_zone *zone, int alg, int keystate_14, int keytype,
    unsigned int time, int setmin, struct dbw_hsmkey *hsmkey)
{
    uint16_t tag;
    if (hsm_keytag(hsmkey->locator, alg, keytype & DBW_KSK, &tag)) {
        ods_log_error("[%s] Error: Keytag for this key %s is not correct",
            module_str, hsmkey->locator);
    }
    struct dbw_key *key = calloc(1, sizeof (struct dbw_key));
    dbw_add(&zone->key, zone->key_count, key);
    dbw_add(&hsmkey->key, hsmkey->key_count, key);
    key->zone = zone;
    key->hsmkey = hsmkey;
    key->keystate_count = 0;
    key->keystate = NULL;
    key->zone = zone;
    key->hsmkey = hsmkey;
    key->keystate_count = 0;
    key->keystate = NULL;
    key->algorithm = alg;
    key->inception = time;
    key->introducing = keystate_14 < RETIRE;
    key->active_zsk = (keytype&DBW_ZSK) && keystate_14 == ACTIVE;
    key->active_ksk = (keytype&DBW_KSK) && keystate_14 >= PUBLISH;
    key->publish = keystate_14 >= PUBLISH;
    key->role = keytype;
    key->ds_at_parent = (keytype&DBW_KSK) ? ds_at_parent[keystate_14] : 0;
    key->keytag = tag;
    key->minimize = setmin;

    struct dbw_keystate *keystate_ds = calloc(1, sizeof (struct dbw_keystate));
    struct dbw_keystate *keystate_dk = calloc(1, sizeof (struct dbw_keystate));
    struct dbw_keystate *keystate_rd = calloc(1, sizeof (struct dbw_keystate));
    struct dbw_keystate *keystate_rs = calloc(1, sizeof (struct dbw_keystate));

    keystate_ds->key = key;
    keystate_dk->key = key;
    keystate_rd->key = key;
    keystate_rs->key = key;
    dbw_add(&key->keystate, &key->keystate_count, keystate_ds);
    dbw_add(&key->keystate, &key->keystate_count, keystate_dk);
    dbw_add(&key->keystate, &key->keystate_count, keystate_rd);
    dbw_add(&key->keystate, &key->keystate_count, keystate_rs);

    keystate_ds->type = DBW_DS;
    keystate_ds->last_change = time;
    keystate_ds->minimize = (key->minimize >> 2) & 1;
    keystate_ds->ttl = zone->policy->parent_ds_ttl;
    keystate_ds->state = (keytype & DBW_KSK) ? ksk_mapping[keystate_14][0] : zsk_mapping[keystate_14][0];

    keystate_dk->type = DBW_DNSKEY;
    keystate_dk->last_change = time;
    keystate_dk->minimize = (key->minimize >> 1) & 1;
    keystate_dk->ttl = zone->policy->keys_ttl;
    keystate_dk->state = (keytype & DBW_KSK) ? ksk_mapping[keystate_14][1] : zsk_mapping[keystate_14][1];

    keystate_rd->type = DBW_RRSIGDNSKEY;
    keystate_rd->last_change = time;
    keystate_rd->minimize = 0;
    keystate_rd->ttl = zone->policy->keys_ttl;
    keystate_rd->state = (keytype & DBW_KSK) ? ksk_mapping[keystate_14][2] : zsk_mapping[keystate_14][2];

    int ttl = max(
        min(zone->policy->zone_soa_ttl, zone->policy->zone_soa_minimum),
        (zone->policy->denial_type == POLICY_DENIAL_TYPE_NSEC3
            ? max(zone->policy->denial_ttl, zone->policy->signatures_max_zone_ttl)
            : zone->policy->signatures_max_zone_ttl));

    keystate_rd->type = DBW_RRSIG;
    keystate_rd->last_change = time;
    keystate_rd->minimize = (key->minimize >> 0) & 1;
    keystate_rd->ttl = ttl;
    keystate_rd->state = (keytype & DBW_KSK) ? ksk_mapping[keystate_14][3] : zsk_mapping[keystate_14][3];

    ods_log_debug("[%s] key data with this locator %s is created successfully", module_str, hsmkey->locator);
    return 0;
}

static void
usage(int sockfd)
{
    client_printf(sockfd,
		"key import\n"
		"	--cka_id <CKA_ID>			aka -k\n"
		"	--repository <repository>		aka -r\n"
		"	--zone <zone>				aka -z\n"
		"	--bits <size>				aka -b\n"
		"	--algorithm <algorithm>			aka -g\n"
		"	--keystate <state>			aka -e\n"
		"	--keytype <type>			aka -t\n"
		"	--inception_time <time>			aka -w\n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"Add a key which was created outside of the OpenDNSSEC into the enforcer database.\n"
		"\nOptions:\n"
		"cka_id		specify the locator of the key\n"
		"repository	name of the repository which the key must be stored\n"
		"zone		name of the zone for which this key is to be used\n"
		"bits		key size in bits\n"
		"algorithm	algorithm number \n"
		"keystate	state of the key in which the key will be after import\n"
		"keytype		type of the key, KSK, ZSK or CSK\n"
		"inception_time	time of inception\n\n");
}

static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
    #define NARGV 18
    char buf[ODS_SE_MAXLINE];
    const char *argv[NARGV];
    int argc = 0, long_index = 0, opt = 0;
    const char *ckaid = NULL;
    const char *repository = NULL;
    const char *zonename = NULL;
    const char *bits = NULL;
    const char *algorithm = NULL;
    const char* keytype = NULL;
    const char* keystate = NULL;
    const char *time = NULL;
    time_t inception = 0;
    struct tm tm;
    int setmin;
    db_connection_t* dbconn = getconnectioncontext(context);

    static struct option long_options[] = {
        {"zone", required_argument, 0, 'z'},
        {"cka_id", required_argument, 0, 'k'},
        {"repository", required_argument, 0, 'r'},
        {"bits", required_argument, 0, 'b'},
        {"algorithm", required_argument, 0, 'g'},
        {"keytype", required_argument, 0, 't'},
        {"keystate", required_argument, 0, 'e'},
        {"inception_time", required_argument, 0, 'w'},
        {0, 0, 0, 0}
    };

    ods_log_debug("[%s] %s command", module_str, key_import_funcblock.cmdname);

    /* Use buf as an intermediate buffer for the command.*/
    strncpy(buf, cmd, sizeof(buf));
    buf[sizeof(buf)-1] = '\0';

    /* separate the arguments*/
    argc = ods_str_explode(buf, NARGV, argv);
    if (argc == -1) {
        client_printf_err(sockfd, "too many arguments\n");
        ods_log_error("[%s] too many arguments for %s command",
                      module_str, key_import_funcblock.cmdname);
        return -1;
    }

    optind = 0;
    while ((opt = getopt_long(argc, (char* const*)argv, "z:k:r:b:g:t:e:w:", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'z':
                zonename = optarg;
                break;
            case 'k':
                ckaid = optarg;
                break;
            case 'r':
                repository = optarg;
                break;
            case 'b':
                bits = optarg;
                break;
            case 'g':
                algorithm = optarg;
                break;
            case 't':
                keytype = optarg;
                break;
            case 'e':
                keystate = optarg;
                break;
            case 'w':
                time = optarg;
                break;
            default:
                client_printf_err(sockfd, "unknown arguments\n");
                ods_log_error("[%s] unknown arguments for %s command",
                                module_str, key_import_funcblock.cmdname);
                return -1;
        }
    }

    if (keytype) {
        if (strcasecmp(keytype, "KSK") && strcasecmp(keytype, "ZSK") && strcasecmp(keytype, "CSK")) {
            ods_log_error("[%s] unknown keytype, should be one of KSK, ZSK, or CSK", module_str);
            client_printf_err(sockfd, "unknown keytype, should be one of KSK, ZSK, or CSK\n");
            return -1;
        }
    }
    else {
        ods_log_error("[%s] specify keytype for command %s", module_str, cmd);
        client_printf_err(sockfd, "specify keytype: ZSK, KSK or CSK\n");
        return -1;
    }

    if (keystate) {
        if (strcasecmp(keystate, "generate") && strcasecmp(keystate, "publish") && strcasecmp(keystate, "ready") && strcasecmp(keystate, "active") && strcasecmp(keystate, "retire") && strcasecmp(keystate, "revoke")) {
            ods_log_error("[%s] unknown keystate", module_str);
            client_printf_err(sockfd, "unknown keystate: states are generate, publish, ready, active or retire\n");
            return -1;
        }
    }
    else {
        ods_log_error("[%s] specify keystate for command %s", module_str, cmd);
        client_printf_err(sockfd, "specify keystate: generate, publish, ready, active or retire\n");
        return -1;
    }

    if (!zonename) {
        ods_log_error("[%s] expected --zone for %s command", module_str, key_import_funcblock.cmdname);
        client_printf_err(sockfd, "expected --zone \n");
        return -1;
    }
    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) return 1;
    struct dbw_zone *zone = dbw_FINDSTR(struct dbw_zone*, db->zones, name, db->nzones, zonename);
    if (!zone) {
        ods_log_error("[%s] Unknown zone: %s", module_str, zonename);
        client_printf_err(sockfd, "Unknown zone: %s\n", zonename);
        dbw_free(db);
        return -1;
    }
    free(zone);
    zone = NULL;

    if (!algorithm) {
        ods_log_error("[%s] specify an algorithm for command %s", module_str, cmd);
        client_printf_err(sockfd, "specify an algorithm\n");
        dbw_free(db);
        return -1;
    }
    if (!bits) {
        ods_log_error("[%s] specify bits for command %s", module_str, cmd);
        client_printf_err(sockfd, "specify bits\n");
        dbw_free(db);
        return -1;
    }
    if (!repository) {
        ods_log_error("[%s] specify repository for command %s", module_str, cmd);
        client_printf_err(sockfd, "specify repository \n");
        return -1;
    }

    if (time && strptime(time, "%Y-%m-%d-%H:%M:%S", &tm)) {
        tm.tm_isdst = -1;
        inception = mktime(&tm);
    } else {
        ods_log_error("[%s] specify inception time for command %s", module_str, cmd);
        client_printf_err(sockfd, "specify inception time YYYY-MM-DD-HH:MM:SS\n");
        dbw_free(db);
        return -1;
    }

    /* gen = 0, pub = 1, ready = 2, act = 3, ... */
    int state = -1;
    if (!strcasecmp(keystate, "generate"))
        state = 0;
    else if (!strcasecmp(keystate,"publish"))
        state = 1;
    else if (!strcasecmp(keystate, "ready"))
        state = 2;
    else if (!strcasecmp(keystate, "active"))
        state = 3;
    else if (!strcasecmp(keystate, "retire"))
        state = 4;
    else if (!strcasecmp(keystate, "revoke"))
        state = 5;

    int type = dbw_txt2enum(dbw_key_role_txt, keytype);

    /* Find relevant policykey */
    struct dbw_policykey *policykey = NULL;
    for (size_t pk = 0; pk < zone->policy->policykey_count; pk++) {
        struct dbw_policykey *pkey = zone->policy->policykey[pk];
        if (pkey->algorithm != atoi(algorithm)) continue;
        if (pkey->role != type) continue;
        policykey = pkey;
        break;
    }
    if (!policykey) {
        ods_log_error("Error: Could not find a policykey with specified type and algorithm.");
        client_printf_err(sockfd, "Could not find a policykey with specified type and algorithm.\n");
        dbw_free(db);
        return 1;
    }

    /* perform task immediately */
    struct dbw_hsmkey * hsmkey = perform_hsmkey_import(sockfd, db, ckaid,
        repository, zone, atoi(bits), atoi(algorithm), type, (unsigned int)inception);
    if (!hsmkey || perform_keydata_import(sockfd, db, zone, atoi(algorithm),
        state, type, (unsigned int)inception, policykey->minimize, hsmkey) ||
        dbw_commit(db))
    {
        ods_log_error("[%s] Error: Unable to add key to the database", module_str);
        dbw_free(db);
        return 1;
    }
    dbw_free(db);
    client_printf(sockfd, "Key imported into zone %s\n", zonename);
    return 0;
}

struct cmd_func_block key_import_funcblock = {
    "key import", &usage, &help, NULL, &run
};
