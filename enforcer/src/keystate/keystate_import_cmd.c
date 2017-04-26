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
#include "db/key_data.h"
#include "db/db_error.h"

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


static int max(int a, int b) { return a>b?a:b; }
static int min(int a, int b) { return a<b?a:b; }


int
perform_hsmkey_import(int sockfd, db_connection_t *dbconn,
	const char *ckaid, const char *rep, const char *zonename, 
	int bits, int alg, int keytype, unsigned int time)
{
    hsm_ctx_t *hsm_ctx;
    hsm_key_t *hsm_key = NULL;
    char *hsm_err;
    libhsm_key_t *libhsmkey;
    zone_db_t *zone;
	
  /* Create an HSM context and check that the repository exists  */
    if (!(hsm_ctx = hsm_create_context())) {
        return -1;
    }
    if (!hsm_token_attached(hsm_ctx, rep)) {
        if ((hsm_err = hsm_get_error(hsm_ctx))) {
            ods_log_error("[%s] Error: Unable to check for the repository %s, HSM error: %s", module_str, rep, hsm_err);
            client_printf_err(sockfd, "Unable to check for the repository %s, HSM error: %s\n", rep, hsm_err);
            free(hsm_err);
        }
        else {
            ods_log_error("[%s] Error: Unable to find repository %s in HSM", module_str, rep);
            client_printf_err(sockfd, "Unable to find repository %s in HSM\n", rep);
        }
        hsm_destroy_context(hsm_ctx);
        return -1;
    }

    if (!(libhsmkey = hsm_find_key_by_id(hsm_ctx, ckaid))) {
	ods_log_error("[%s] Error: Unable to find the key with this locator: %s", module_str, ckaid);
	client_printf_err(sockfd, "Unable to find the key with this locator: %s\n", ckaid);
	hsm_destroy_context(hsm_ctx);
	return -1;
    }
    libhsm_key_free(libhsmkey);
    hsm_key = hsm_key_new_get_by_locator(dbconn, ckaid);
    if (hsm_key) {
        ods_log_error("[%s] Error: Already used this key with this locator: %s", module_str, ckaid);
        client_printf_err(sockfd, "Already used this key with this locator: %s\n", ckaid);
        hsm_key_free(hsm_key);
        hsm_destroy_context(hsm_ctx);
        return -1;
    }

    zone = zone_db_new_get_by_name(dbconn, zonename);
    if (!(hsm_key = hsm_key_new(dbconn))
                || hsm_key_set_algorithm(hsm_key, alg)
                || hsm_key_set_bits(hsm_key, bits)
                || hsm_key_set_inception(hsm_key, time)
                || hsm_key_set_key_type(hsm_key, HSM_KEY_KEY_TYPE_RSA)
                || hsm_key_set_locator(hsm_key, ckaid)
                || hsm_key_set_policy_id(hsm_key, zone_db_policy_id(zone))
                || hsm_key_set_repository(hsm_key, rep)
                || hsm_key_set_role(hsm_key, keytype)
                || hsm_key_set_state(hsm_key, (hsm_key_state_t)HSM_KEY_STATE_PRIVATE)
                || hsm_key_create(hsm_key))
    {
        ods_log_error("[%s] hsm key creation failed, database or memory error", module_str);
        hsm_key_free(hsm_key);                
        hsm_destroy_context(hsm_ctx);
        zone_db_free(zone);
        return -1;
    }
    ods_log_debug("[%s] hsm key with this locator %s is created successfully", module_str, ckaid);
    hsm_key_free(hsm_key);
    hsm_destroy_context(hsm_ctx);
    zone_db_free(zone);
    return 0;
}

int 
perform_keydata_import(int sockfd, db_connection_t *dbconn,
        const char *ckaid, const char *rep, const char *zonename,
        int alg, int keystate, int keytype, unsigned int time, int setmin, db_value_t *hsmkey_id)
{
    key_data_t *key_data = NULL;
    hsm_ctx_t *hsm_ctx;
    char *hsm_err;
    uint16_t tag;
    hsm_key_t * hsmkey;
    libhsm_key_t *libhsmkey;
    zone_db_t *zone;

    /* Create a HSM context and check that the repository exists  */
    if (!(hsm_ctx = hsm_create_context())) {
        return -1;
    }
    if (!hsm_token_attached(hsm_ctx, rep)) {
        if ((hsm_err = hsm_get_error(hsm_ctx))) {
            ods_log_error("[%s] Error: Unable to check for the repository %s, HSM error: %s", module_str, rep, hsm_err);
            client_printf_err(sockfd, "Unable to check for the repository %s, HSM error: %s\n", rep, hsm_err);
            free(hsm_err);
        }
        else {
            ods_log_error("[%s] Error: Unable to find repository %s in HSM", module_str, rep);
            client_printf_err(sockfd, "Unable to find repository %s in HSM\n", rep);
        }
        hsm_destroy_context(hsm_ctx);
        return -1;
    }

    if (!(libhsmkey = hsm_find_key_by_id(hsm_ctx, ckaid))) {
        ods_log_error("[%s] Error: Unable to find the key with this locator: %s", module_str, ckaid);
        client_printf_err(sockfd, "Unable to find the key with this locator: %s\n", ckaid);
        hsm_destroy_context(hsm_ctx);
        return -1;
    }
    libhsm_key_free(libhsmkey);
    if (!(hsmkey = hsm_key_new_get_by_locator(dbconn, ckaid))) {
        ods_log_error("[%s] Error: Cannot get hsmkey %s from database, database error", module_str, ckaid);
        hsm_destroy_context(hsm_ctx);
        return -1;
    }
    if (hsm_keytag(ckaid, alg, keytype == 1 ? 1 : 0, &tag)) {
        ods_log_error("[%s] Error: Keytag for this key %s is not correct", module_str, ckaid);
    }

    zone = zone_db_new_get_by_name(dbconn, zonename);
    if (!(key_data = key_data_new(dbconn))
                || key_data_set_zone_id(key_data, zone_db_id(zone))
                || key_data_set_hsm_key_id(key_data, hsm_key_id(hsmkey))
		|| key_data_set_algorithm (key_data, alg)
                || key_data_set_inception(key_data, time)
		|| key_data_set_introducing (key_data, keystate < 4 ? 1 : 0)
		|| key_data_set_active_zsk(key_data, keytype == 1 || keystate < 2 || keystate > 3 ? 0 : 1)
		|| key_data_set_publish(key_data,0 < keystate ? 1 : 0)
		|| key_data_set_active_ksk(key_data, keytype == 2 || keystate == 0 ? 0 : 1)
		|| key_data_set_role(key_data, keytype)
		|| key_data_set_ds_at_parent(key_data, keytype == 1 ? ds_at_parent[keystate] : 0)
		|| key_data_set_keytag(key_data, tag)
		|| key_data_set_minimize(key_data,setmin)
                || key_data_create(key_data))
    {
        ods_log_error("[%s] key data creation failed, database or memory error", module_str);
        hsm_key_free(hsmkey);
        key_data_free(key_data);
        hsm_destroy_context(hsm_ctx);
        zone_db_free(zone);
        return -1;
    }
    zone_db_free(zone);
    ods_log_debug("[%s] key data with this locator %s is created successfully", module_str, ckaid);
    key_data_free(key_data);
    hsm_destroy_context(hsm_ctx);
    db_value_copy (hsmkey_id, hsm_key_id(hsmkey));
    hsm_key_free(hsmkey);
    return 0;
}

int
perform_keystate_import(int sockfd, db_connection_t *dbconn,
        const char *ckaid, const char *rep, const char *zonename,
        int keystate, int keytype, unsigned int time, db_value_t *hsmkeyid)
{
    key_state_t *key_state = NULL;
    hsm_ctx_t *hsm_ctx;
    char *hsm_err;
    int ttl;
    key_data_t* key;
    const db_value_t* keydataid;
    policy_t* policy;
    libhsm_key_t *libhsmkey;
    zone_db_t *zone;

    /* Create a HSM context and check that the repository exists  */
    if (!(hsm_ctx = hsm_create_context())) {
        return -1;
    }
    if (!hsm_token_attached(hsm_ctx, rep)) {
        if ((hsm_err = hsm_get_error(hsm_ctx))) {
            ods_log_error("[%s] Error: Unable to check for the repository %s, HSM error: %s", module_str, rep, hsm_err);
            client_printf_err(sockfd, "Unable to check for the repository %s, HSM error: %s\n", rep, hsm_err);
            free(hsm_err);
        }
        else {
            ods_log_error("[%s] Error: Unable to find repository %s in HSM", module_str, rep);
            client_printf_err(sockfd, "Unable to find repository %s in HSM\n", rep);
        }
        hsm_destroy_context(hsm_ctx);
        return -1;
    }

    if (!(libhsmkey = hsm_find_key_by_id(hsm_ctx, ckaid))) {
        ods_log_error("[%s] Error: Unable to find the key with this locator: %s", module_str, ckaid);
        client_printf(sockfd, "Unable to find the key with this locator: %s\n", ckaid);
        hsm_destroy_context(hsm_ctx);
        return -1;
    }
    libhsm_key_free(libhsmkey);
    key = key_data_new_get_by_hsm_key_id(dbconn, hsmkeyid);
    keydataid = key_data_id(key);

    policy = policy_new(dbconn);
    zone = zone_db_new_get_by_name(dbconn, zonename);
    policy_get_by_id(policy, zone_db_policy_id(zone));
    zone_db_free(zone);

    if (!(key_state = key_state_new(dbconn))
                || key_state_set_key_data_id(key_state, keydataid)
                || key_state_set_type(key_state, KEY_STATE_TYPE_DS)
                || key_state_set_last_change (key_state, time)
                || key_state_set_minimize(key_state, (key_data_minimize(key) >> 2) & 1)
                || key_state_set_ttl (key_state, policy_parent_ds_ttl(policy))
		|| key_state_set_state(key_state, keytype == 1 ? ksk_mapping[keystate][0] : zsk_mapping[keystate][0])
                || key_state_create(key_state))
    {
        ods_log_error("[%s] key state creation for DS failed, database or memory error", module_str);
        key_data_free(key);
        policy_free(policy);
        key_state_free(key_state);
        hsm_destroy_context(hsm_ctx);
        return -1;
    }
    key_state_free(key_state);

    if (!(key_state = key_state_new(dbconn))
                || key_state_set_key_data_id(key_state, keydataid)
                || key_state_set_type(key_state, KEY_STATE_TYPE_DNSKEY)
                || key_state_set_last_change (key_state, time)
                || key_state_set_minimize(key_state, (key_data_minimize(key) >> 1) & 1)
                || key_state_set_ttl (key_state, policy_keys_ttl(policy))
		|| key_state_set_state(key_state, keytype == 1 ? ksk_mapping[keystate][1] : zsk_mapping[keystate][1])
                || key_state_create(key_state))
    {
        ods_log_error("[%s] key state creation for DNSKEY failed, database or memory error", module_str);
        key_data_free(key);
        policy_free(policy);
        key_state_free(key_state);
        hsm_destroy_context(hsm_ctx);
        return -1;
    }
    key_state_free(key_state);

    if (!(key_state = key_state_new(dbconn))
                || key_state_set_key_data_id(key_state, keydataid)
                || key_state_set_type(key_state, KEY_STATE_TYPE_RRSIGDNSKEY)
                || key_state_set_last_change (key_state, time)
                || key_state_set_ttl (key_state, policy_keys_ttl(policy))
                || key_state_set_state(key_state, keytype == 1 ? ksk_mapping[keystate][2] : zsk_mapping[keystate][2])
                || key_state_create(key_state))
    {
        ods_log_error("[%s] key state creation for RRSIGDNSKEY failed, database or memory error", module_str);
        key_data_free(key);
        policy_free(policy);
        key_state_free(key_state);
        hsm_destroy_context(hsm_ctx);
        return -1;
    }
    key_state_free(key_state);

    ttl = max(min(policy_zone_soa_ttl(policy), policy_zone_soa_minimum(policy)),
            (policy_denial_type(policy) == POLICY_DENIAL_TYPE_NSEC3
                ? ( policy_denial_ttl(policy) > policy_signatures_max_zone_ttl(policy)
                    ? policy_denial_ttl(policy)
                    : policy_signatures_max_zone_ttl(policy))
                : policy_signatures_max_zone_ttl(policy)));

    if (!(key_state = key_state_new(dbconn))
                || key_state_set_key_data_id(key_state, keydataid)
       /*         || hsm_key_set_backup(hsm_key, (hsm->require_backup ? HSM_KEY_BACKUP_BACKUP_REQUIRED : HSM_KEY_BACKUP_NO_BACKUP))*/
                || key_state_set_type(key_state, KEY_STATE_TYPE_RRSIG)
                || key_state_set_last_change (key_state, time)
                || key_state_set_minimize(key_state, key_data_minimize(key) & 1)
                || key_state_set_ttl (key_state, ttl)
                || key_state_set_state(key_state, keytype == 1 ? ksk_mapping[keystate][3] : zsk_mapping[keystate][3])
                || key_state_create(key_state))
    {
        ods_log_error("[%s] key state creation for RRSIG failed, database or memory error", module_str);
        key_data_free(key);
        policy_free(policy);
        key_state_free(key_state);
        hsm_destroy_context(hsm_ctx);
        return -1;
    }
    ods_log_debug("[%s] key state with this locator %s is created successfully", module_str, ckaid);

    key_data_free(key);
    policy_free(policy);
    key_state_free(key_state);
    hsm_destroy_context(hsm_ctx);

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
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
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
    zone_db_t *zone = NULL;
    time_t inception = 0;
    struct tm tm;
    int setmin;
    db_value_t *hsmkey_id;
    policy_key_t *policy_key;
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
    if (zonename && !(zone = zone_db_new_get_by_name(dbconn, zonename))) {
        ods_log_error("[%s] Unknown zone: %s", module_str, zonename);
        client_printf_err(sockfd, "Unknown zone: %s\n", zonename);
        return -1;
    }
    free(zone);
    zone = NULL;

    if (!algorithm) {
        ods_log_error("[%s] specify an algorithm for command %s", module_str, cmd);
        client_printf_err(sockfd, "specify an algorithm\n");
        return -1;
    }
    if (!bits) {
        ods_log_error("[%s] specify bits for command %s", module_str, cmd);
        client_printf_err(sockfd, "specify bits\n");
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
    }
    else {
        ods_log_error("[%s] specify inception time for command %s", module_str, cmd);
        client_printf_err(sockfd, "specify inception time YYYY-MM-DD-HH:MM:SS\n");
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

    int type = -1;
    if (!strcasecmp(keytype, "KSK"))
        type = 1;
    else if (!strcasecmp(keytype, "ZSK"))
        type = 2;
    else if (!strcasecmp(keytype, "CSK"))
        type = 3;

    hsmkey_id = db_value_new();
    zone = zone_db_new_get_by_name(dbconn, zonename);
    policy_key = policy_key_new_get_by_policyid_and_role(dbconn, zone_db_policy_id(zone), type);
    zone_db_free(zone);
    if (!policy_key) {
        ods_log_error("Unable to get policyKey, database error!");
        client_printf_err(sockfd, "Unable to get policyKey, database error!\n");
        db_value_free((void*)hsmkey_id);
        return -1;
    }
    if (atoi(algorithm) != policy_key_algorithm(policy_key)) {
        ods_log_error("Error: the given algorithm in import command doesn't match the algorithm in kasp");
        client_printf_err(sockfd, "The given algorithm doesn't match the algorithm in kasp\n");
        db_value_free((void*)hsmkey_id);
        policy_key_free(policy_key);
        return -1;
    }

    setmin = policy_key_minimize(policy_key);
    policy_key_free(policy_key);

    /* perform task immediately */
    if (perform_hsmkey_import(sockfd, dbconn, ckaid, repository, zonename, atoi(bits), atoi(algorithm), type, (unsigned int)inception)
        || perform_keydata_import(sockfd, dbconn, ckaid, repository, zonename, atoi(algorithm), state, type, (unsigned int)inception, setmin, hsmkey_id)
        || perform_keystate_import(sockfd, dbconn, ckaid, repository, zonename, state, type, (unsigned int)inception, hsmkey_id)) {
        ods_log_error("[%s] Error: Unable to add key to the database", module_str);
        db_value_free((void*)hsmkey_id);
        return -1;
    } 
    db_value_free((void*)hsmkey_id);
    client_printf(sockfd, "Key imported into zone %s\n", zonename);
    return 0;
}

struct cmd_func_block key_import_funcblock = {
    "key import", &usage, &help, NULL, &run
};
