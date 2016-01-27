/*
 * Copyright (c) 2011 Surfnet 
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2011 OpenDNSSEC AB (svb)
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

#include "daemon/cmdhandler.h"
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

#include "keystate/keystate_export_cmd.h"
#include "keystate/keystate_list_cmd.h"

static const char *module_str = "keystate_export_cmd";

/** Retrieve KEY from HSM, should only be called for DNSKEYs
 * @param id, locator of DNSKEY on HSM
 * @param zone, name of zone key belongs to
 * @param algorithm, alg of DNSKEY
 * @param ttl, ttl DS should get. if 0 DNSKEY_TTL is used.
 * @return RR on succes, NULL on error */
static ldns_rr *
get_dnskey(const char *id, const char *zone, const char *keytype, int alg, uint32_t ttl)
{
	libhsm_key_t *key;
	hsm_sign_params_t *sign_params;
	ldns_rr *dnskey_rr;
	/* Code to output the DNSKEY record  (stolen from hsmutil) */
	hsm_ctx_t *hsm_ctx = hsm_create_context();
	if (!hsm_ctx) {
		ods_log_error("[%s] Could not connect to HSM", module_str);
		return NULL;
	}
	if (!(key = hsm_find_key_by_id(hsm_ctx, id))) {
		hsm_destroy_context(hsm_ctx);
		return NULL;
	}

	/* Sign params only need to be kept around 
	 * for the hsm_get_dnskey() call. */
	sign_params = hsm_sign_params_new();
	sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zone);
	sign_params->algorithm = (ldns_algorithm) alg;
	sign_params->flags = LDNS_KEY_ZONE_KEY;

	if (keytype && !strcasecmp(keytype, "KSK"))
		sign_params->flags = sign_params->flags | LDNS_KEY_SEP_KEY;
		
	/* Get the DNSKEY record */
	dnskey_rr = hsm_get_dnskey(hsm_ctx, key, sign_params);

	free(key);
	hsm_sign_params_free(sign_params);
	hsm_destroy_context(hsm_ctx);
	
	/* Override the TTL in the dnskey rr */
	if (ttl) ldns_rr_set_ttl(dnskey_rr, ttl);
	
	return dnskey_rr;
}

/**
 * Print DNSKEY record or SHA1 and SHA256 DS records, should only be
 * called for DNSKEYs.
 *
 * @param sockfd, Where to print to
 * @param key, Key to be printed. Must not be NULL.
 * @param zone, name of zone key belongs to. Must not be NULL.
 * @param bind_style, bool. print DS rather than DNSKEY rr.
 * @return 1 on succes 0 on error
 */
static int 
print_ds_from_id(int sockfd, key_data_t *key, const char *zone,
	const char* state, int bind_style)
{
	ldns_rr *dnskey_rr;
	ldns_rr *ds_sha_rr;
	int ttl = 0;
	const char *locator;
	char *rrstr;

	assert(key);
	assert(zone);

	locator = hsm_key_locator(key_data_hsm_key(key));
	if (!locator) return 1;
	/* This fetches the states from the DB, I'm only assuming they get
	 * cleaned up when 'key' is cleaned(?) */
	if (key_data_cache_key_states(key) != DB_OK)
		return 1;

	ttl = key_state_ttl(key_data_cached_dnskey(key));

	dnskey_rr = get_dnskey(locator, zone, key_data_role_text(key), key_data_algorithm(key), ttl);
	if (!dnskey_rr) return 1;

	if (bind_style) {
		ldns_rr_set_ttl(dnskey_rr, key_state_ttl (key_data_cached_ds(key)));
		ds_sha_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA1);
		rrstr = ldns_rr2str(ds_sha_rr);
		ldns_rr_free(ds_sha_rr);
		/* TODO log error on failure */
		(void)client_printf(sockfd, ";%s %s DS record (SHA1):\n%s", state, key_data_role_text(key), rrstr);
		LDNS_FREE(rrstr);

		ds_sha_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA256);
		rrstr = ldns_rr2str(ds_sha_rr);
		ldns_rr_free(ds_sha_rr);
		/* TODO log error on failure */
		(void)client_printf(sockfd, ";%s %s DS record (SHA256):\n%s", state, key_data_role_text(key), rrstr);
		LDNS_FREE(rrstr);
	} else {
		rrstr = ldns_rr2str(dnskey_rr);
		/* TODO log error on failure */
		(void)client_printf(sockfd, "%s", rrstr);
		LDNS_FREE(rrstr);
	}
	
	ldns_rr_free(dnskey_rr);
	return 0;
}

static int
perform_keystate_export(int sockfd, db_connection_t *dbconn,
	const char *zonename, const char *keytype, const char *keystate, int all, int bind_style)
{
	key_data_list_t *key_list = NULL;
	key_data_t *key;
	zone_t *zone = NULL;
	db_clause_list_t* clause_list = NULL;
	const char *azonename = NULL;

	/* Find all keys related to zonename */
	if (all == 0) { 
		if (!(key_list = key_data_list_new(dbconn)) ||
			!(clause_list = db_clause_list_new()) ||
			!(zone = zone_new_get_by_name(dbconn, zonename)) ||
			!key_data_zone_id_clause(clause_list, zone_id(zone)) ||
			key_data_list_get_by_clauses(key_list, clause_list))
		{
			key_data_list_free(key_list);
			db_clause_list_free(clause_list);
			zone_free(zone);
			ods_log_error("[%s] Error fetching from database", module_str);
			return 1;
		}
		db_clause_list_free(clause_list);
		zone_free(zone);
	}
	if (all && !(key_list = key_data_list_new_get(dbconn))) {
		client_printf_err(sockfd, "Unable to get list of keys, memory allocation or database error!\n");
		return 1;
	}
	
	/* Print data*/
	while ((key = key_data_list_get_next(key_list))) {
		if (keytype && strcasecmp(key_data_role_text(key), keytype)) {
			key_data_free(key);
			continue;
		}
		if (keystate && strcasecmp(map_keystate(key), keystate)) {
			key_data_free(key);
			continue;
		}
		if (!keytype && !keystate && 
			key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_SUBMIT    &&
			key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_SUBMITTED &&
			key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_RETRACT   &&
			key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_RETRACTED)
		{
			key_data_free(key);
			continue;
		}

		if (all && (!(zone = zone_new (dbconn)) || (zone_get_by_id(zone, key_data_zone_id(key))) || !(azonename = zone_name(zone)))) {
                        ods_log_error("[%s] Error fetching from database", module_str);
                        client_printf_err(sockfd, "Error fetching from database \n");
		}

                /* check return code TODO */	
		if (key_data_cache_hsm_key(key) == DB_OK) {
			if (print_ds_from_id(sockfd, key, (const char*)azonename?azonename:zonename, (const char*)map_keystate(key), bind_style)) {
				ods_log_error("[%s] Error in print_ds_from_id", module_str);
				client_printf_err(sockfd, "Error in print_ds_from_id \n");
			}

		} else {
			ods_log_error("[%s] Error fetching from database", module_str);
			client_printf_err(sockfd, "Error fetching from database \n");
		}
		key_data_free(key);

		if (all)
			zone_free(zone);
	}
	key_data_list_free(key_list);
	return 0;
}

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key export             Export DNSKEY(s) for a given zone.\n"
		"      --zone <zone>  | --all		(aka -z)  zone | (aka -a) all zones\n"
		"      [--keystate <state>]		(aka -e) state\n"
		"      [--keytype <type>]		(aka -t) type \n"
		"      [--ds]				(aka -d)  export DS in BIND format.\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_export_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	#define NARGV 8
	char buf[ODS_SE_MAXLINE];
	const char *argv[NARGV];
	int argc;
	const char *zonename = NULL;
	const char* keytype = NULL;
	const char* keystate = NULL;
	zone_t * zone = NULL;
	int all = 0;
	(void)engine;
	
	ods_log_debug("[%s] %s command", module_str, key_export_funcblock()->cmdname);
	cmd = ods_check_command(cmd, n, key_export_funcblock()->cmdname);
	
	/* Use buf as an intermediate buffer for the command.*/
	strncpy(buf, cmd, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	
	/* separate the arguments*/
	argc = ods_str_explode(buf, NARGV, argv);
	if (argc > NARGV) {
		ods_log_error("[%s] too many arguments for %s command",
						module_str, key_export_funcblock()->cmdname);
		client_printf_err(sockfd,"too many arguments\n");
		return -1;
	}
	
	bool bds = 0;
	(void)ods_find_arg_and_param(&argc,argv,"zone","z",&zonename);
	(void)ods_find_arg_and_param(&argc, argv, "keytype", "t", &keytype);
	(void)ods_find_arg_and_param(&argc, argv, "keystate", "e", &keystate);
	all = ods_find_arg(&argc, argv, "all", "a") > -1 ? 1 : 0;

	if (keytype) {
		if (strcasecmp(keytype, "KSK") && strcasecmp(keytype, "ZSK") && strcasecmp(keytype, "CSK")) {
			ods_log_error("[%s] unknown keytype, should be one of KSK, ZSK, or CSK", module_str);
			client_printf_err(sockfd, "unknown keytype, should be one of KSK, ZSK, or CSK\n");
			return -1;
		}	
	}

	if (keystate) {
		if (strcasecmp(keystate, "generate") && strcasecmp(keystate, "publish") && strcasecmp(keystate, "ready") && strcasecmp(keystate, "active") && strcasecmp(keystate, "retire") && strcasecmp(keystate, "revoke")) {
			ods_log_error("[%s] unknown keystate", module_str);
			client_printf_err(sockfd, "unknown keystate\n");
			return -1;
		} 
	}

	if (ods_find_arg(&argc,argv,"ds","d") >= 0) bds = 1;

	if (argc) {
		ods_log_error("[%s] unknown arguments for %s command",
						module_str, key_export_funcblock()->cmdname);
		client_printf_err(sockfd,"unknown arguments\n");
		return -1;
	}

	if ((!zonename && !all) || (zonename && all)) {
		ods_log_error("[%s] expected either --zone or --all for %s command", module_str, key_export_funcblock()->cmdname);
		client_printf_err(sockfd, "expected either --zone or --all \n");
		return -1;
	}
	if (zonename && !(zone = zone_new_get_by_name(dbconn, zonename))) {
		ods_log_error("[%s] Unknown zone: %s", module_str, zonename);
		client_printf_err(sockfd, "Unknown zone: %s\n", zonename);
		return -1;
	}
	free(zone);
	zone = NULL;
	
	/* in 1.4 the default state for ZSK is active */
	if (keytype && !strcasecmp(keytype, "ZSK") && !keystate)
		keystate = "active";
	/* in 1.4 the dafault type is KSK */
	else if (keystate && !keytype)
		keytype = "KSK";
	else if (keytype && !strcasecmp(keytype, "KSK") && !keystate)
		keytype = NULL; 

	/* perform task immediately */
	return perform_keystate_export(sockfd, dbconn, zonename, (const char*) keytype, (const char*) keystate, all, bds?1:0);
}

static struct cmd_func_block funcblock = {
	"key export", &usage, NULL, &handles, &run
};

struct cmd_func_block*
key_export_funcblock(void)
{
	return &funcblock;
}
