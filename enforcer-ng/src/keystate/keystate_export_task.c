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
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
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

#include "daemon/engine.h"
#include "daemon/clientpipe.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/duration.h"
#include "libhsm.h"
#include "libhsmdns.h"
#include "db/key_data.h"

#include "keystate/keystate_export_task.h"

static const char *module_str = "keystate_export_task";

/** Retrieve KEY from HSM, should only be called for DNSKEYs
 * @param id, locator of DNSKEY on HSM
 * @param zone, name of zone key belongs to
 * @param algorithm, alg of DNSKEY
 * @param ttl, ttl DS should get. if 0 DNSKEY_TTL is used.
 * @return RR on succes, NULL on error */
static ldns_rr *
get_dnskey(const char *id, const char *zone, int alg, uint32_t ttl)
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
	sign_params->flags = LDNS_KEY_ZONE_KEY | LDNS_KEY_SEP_KEY;
		
	/* Get the DNSKEY record */
	dnskey_rr = hsm_get_dnskey(hsm_ctx, key, sign_params);

	libhsm_key_free(key);
	hsm_sign_params_free(sign_params);
	hsm_destroy_context(hsm_ctx);
	
	/* Override the TTL in the dnskey rr */
	if (ttl) ldns_rr_set_ttl(dnskey_rr, ttl);
	
	return dnskey_rr;
}

/** get DNSKEY record and keytag, should only be called for DNSKEYs
 * @param[out] dnskey, DNSKEY in zonefile format
 * @param id, locator of DNSKEY on HSM
 * @param zone, name of zone key belongs to
 * @param algorithm, alg of DNSKEY
 * @param ttl, ttl DS should get. if 0 DNSKEY_TTL is used.
 * @return keytag on succes, 0 on error 
 * 
 * TODO: KEYTAG could very well be 0 THIS is not the right way to 
 * flag succes! */
static int 
print_dnskey_from_id(int sockfd, key_data_t *key, const char *zone)
{

	ldns_rr *dnskey_rr;
	const key_state_t *state;
	int ttl = 0;
	const hsm_key_t *hsmkey;
	const char *locator;
	char *rrstr;

	assert(key);
	assert(zone);

	hsmkey = key_data_hsm_key(key);
	locator = hsm_key_locator(hsmkey);
	key_data_cache_key_states(key);

	state = key_data_cached_dnskey(key);
	ttl = key_state_ttl(state);

	if (!locator) return 1;
	dnskey_rr = get_dnskey(locator, zone, key_data_algorithm(key), ttl);
	if (!dnskey_rr) return 1;

	rrstr = ldns_rr2str(dnskey_rr);
	ldns_rr_free(dnskey_rr);

	if (!client_printf(sockfd, "%s", rrstr)) {
		LDNS_FREE(rrstr);
		return 1;
	}
	LDNS_FREE(rrstr);
	return 0;
}

/** Print SHA1 and SHA256 DS records, should only be called for DNSKEYs
 * @param sockfd, Where to print to
 * @param id, locator of DNSKEY on HSM
 * @param zone, name of zone key belongs to
 * @param algorithm, alg of DNSKEY
 * @param ttl, ttl DS should get. if 0 DNSKEY_TTL is used.
 * @return 1 on succes 0 on error */
//~ static int 
//~ print_ds_from_id(int sockfd, const char *id, const char *zone, 
	//~ int algorithm, uint32_t ttl)
//~ {
	//~ ldns_rr *dnskey_rr = get_dnskey(id, zone, algorithm, ttl);
	//~ if (!dnskey_rr) return 0;
	//~ char *rrstr;
	//~ ldns_rr *ds_sha_rr;
	//~ 
	//~ /* DS record (SHA1) */
	//~ ds_sha_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA1);
	//~ rrstr = ldns_rr2str(ds_sha_rr);
	//~ client_printf(sockfd, ";KSK DS record (SHA1):\n%s", rrstr);
	//~ LDNS_FREE(rrstr);
	//~ ldns_rr_free(ds_sha_rr);
	//~ 
	//~ /* DS record (SHA256) */
	//~ ds_sha_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA256);
	//~ rrstr = ldns_rr2str(ds_sha_rr);
	//~ client_printf(sockfd, ";KSK DS record (SHA256):\n%s", rrstr);
	//~ LDNS_FREE(rrstr);
	//~ ldns_rr_free(ds_sha_rr);
//~ 
	//~ ldns_rr_free(dnskey_rr);
	//~ return 1;
//~ }
static int 
print_ds_from_id(int sockfd, key_data_t *key, const char *zone)
{

	ldns_rr *dnskey_rr;
	ldns_rr *ds_sha_rr;
	const key_state_t *state;
	int ttl = 0;
	const hsm_key_t *hsmkey;
	const char *locator;
	char *rrstr;

	assert(key);
	assert(zone);

	hsmkey = key_data_hsm_key(key);
	locator = hsm_key_locator(hsmkey);
	key_data_cache_key_states(key);

	state = key_data_cached_dnskey(key);
	ttl = key_state_ttl(state);

	if (!locator) return 1;
	dnskey_rr = get_dnskey(locator, zone, key_data_algorithm(key), ttl);
	if (!dnskey_rr) return 1;

	ds_sha_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA1);
	rrstr = ldns_rr2str(ds_sha_rr);
	ldns_rr_free(dnskey_rr);

	if (!client_printf(sockfd, "%s", rrstr)) {
		LDNS_FREE(rrstr);
		return 1;
	}
	LDNS_FREE(rrstr);
	return 0;
}
//~ static bool
//~ load_kasp_policy(OrmConn conn,const std::string &name,
				//~ ::ods::kasp::Policy &policy)
//~ {
	//~ std::string qname;
	//~ if (!OrmQuoteStringValue(conn, name, qname))
		//~ return false;
	//~ 
	//~ OrmResultRef rows;
	//~ if (!OrmMessageEnumWhere(conn,policy.descriptor(),rows,
							 //~ "name=%s",qname.c_str()))
		//~ return false;
	//~ 
	//~ if (!OrmFirst(rows))
		//~ return false;
	//~ 
	//~ return OrmGetMessage(rows, policy, true);
//~ }

/**
 * @param bds: bool bind format DS
 * 
 *@return: 1 on failure, 0 success 
 */
int 
perform_keystate_export(int sockfd,
	db_connection_t *dbconn,
	const char *zonename, int bds)
{
	key_data_list_t *key_list = NULL;
	key_data_t *key;
	zone_t *zone = NULL;
	db_clause_list_t* clause_list = NULL;


	/* Find all keys related to zonename */
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
	
	//TODO FETCH TTL FROM POLICY

	/* loop over all keys */
	while ((key = key_data_list_get_next(key_list))) {
		/* SKIP anything not KSK */
		if (!(key_data_role(key) & KEY_DATA_ROLE_KSK)) {
			key_data_free(key);
			continue;
		}
		if (key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_SUBMIT &&
			key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_SUBMITTED &&
			key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_RETRACT &&
			key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_RETRACTED)
		{
			key_data_free(key);
			continue;
		}
		/* check return code TODO */
		key_data_cache_hsm_key(key);
		//STUFF
		if (!bds) {
			if (print_dnskey_from_id(sockfd, key, zonename))
				ods_log_error("[%s] Error", module_str);
		} else {
			if (print_ds_from_id(sockfd, key, zonename))
				ods_log_error("[%s] Error", module_str);
		}

		key_data_free(key);
	}
	key_data_list_free(key_list);
	return 0;
}
