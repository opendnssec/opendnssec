/*
 * Copyright (c) 2014 Stichting NLnet Labs
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

#include <sys/stat.h>
#include <getopt.h>

#include "cmdhandler.h"
#include "daemon/engine.h"
#include "enforcer/enforce_task.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "duration.h"
#include "db/key_data.h"
#include "db/zone_db.h"
#include "db/db_error.h"
#include "db/hsm_key.h"
#include "libhsm.h"
#include "libhsmdns.h"

#include "keystate/keystate_ds.h"

static const char *module_str = "keystate_ds_x_cmd";

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

/** returns non 0 on error */
static int
exec_dnskey_by_id(int sockfd, key_data_t *key, const char* ds_command,
	const char* action)
{
	ldns_rr *dnskey_rr;
	int ttl = 0, status, i;
	const char *locator;
	char *rrstr, *chrptr;
	zone_db_t* zone;
	struct stat stat_ret;
        int cka = 0;
	char *pos = NULL;

	assert(key);

	zone = key_data_get_zone(key);
	if(key_data_cache_hsm_key(key) != DB_OK) {
		ods_log_error_and_printf(sockfd, module_str,
			"Error fetching from database");
		zone_db_free(zone);
		return 1;
	}
	locator = hsm_key_locator(key_data_hsm_key(key));
	if (!locator) {
		zone_db_free(zone);
		return 1;
	}
	/* This fetches the states from the DB, I'm only assuming they get
	 * cleaned up when 'key' is cleaned(?) */
	if (key_data_cache_key_states(key) != DB_OK) {
		zone_db_free(zone);
		return 1;
	}

	ttl = key_state_ttl(key_data_cached_dnskey(key));

	dnskey_rr = get_dnskey(locator, zone_db_name(zone), key_data_algorithm(key), ttl);
	zone_db_free(zone);
	if (!dnskey_rr) return 2;

	rrstr = ldns_rr2str(dnskey_rr);

	/* Replace tab with white-space */
	for (i = 0; rrstr[i]; ++i) {
		if (rrstr[i] == '\t') rrstr[i] = ' ';
	}

	/* We need to strip off trailing comments before we send
	 to any clients that might be listening */
	if ((chrptr = strchr(rrstr, ';'))) {
		chrptr[0] = '\n';
		chrptr[1] = '\0';
	}

	if (!ds_command || ds_command[0] == '\0') {
		ods_log_error_and_printf(sockfd, module_str, 
			"No \"DelegationSigner%sCommand\" "
			"configured.", action);
		status = 1;
	} else {
		pos = strstr(ds_command, " --cka_id");
                if (pos){
                        cka = 1;
                        *pos = '\0';
                        rrstr[strlen(rrstr)-1] = '\0';
                        pos = NULL;
                }

		if (stat(ds_command, &stat_ret) != 0) {
			ods_log_error_and_printf(sockfd, module_str,
				"Cannot stat file %s: %s", ds_command,
				strerror(errno));
			status = 2;
		} else if (S_ISREG(stat_ret.st_mode) && 
				!(stat_ret.st_mode & S_IXUSR || 
				  stat_ret.st_mode & S_IXGRP || 
				  stat_ret.st_mode & S_IXOTH)) {
			/* Then see if it is a regular file, then if usr, grp or 
			 * all have execute set */
			status = 3;
			ods_log_error_and_printf(sockfd, module_str,
				"File %s is not executable", ds_command);
		} else {
			/* send records to the configured command */
			FILE *fp = popen(ds_command, "w");
			if (fp == NULL) {
				status = 4;
				ods_log_error_and_printf(sockfd, module_str,
					"failed to run command: %s: %s",ds_command,
					strerror(errno));
			} else {
				int bytes_written;
				if (cka)
					bytes_written = fprintf(fp, "%s; {cka_id = %s}\n", rrstr, locator);
				else
					bytes_written = fprintf(fp, "%s", rrstr);
				if (bytes_written < 0) {
					status = 5;
					ods_log_error_and_printf(sockfd,  module_str,
						 "Failed to write to %s: %s", ds_command,
						 strerror(errno));
				} else if (pclose(fp) == -1) {
					status = 6;
					ods_log_error_and_printf(sockfd, module_str,
						"failed to close %s: %s", ds_command,
						strerror(errno));
				} else {
					client_printf(sockfd, "key %sed to %s\n",
						action, ds_command);
					status = 0;
				}
			}
		}
	}
	LDNS_FREE(rrstr);
	ldns_rr_free(dnskey_rr);
	return status;
}

static int
submit_dnskey_by_id(int sockfd, key_data_t *key, engine_type* engine)
{
	const char* ds_submit_command;
	ds_submit_command = engine->config->delegation_signer_submit_command;
	return exec_dnskey_by_id(sockfd, key, ds_submit_command, "submit");
}

static int
retract_dnskey_by_id(int sockfd, key_data_t *key, engine_type* engine)
{
	const char* ds_retract_command;
	ds_retract_command = engine->config->delegation_signer_retract_command;
	return exec_dnskey_by_id(sockfd, key, ds_retract_command, "retract");
}

static int
ds_list_keys(db_connection_t *dbconn, int sockfd,
	key_data_ds_at_parent_t state)
{
	const char *fmth = "%-31s %-13s %-13s %-40s\n";
	const char *fmtl = "%-31s %-13s %-13u %-40s\n";

	key_data_list_t *key_list;
	const key_data_t *key;
	zone_db_t *zone = NULL;
	hsm_key_t* hsmkey = NULL;
	db_clause_list_t* clause_list;
	db_clause_t* clause;

	if (!(key_list = key_data_list_new(dbconn))
		|| !(clause_list = db_clause_list_new()))
	{
		key_data_list_free(key_list);
		return 10;
	}
	if (!(clause = key_data_role_clause(clause_list, KEY_DATA_ROLE_ZSK))
		|| db_clause_set_type(clause, DB_CLAUSE_NOT_EQUAL)
		|| !(clause = key_data_ds_at_parent_clause(clause_list, state))
		|| db_clause_set_type(clause, DB_CLAUSE_EQUAL))
	{
		key_data_list_free(key_list);
		db_clause_list_free(clause_list);
		return 11;
	}
	if (key_data_list_get_by_clauses(key_list, clause_list)) {
		key_data_list_free(key_list);
		db_clause_list_free(clause_list);
		return 12;
	}
	db_clause_list_free(clause_list);

	client_printf(sockfd, fmth, "Zone:", "Key role:", "Keytag:", "Id:");

	for (key = key_data_list_next(key_list); key;
		key = key_data_list_next(key_list))
	{
		zone = key_data_get_zone(key);
		hsmkey = key_data_get_hsm_key(key);
		client_printf(sockfd, fmtl,
			(zone ? zone_db_name(zone) : "NOT_FOUND"),
			key_data_role_text(key), key_data_keytag(key),
			(hsmkey ? hsm_key_locator(hsmkey) : "NOT_FOUND")
		);
		zone_db_free(zone);
		hsm_key_free(hsmkey);
	}
	key_data_list_free(key_list);
	return 0;
}

static int
push_clauses(db_clause_list_t *clause_list, zone_db_t *zone,
	key_data_ds_at_parent_t state_from, const hsm_key_t* hsmkey, int keytag)
{
	db_clause_t* clause;

	if (!key_data_zone_id_clause(clause_list, zone_db_id(zone)))
		return 1;
	if (!(clause = key_data_role_clause(clause_list, KEY_DATA_ROLE_ZSK)) ||
			db_clause_set_type(clause, DB_CLAUSE_NOT_EQUAL))
		return 1;
	if (!key_data_ds_at_parent_clause(clause_list, state_from))
		return 1;

	/* filter in id and or keytag conditionally. */
	if (hsmkey) {
		if (hsmkey && !key_data_hsm_key_id_clause(clause_list, hsm_key_id(hsmkey)))
			return 1;
	}
	if (keytag > 0) {
		if (!key_data_keytag_clause(clause_list, keytag))
			return 1;
	}
	return 0;
}

/** Update timestamp on DS of key to now */
static int
ds_changed(key_data_t *key)
{
	key_state_list_t* keystatelist;
	key_state_t* keystate;

	if(key_data_retrieve_key_state_list(key)) return 1;
	keystatelist = key_data_key_state_list(key);
	keystate = key_state_list_get_begin(keystatelist);
	if (!keystate) return 1;

	while (keystate) {
		key_state_t* keystate_next;
		if (keystate->type == KEY_STATE_TYPE_DS) {
			keystate->last_change = time_now();
			if(key_state_update(keystate)) {
				key_state_free(keystate);
				return 1;
			}
			key_state_free(keystate);
			return 0;
		}
		keystate_next = key_state_list_get_next(keystatelist);
		key_state_free(keystate);
		keystate = keystate_next;
	}
	return 1;
}

/* Change DS state, when zonename not given do it for all zones!
 */
int
change_keys_from_to(db_connection_t *dbconn, int sockfd,
	const char *zonename, const hsm_key_t* hsmkey, int keytag,
	key_data_ds_at_parent_t state_from, key_data_ds_at_parent_t state_to,
	engine_type *engine)
{
	key_data_list_t *key_list = NULL;
	key_data_t *key;
	zone_db_t *zone = NULL;
	int status = 0, key_match = 0, key_mod = 0;
	db_clause_list_t* clause_list = NULL;
	db_clause_t* clause = NULL;
	char *tmp_zone_name;

	if (zonename) {
		if (!(key_list = key_data_list_new(dbconn)) ||
			!(clause_list = db_clause_list_new()) ||
			!(zone = zone_db_new_get_by_name(dbconn, zonename)) ||
			push_clauses(clause_list, zone, state_from, hsmkey, keytag) ||
			key_data_list_get_by_clauses(key_list, clause_list))
		{
			key_data_list_free(key_list);
			db_clause_list_free(clause_list);
			zone_db_free(zone);
			client_printf_err(sockfd, "Could not find ksk for zone %s, "
				"does zone exist?\n", zonename);
			ods_log_error("[%s] Error fetching from database", module_str);
			return 10;
		}
		db_clause_list_free(clause_list);
	} else {
		/* Select all KSKs */
		if (!(clause_list = db_clause_list_new()) ||
			!key_data_ds_at_parent_clause(clause_list, state_from) ||
			!(clause = key_data_role_clause(clause_list, KEY_DATA_ROLE_ZSK)) ||
			db_clause_set_type(clause, DB_CLAUSE_NOT_EQUAL) != DB_OK ||
			!(key_list = key_data_list_new_get_by_clauses(dbconn, clause_list)))
		{
			key_data_list_free(key_list);
			db_clause_list_free(clause_list);
			ods_log_error("[%s] Error fetching from database", module_str);
			return 14;
		}
		db_clause_list_free(clause_list);
	}
	while ((key = key_data_list_get_next(key_list))) {
		key_match++;
		/* if from is submit also exec dsSubmit command? */
		if (state_from == KEY_DATA_DS_AT_PARENT_SUBMIT &&
			state_to == KEY_DATA_DS_AT_PARENT_SUBMITTED)
		{
			(void)submit_dnskey_by_id(sockfd, key, engine);
		} else if (state_from == KEY_DATA_DS_AT_PARENT_RETRACT &&
			state_to == KEY_DATA_DS_AT_PARENT_RETRACTED)
		{
			(void)retract_dnskey_by_id(sockfd, key, engine);
		}

		if (key_data_set_ds_at_parent(key, state_to) ||
			key_data_update(key) || ds_changed(key) )
		{
			key_data_free(key);
			ods_log_error("[%s] Error writing to database", module_str);
			client_printf(sockfd, "[%s] Error writing to database", module_str);
			status = 12;
			break;
		}
		key_mod++;
		/* We need to schedule enforce for owner of key. */
		tmp_zone_name = zone_db_ext_zonename_from_id(dbconn, &key->zone_id);
		if (tmp_zone_name)
			enforce_task_flush_zone(engine, tmp_zone_name);
		free(tmp_zone_name);
		key_data_free(key);
	}
	key_data_list_free(key_list);

	client_printf(sockfd, "%d KSK matches found.\n", key_match);
	if (!key_match) status = 11;
	client_printf(sockfd, "%d KSKs changed.\n", key_mod);
	if (zone && key_mod > 0) {
		zone->next_change = 0; /* asap */
		(void)zone_db_update(zone);
	}
	zone_db_free(zone);
	return status;
}

int
run_ds_cmd(int sockfd, const char *cmd,
	db_connection_t *dbconn, key_data_ds_at_parent_t state_from,
	key_data_ds_at_parent_t state_to, engine_type *engine)
{
	#define NARGV 6
	const char *zonename = NULL, *cka_id = NULL, *keytag_s = NULL;
	int keytag = -1;
	hsm_key_t* hsmkey = NULL;
	int ret;
	char buf[ODS_SE_MAXLINE];
	zone_db_t* zone = NULL;
	int all = 0;
	int argc = 0, long_index = 0, opt = 0;
	const char* argv[NARGV];

	static struct option long_options[] = {
		{"zone", required_argument, 0, 'z'},
		{"cka_id", required_argument, 0, 'k'},
		{"keytag", required_argument, 0, 'x'},
		{"all", no_argument, 0, 'a'},
		{0, 0, 0, 0}
	};

	strncpy(buf, cmd, ODS_SE_MAXLINE);
	buf[sizeof(buf)-1] = '\0';
	argc = ods_str_explode(buf, NARGV, argv);
	if (argc == -1) {
		client_printf_err(sockfd, "too many arguments\n");
		ods_log_error("[%s] too many arguments for %s command",
				module_str, cmd);
		return -1;
	}

	optind = 0;
	while ((opt = getopt_long(argc, (char* const*)argv, "z:k:x:a", long_options, &long_index)) != -1) {
		switch (opt) {
			case 'z':
				zonename = optarg;
				break;
			case 'k':
				cka_id = optarg;
				break;
			case 'x':
				keytag_s = optarg;
				break;
			case 'a':
				all = 1;
				break;
			default:
				client_printf_err(sockfd, "unknown arguments\n");
				ods_log_error("[%s] unknown arguments for %s command",
						module_str, cmd);
				return -1;
		}
	}

	if (!all && !zonename && !cka_id && !keytag_s) {
		return ds_list_keys(dbconn, sockfd, state_from);
	}

	if (keytag_s) {
		keytag = atoi(keytag_s);
		if (keytag < 0 || keytag >= 65536) {
			ods_log_warning("[%s] value \"%d\" for --keytag is invalid",
				module_str, keytag);
                        client_printf_err(sockfd, "value \"%d\" for --keytag is invalid\n",
                                keytag);

			return 1;
		}
	}

	if (all && zonename) {
		ods_log_warning ("[%s] Error: Unable to use --zone and --all together", module_str);
		client_printf_err(sockfd, "Error: Unable to use --zone and --all together\n");
		return -1;
	}

	if (zonename && (!(zone = zone_db_new(dbconn)) || zone_db_get_by_name(zone, zonename))) {
		ods_log_warning ("[%s] Error: Unable to find a zone named \"%s\" in database\n", module_str, zonename);
	        client_printf_err(sockfd, "Error: Unable to find a zone named \"%s\" in database\n", zonename);
		zone_db_free(zone);
		zone = NULL;
        	return -1;
	}
	zone_db_free(zone);
	zone = NULL;
        if (!zonename && (keytag != -1 || cka_id)) {
                ods_log_warning ("[%s] Error: expected --zone <zone>", module_str);
                client_printf_err(sockfd, "Error: expected --zone <zone>\n");
                return -1;
        }

	if (!(zonename && ((cka_id && keytag == -1) || (!cka_id && keytag != -1))) && !all)
	{
		ods_log_warning("[%s] expected --zone and either --cka_id or "
			"--keytag option or expected --all", module_str);
		client_printf_err(sockfd, "expected --zone and either --cka_id or "
			"--keytag option or expected --all.\n");
		return -1;
	}
	
	if (cka_id && !(hsmkey = hsm_key_new_get_by_locator(dbconn, cka_id))) {
			client_printf_err(sockfd, "CKA_ID %s can not be found!\n", cka_id);
			return -1;
	}
	ret = change_keys_from_to(dbconn, sockfd, zonename, hsmkey, keytag,
		state_from, state_to, engine);
	hsm_key_free(hsmkey);
	return ret;
}
