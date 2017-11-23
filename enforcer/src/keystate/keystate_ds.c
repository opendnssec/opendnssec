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
#include "db/dbw.h"
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
exec_dnskey_by_id(int sockfd, struct dbw_key *key, const char* ds_command,
	const char* action)
{
	ldns_rr *dnskey_rr;
	int status, i;
	char *rrstr, *chrptr, *cp_ds;
	struct stat stat_ret;
        int cka = 0;
	char *pos = NULL;

	assert(key);
	char *locator = key->hsmkey->locator;
	struct dbw_keystate *dnskey = dbw_get_keystate(key, DBW_DNSKEY);
	if (!dnskey) return 1;
	dnskey_rr = get_dnskey(locator, key->zone->name, key->algorithm, dnskey->ttl);
	if (!dnskey_rr) return 2;
	rrstr = ldns_rr2str(dnskey_rr);

	/* Replace tab with space */
	for (i = 0; rrstr[i]; ++i) {
		if (rrstr[i] == '\t') rrstr[i] = ' ';
	}

	/* We need to strip off trailing comments before we send
	 to any clients that might be listening */
	if ((chrptr = strchr(rrstr, ';'))) {
		chrptr[0] = '\n';
		chrptr[1] = '\0';
	}

        cp_ds = strdup(ds_command);

	if (!ds_command || ds_command[0] == '\0') {
		ods_log_error_and_printf(sockfd, module_str, 
			"No \"DelegationSigner%sCommand\" "
			"configured.", action);
		status = 1;
	} else {
                pos = strstr(cp_ds, " --cka_id");
                if (pos){
                        cka = 1;
                        *pos = '\0';
                        rrstr[strlen(rrstr)-1] = '\0';
                        pos = NULL;
                }

		if (stat(cp_ds, &stat_ret) != 0) {
			ods_log_error_and_printf(sockfd, module_str,
				"Cannot stat file %s: %s", cp_ds,
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
				"File %s is not executable", cp_ds);
		} else {
			/* send records to the configured command */
			FILE *fp = popen(cp_ds, "w");
			if (fp == NULL) {
				status = 4;
				ods_log_error_and_printf(sockfd, module_str,
					"failed to run command: %s: %s",cp_ds,
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
						 "[%s] Failed to write to %s: %s", cp_ds,
						 strerror(errno));
				} else if (pclose(fp) == -1) {
					status = 6;
					ods_log_error_and_printf(sockfd, module_str,
						"failed to close %s: %s", cp_ds,
						strerror(errno));
				} else {
					ods_log_info("key %sed to %s\n",
						action, cp_ds);
					status = 0;
				}
			}
		}
	}
	LDNS_FREE(rrstr);
	ldns_rr_free(dnskey_rr);
	free(cp_ds);
	return status;
}

static int
submit_dnskey_by_id(int sockfd, struct dbw_key *key, engine_type* engine)
{
    const char* ds_submit_command;
    ds_submit_command = engine->config->delegation_signer_submit_command;
    return exec_dnskey_by_id(sockfd, key, ds_submit_command, "submit");
}

static int
retract_dnskey_by_id(int sockfd, struct dbw_key *key, engine_type* engine)
{
    const char* ds_retract_command;
    ds_retract_command = engine->config->delegation_signer_retract_command;
    return exec_dnskey_by_id(sockfd, key, ds_retract_command, "retract");
}

static int
ds_list_keys(db_connection_t *dbconn, int sockfd, enum dbw_ds_at_parent state)
{
    const char *fmth = "%-31s %-13s %-13s %-40s\n";
    const char *fmtl = "%-31s %-13s %-13u %-40s\n";

    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) return 1;

    client_printf(sockfd, fmth, "Zone:", "Key role:", "Keytag:", "Id:");
    for (size_t z = 0; z < db->zones->n; z++) {
        struct dbw_zone *zone = (struct dbw_zone *)db->zones->set[z];
        for (size_t k = 0; k < zone->key_count; k++) {
            struct dbw_key *key = zone->key[k];
            if (!(key->role & DBW_KSK)) continue;
            if (key->ds_at_parent != state) continue;
            client_printf(sockfd, fmtl, zone->name,
                dbw_enum2txt(dbw_key_role_txt, key->role), key->keytag,
                key->hsmkey->locator);
        }
    }
    dbw_free(db);
    return 0;
}

/* Change DS state, when zonename not given do it for all zones!
 */
int
change_keys_from_to(db_connection_t *dbconn, int sockfd, const char *zonename,
    const char *cka_id, int keytag, int state_from,
    int state_to, engine_type *engine)
{
    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) return 1;

    int key_match = 0;
    for (size_t z = 0; z < db->zones->n; z++) {
        struct dbw_zone *zone = (struct dbw_zone *)db->zones->set[z];
        if (zonename && strcmp(zonename, zone->name)) continue;
        for (size_t k = 0; k < zone->key_count; k++) {
            struct dbw_key *key = zone->key[k];
            if (!(key->role & DBW_KSK)) continue;
            if (state_from != key->ds_at_parent) continue;
            if ((keytag != -1) && key->keytag != keytag) continue;
            if (cka_id && strcmp(key->hsmkey->locator, cka_id)) continue;
            key_match++;
            /* if from is submit also exec dsSubmit command? */
            if (state_from == DBW_DS_AT_PARENT_SUBMIT &&
                    state_to == DBW_DS_AT_PARENT_SUBMITTED)
            {
                (void)submit_dnskey_by_id(sockfd, key, engine);
            }
            else if (state_from == DBW_DS_AT_PARENT_RETRACT &&
                    state_to == DBW_DS_AT_PARENT_RETRACTED)
            {
                (void)retract_dnskey_by_id(sockfd, key, engine);
            }
            key->ds_at_parent = state_to;
            key->dirty = DBW_UPDATE;
            zone->scratch = 1;
            struct dbw_keystate *dnskey = dbw_get_keystate(key, DBW_DS);
            dnskey->last_change = time_now();
            dnskey->dirty = DBW_UPDATE;
        }
    }
    if (dbw_commit(db)) {
        dbw_free(db);
        client_printf_err(sockfd, "Error committing to database");
        return 1;
    }
    for (size_t z = 0; z < db->zones->n; z++) {
        struct dbw_zone *zone = (struct dbw_zone *)db->zones->set[z];
        if (!zone->scratch) continue;
        enforce_task_flush_zone(engine, zone->name);
    }
    dbw_free(db);
    client_printf(sockfd, "%d KSK matches found.\n", key_match);
    client_printf(sockfd, "%d KSKs changed.\n", key_match);
    return (!key_match);
}

int
run_ds_cmd(int sockfd, const char *cmd, db_connection_t *dbconn, int state_from,
	int state_to, engine_type *engine)
{
	#define NARGV 6
	const char *zonename = NULL, *cka_id = NULL, *keytag_s = NULL;
	int keytag = -1;
	int ret;
	char buf[ODS_SE_MAXLINE];
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

	/* With no options we list everything in state_from */
	if (!all && !zonename && !cka_id && !keytag_s) {
		return ds_list_keys(dbconn, sockfd, state_from);
	}

	/* At this point (zonename must be given and either id, tag) or all exclusively */
	if (!(( all && !zonename && !cka_id && (keytag == -1)) ||
	    (!all &&  zonename && ((cka_id != NULL)^(keytag != -1)))))
	{
		ods_log_warning("[%s] expected --zone and either --cka_id or "
			"--keytag option or expected --all", module_str);
		client_printf_err(sockfd, "expected --zone and either --cka_id or "
			"--keytag option or expected --all.\n");
		return -1;
	}

	ret = change_keys_from_to(dbconn, sockfd, zonename, cka_id, keytag,
		state_from, state_to, engine);
	return ret;
}
