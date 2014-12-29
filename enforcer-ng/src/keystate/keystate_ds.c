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

#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "enforcer/enforce_task.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "daemon/clientpipe.h"
#include "shared/duration.h"
#include "db/key_data.h"
#include "db/zone.h"
#include "db/hsm_key.h"

#include "keystate/keystate_ds_gone_cmd.h"

static const char *module_str = "keystate_ds_x_cmd";

static int
ds_list_keys(db_connection_t *dbconn, int sockfd,
	key_data_ds_at_parent_t state)
{
	const char *fmth = "%-31s %-13s %-13s %-40s\n";
	const char *fmtl = "%-31s %-13s %-13u %-40s\n";

	key_data_list_t *key_list;
	const key_data_t *key;
	zone_t *zone = NULL;
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
        || db_clause_set_type(clause, DB_CLAUSE_NOT_EQUAL))
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
            (zone ? zone_name(zone) : "NOT_FOUND"),
            key_data_role_text(key), key_data_keytag(key),
            (hsmkey ? hsm_key_locator(hsmkey) : "NOT_FOUND")
        );
        zone_free(zone);
        hsm_key_free(hsmkey);
	}
	key_data_list_free(key_list);
	return 0;
}

static int
push_clauses(db_clause_list_t *clause_list, zone_t *zone,
	key_data_ds_at_parent_t state_from, const hsm_key_t* hsmkey, int keytag)
{
	db_clause_t* clause;

	if (!key_data_zone_id_clause(clause_list, zone_id(zone)))
		return 1;
	if (!(clause = key_data_role_clause(clause_list, KEY_DATA_ROLE_ZSK)) ||
			db_clause_set_type(clause, DB_CLAUSE_NOT_EQUAL))
		return 1;
	if (!key_data_ds_at_parent_clause(clause_list, state_from))
		return 1;
	/* filter in id and or keytag conditionally. */
	if (hsmkey && !key_data_hsm_key_id_clause(clause_list, hsm_key_id(hsmkey)))
		return 1;
	if (keytag < 0 || !key_data_keytag_clause(clause_list, keytag))
	    return 1;
	return 0;
}

static int
change_keys_from_to(db_connection_t *dbconn, int sockfd,
	const char *zonename, const hsm_key_t* hsmkey, int keytag,
	key_data_ds_at_parent_t state_from, key_data_ds_at_parent_t state_to)
{
	key_data_list_t *key_list = NULL;
	key_data_t *key;
	zone_t *zone = NULL;
	int status = 0, key_match = 0, key_mod = 0;
	db_clause_list_t* clause_list = NULL;

	if (!(key_list = key_data_list_new(dbconn)) ||
	    !(clause_list = db_clause_list_new()) ||
		!(zone = zone_new_get_by_name(dbconn, zonename)) ||
		push_clauses(clause_list, zone, state_from, hsmkey, keytag) ||
		key_data_list_get_by_clauses(key_list, clause_list))
	{
		key_data_list_free(key_list);
		db_clause_list_free(clause_list);
        zone_free(zone);
		ods_log_error("[%s] Error fetching from database", module_str);
		return 10;
	}
    db_clause_list_free(clause_list);

	while ((key = key_data_list_get_next(key_list))) {
		key_match++;
		if (key_data_set_ds_at_parent(key, state_to) ||
			key_data_update(key))
		{
		    key_data_free(key);
			break;
		}
		key_mod++;
		key_data_free(key);
	}
    key_data_list_free(key_list);

	client_printf(sockfd, "%d KSK matches found.\n", key_match);
	if (!key_match)
		status = 11;
	if (key_match != key_mod) {
		ods_log_error("[%s] Error writing to database", module_str);
		client_printf(sockfd, "[%s] Error writing to database", module_str);
		status = 12;
	}
	client_printf(sockfd, "%d KSKs changed.\n", key_mod);
	if (key_mod && (zone_set_next_change(zone, 0) || zone_update(zone))) {
		ods_log_error("[%s] error updating zone in DB.", module_str);
		status = 13;
	}

    zone_free(zone);
	return status;
}

static int
get_args(const char *cmd, ssize_t n, const char **zone,
	const char **cka_id, int *keytag, char *buf)
{

	#define NARGV 16
	const char *argv[NARGV], *tag;
	int argc;
	(void)n;

	*keytag = -1;
	*zone = NULL;
	*cka_id = NULL;
	tag = NULL;
	
	strncpy(buf, cmd, ODS_SE_MAXLINE);
	argc = ods_str_explode(buf, NARGV, argv);
	buf[sizeof(buf)-1] = '\0';
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
			module_str, cmd);
		return 1;
	}
	
	(void)ods_find_arg_and_param(&argc, argv, "zone", "z", zone);
	(void)ods_find_arg_and_param(&argc, argv, "cka_id", "k", cka_id);
	(void)ods_find_arg_and_param(&argc, argv, "keytag", "x", &tag);

	if (tag) {
		*keytag = atoi(tag);
		if (*keytag < 0 || *keytag >= 65536) {
			ods_log_warning("[%s] value \"%s\" for --keytag is invalid",
				module_str, *keytag);
			return 1;
		}
	}
	return 0;
}

int
run_ds_cmd(int sockfd, const char *cmd, ssize_t n,
	db_connection_t *dbconn, key_data_ds_at_parent_t state_from,
	key_data_ds_at_parent_t state_to)
{
	const char *zone, *cka_id;
	int keytag;
	hsm_key_t* hsmkey = NULL;
	int ret;
	char buf[ODS_SE_MAXLINE];

	if (get_args(cmd, n, &zone, &cka_id, &keytag, buf)) {
		client_printf(sockfd, "Error parsing arguments\n", keytag);
		return -1;
	}
	
	if (!zone && !cka_id && keytag == -1) {
		return ds_list_keys(dbconn, sockfd, state_from);
	}
	if (!(zone && ((cka_id && keytag == -1) || (!cka_id && keytag != -1))))
	{
		ods_log_warning("[%s] expected --zone and either --cka_id or "
			"--keytag option for %s command", module_str,
			key_ds_gone_funcblock()->cmdname);
		client_printf(sockfd, "expected --zone and either --cka_id or "
			"--keytag option.\n");
		return -1;
	}
	
	if (cka_id) {
	    if (!(hsmkey = hsm_key_new_get_by_locator(dbconn, cka_id))) {
	        client_printf_err(sockfd, "CKA_ID %s can not be found!\n", cka_id);
	    }
	}

	ret = change_keys_from_to(dbconn, sockfd, zone, hsmkey, keytag,
		state_from, state_to);
	hsm_key_free(hsmkey);
	return ret;
}
