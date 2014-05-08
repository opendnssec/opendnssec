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
	zone_t *zone;

	if (!(key_list = key_data_list_new(dbconn)))
		return 10;
	if (key_data_list_get(key_list)) {
		key_data_list_free(key_list);
		return 11;
	}
	if (!(zone = zone_new(dbconn))) {
		key_data_list_free(key_list);
		return 12;
	}

	client_printf(sockfd, fmth, "Zone:", "Key role:", "Keytag:", "Id:");

	/* We should consider filtering this in the DB. */
	for (key = key_data_list_begin(key_list); key;
		key = key_data_list_next(key_list))
	{
		if (!key_data_is_ksk(key)) continue; /* skip ZSK */
		if (!key_data_locator(key)) continue; /* placeholder key */
		if (key_data_ds_at_parent(key) != state) continue;

		if(!zone_get_by_id(zone, key_data_zone_id(key))) {
			client_printf(sockfd, fmtl, zone_name(zone),
				key_data_role_text(key), key_data_keytag(key),
				key_data_locator(key)
			);
			zone_reset(zone);
		}
	}
	key_data_list_free(key_list);
	zone_free(zone);
	return 0;
}

static int
push_clauses(db_clause_list_t *clause_list, zone_t *zone,
	key_data_ds_at_parent_t state_from, const char *id, int keytag)
{
	db_clause_t* clause;

	if (!key_data_zone_id_clause(clause_list, zone_id(zone)))
		return 1;
	if (!(clause = key_data_role_clause(clause_list, KEY_DATA_ROLE_ZSK)) ||
			db_clause_set_type(clause, DB_CLAUSE_NOT_EQUAL))
		return 1;
	if (key_data_ds_at_parent_clause(clause_list, state_from))
		return 1;
	/* filter in id and or keytag conditionally. */
	if (id && !key_data_locator_clause(clause_list, id))
		return 1;
	return (keytag >= 0 && !key_data_keytag_clause(clause_list, keytag));
}

static int
change_keys_from_to(db_connection_t *dbconn, int sockfd,
	const char *zonename, const char *id, int keytag,
	key_data_ds_at_parent_t state_from, key_data_ds_at_parent_t state_to)
{
	key_data_list_t *key_list = NULL;
	const key_data_t *key;
	key_data_t *rw_key = NULL;
	zone_t *zone = NULL;
	int status = 0, key_match = 0, key_mod = 0;
	db_clause_list_t* clause_list = NULL;

	key_list = key_data_list_new(dbconn);
	rw_key = key_data_new(dbconn);
	zone = zone_new(dbconn);
	clause_list = db_clause_list_new();
	if (!key_list || !rw_key || !zone || !clause_list ||
		zone_get_by_name(zone, zonename) ||
		push_clauses(clause_list, zone, state_from, id, keytag) ||
		key_data_list_get_by_clauses(key_list, clause_list))
	{
		key_data_list_free(key_list);
		key_data_free(rw_key);
		zone_free(zone);
		db_clause_list_free(clause_list);
		ods_log_error("[%s] Error fetching from database", module_str);
		return 10;
	}

	for (key = key_data_list_begin(key_list); key;
		key = key_data_list_next(key_list))
	{
		key_match++;
		if (key_data_copy(rw_key, key) ||
			key_data_set_ds_at_parent(rw_key, state_to) ||
			key_data_update(rw_key))
		{
			break;
		}
		key_mod++;
		key_data_reset(rw_key);
	}

			
	client_printf(sockfd, "%d KSK matches found.\n", key_match);
	if (!key_match)
		status = 11;
	if (key_match != key_mod) {
		ods_log_error("[%s] Error writing to database", module_str);
		client_printf(sockfd, "[%s] Error writing to database", module_str);
		status = 12;
	}
	client_printf(sockfd, "%d KSKs changed.\n", key_mod);
	if (key_mod && (zone_set_next_change(zone, 0) || zone_update(zone)))
	{
		ods_log_error("[%s] error updating zone in DB.", module_str);
		status = 13;
	}

	key_data_list_free(key_list);
	key_data_free(rw_key);
	zone_free(zone);
	db_clause_list_free(clause_list);

	return status;
}

static int
get_args(const char *cmd, ssize_t n, const char **zone,
	const char **cka_id, int *keytag)
{

	#define NARGV 16
	const char *argv[NARGV], *tag;
	char buf[ODS_SE_MAXLINE];
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

	if (get_args(cmd, n, &zone, &cka_id, &keytag)) {
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
	
	return change_keys_from_to(dbconn, sockfd, zone, cka_id, keytag,
		state_from, state_to);

}
