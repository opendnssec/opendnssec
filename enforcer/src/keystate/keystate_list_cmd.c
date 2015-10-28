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

#include "db/key_data.h"
#include "db/key_state.h"
#include "db/hsm_key.h"
#include "db/zone.h"

#include "keystate/keystate_list_cmd.h"

static const char *module_str = "keystate_list_task";

/* shorter defines to keep keystate table more readable */
#define HID KEY_STATE_STATE_HIDDEN
#define RUM KEY_STATE_STATE_RUMOURED
#define OMN KEY_STATE_STATE_OMNIPRESENT
#define UNR KEY_STATE_STATE_UNRETENTIVE
#define NAV KEY_STATE_STATE_NA

enum {KS_GEN = 0, KS_PUB, KS_RDY, KS_ACT, KS_RET, KS_DEA, KS_UNK, KS_MIX};
const char* statenames[] = {"generate", "publish", "ready",
		"active", "retire", "dead", "unknown", "mixed"};

/** Map 2.0 states to 1.x states
 * @param p: state of RR higher in the chain (e.g. DS)
 * @param c: state of RR lower in the chain (e.g. DNSKEY)
 * @param introducing: key goal
 * @return: state in 1.x speak
 **/
static int
keystate(int p, int c, int introducing, int dsseen)
{
	if (introducing) {
		if (p == HID && c == HID) return KS_GEN;
		if (p == HID || c == HID) return KS_PUB;
		if (p == OMN && c == OMN) return KS_ACT;
		if (p == RUM && dsseen && c == OMN) return KS_ACT;
		if (p == RUM || c == RUM) return KS_RDY;
		return KS_UNK;
	} else {
		/* retire conforms better to 1.4 terminology than dead. */
		if (p == HID && c == HID) return KS_RET; /* dead */
		if (p == UNR || c == UNR) return KS_RET;
		if (p == OMN && c == OMN) return KS_ACT;
		return KS_RET;
	}
}

static int
zskstate(key_data_t *key)
{
	return keystate(key_state_state(key_data_cached_dnskey(key)),
		key_state_state(key_data_cached_rrsig(key)),
		key_data_introducing(key), 0);
}

static int
kskstate(key_data_t *key)
{
	return keystate(key_state_state(key_data_cached_ds(key)),
		key_state_state(key_data_cached_dnskey(key)),
		key_data_introducing(key),
		key_data_ds_at_parent(key) == KEY_DATA_DS_AT_PARENT_SEEN);
}

/** Human readable keystate in 1.x speak
 * @param key: key to evaluate
 * @return: state as string
 **/
static const char*
map_keystate(key_data_t *key)
{
	int z,k;
	switch(key_data_role(key)) {
		case KEY_DATA_ROLE_KSK:
			return statenames[kskstate(key)];
		case KEY_DATA_ROLE_ZSK:
			return statenames[zskstate(key)];
		case KEY_DATA_ROLE_CSK:
			k = kskstate(key);
			z = zskstate(key);
			if (k != z) return statenames[KS_MIX];
			return statenames[k];
		default:
			return statenames[KS_UNK];
	}
}

/** Time of next transition. Caller responsible for freeing ret
 * @param zone: zone key belongs to
 * @param key: key to evaluate
 * @return: human readable transition time/event */
static char*
map_keytime(const zone_t *zone, const key_data_t *key)
{
	char ct[26];
	struct tm srtm;
	time_t t;

	switch(key_data_ds_at_parent(key)) {
		case KEY_DATA_DS_AT_PARENT_SUBMIT:
			return strdup("waiting for ds-submit");
		case KEY_DATA_DS_AT_PARENT_SUBMITTED:
			return strdup("waiting for ds-seen");
		case KEY_DATA_DS_AT_PARENT_RETRACT:
			return strdup("waiting for ds-retract");
		case KEY_DATA_DS_AT_PARENT_RETRACTED:
			return strdup("waiting for ds-gone");
		default:
			break;
	}
	if (zone_next_change(zone) < 0)
		return strdup("-");

	t = (time_t)zone_next_change(zone);
	localtime_r(&t, &srtm);
	strftime(ct, 26, "%Y-%m-%d %H:%M:%S", &srtm);
	return strdup(ct);
}

static int
perform_keystate_list_compat(int sockfd, db_connection_t *dbconn, const char *zonename, const char *type)
{
	const char* fmt = "%-31s %-8s %-9s %s\n";
	key_data_list_t* key_list;
	key_data_t* key;
	int cmp;
	zone_t *zone = NULL;
	char* tchange;

	if (zonename) {
		zone = zone_new(dbconn);
		zone_get_by_name(zone, zonename);
		key_list = key_data_list_new_get_by_zone_id(dbconn, &zone->id);
	}
	else if (type) {
		if (!strncmp(type, "KSK", 3))
			key_list = key_data_list_new_get_by_role(dbconn, KEY_DATA_ROLE_KSK);
		else
			key_list = key_data_list_new_get_by_role(dbconn, KEY_DATA_ROLE_ZSK);
	}
	else
		key_list = key_data_list_new_get(dbconn);

	if (!key_list) {
		client_printf_err(sockfd, "Unable to get list of keys, memory "
			"allocation or database error!\n");
		return 1;
	}

	client_printf(sockfd, "Keys:\n");
	client_printf(sockfd, fmt, "Zone:", "Keytype:", "State:",
		"Date of next transition:");

	while ((key = key_data_list_get_next(key_list))) {
		if (!zonename && zone
	        && (db_value_cmp(zone_id(zone), key_data_zone_id(key), &cmp)
	            || cmp)) {
			zone_free(zone);
			zone = NULL;
		}
		if (!zonename && !zone) {
	        	zone = key_data_get_zone(key);
	    	}
		key_data_cache_key_states(key);
		tchange = map_keytime(zone, key); /* allocs */
		client_printf(sockfd,
			fmt,
			zone_name(zone),
			key_data_role_text(key),
			map_keystate(key),
			tchange);
		free(tchange);
		key_data_free(key);
	}
	zone_free(zone);
	key_data_list_free(key_list);
	return 0;
}

static int
perform_keystate_list_verbose(int sockfd, db_connection_t *dbconn,
	bool parsable, const char *zonename, const char *type)
{
	const char* fmthdr = "%-31s %-8s %-9s %-24s %-5s %-10s %-32s %-11s %s\n";
	const char* fmt    = "%-31s %-8s %-9s %-24s %-5d %-10d %-32s %-11s %d\n";
	const char* pfmt   = "%s;%s;%s;%s;%d;%d;%s;%s;%d\n";
	key_data_list_t* key_list;
	key_data_t* key;
	zone_t *zone = NULL;
	char* tchange;
	hsm_key_t *hsmkey;
	int cmp;

	if (zonename) {
		zone = zone_new(dbconn);
		zone_get_by_name(zone, zonename);
		key_list = key_data_list_new_get_by_zone_id(dbconn, &zone->id);	
	}
	else if (type) {
		if (!strncmp (type, "KSK", 3))
			key_list = key_data_list_new_get_by_role (dbconn, KEY_DATA_ROLE_KSK);
		else
			key_list = key_data_list_new_get_by_role (dbconn, KEY_DATA_ROLE_ZSK);		
	}
	else
		key_list = key_data_list_new_get(dbconn);

	if (!key_list) {
		client_printf_err(sockfd, "Unable to get list of keys, memory "
			"allocation or database error!\n");
		return 1;
	}

	if (!parsable) {
		client_printf(sockfd, "Keys:\n");
		client_printf(sockfd, fmthdr, "Zone:", "Keytype:", "State:",
			"Date of next transition:", "Size:", "Algorithm:", "CKA_ID:",
			"Repository:", "KeyTag:");
	}

	while ((key = key_data_list_get_next(key_list))) {
	        if (!zonename && zone
        	    && (db_value_cmp(zone_id(zone), key_data_zone_id(key), &cmp)
                	|| cmp))
        	{
	            zone_free(zone);
        	    zone = NULL;
        	}
	        if (!zonename && !zone) {
        	    zone = key_data_get_zone(key);
        	}
	        hsmkey = key_data_get_hsm_key(key);
        	key_data_cache_key_states(key);
		tchange = map_keytime(zone, key); /* allocs */
		client_printf(sockfd,
			parsable?pfmt:fmt,
			zone_name(zone),
			key_data_role_text(key),
			map_keystate(key),
			tchange,
			hsm_key_bits(hsmkey),
			hsm_key_algorithm(hsmkey),
			hsm_key_locator(hsmkey),
			hsm_key_repository(hsmkey),
			key_data_keytag(key));
		free(tchange);
		hsm_key_free(hsmkey);
		key_data_free(key);
	}
	zone_free(zone);
	key_data_list_free(key_list);
	return 0;
}

static int
perform_keystate_list_debug(int sockfd, db_connection_t *dbconn,
	bool parsable, const char *zonename, const char *type)
{
	const char *fmt  = "%-31s %-13s %-12s %-12s %-12s %-12s %d %4d    %s\n";
	const char *pfmt = "%s;%s;%s;%s;%s;%s;%d;%d;%s\n";
	key_data_list_t* key_list;
	key_data_t* key;
	zone_t *zone = NULL;
	hsm_key_t *hsmkey;
	int cmp;

	if (zonename) {
                zone = zone_new(dbconn);
                zone_get_by_name (zone, zonename);
                key_list = key_data_list_new_get_by_zone_id (dbconn, &zone->id);
	}
	else if (type) {
		if (!strncmp (type, "KSK", 3))
			key_list = key_data_list_new_get_by_role (dbconn, KEY_DATA_ROLE_KSK);
		else
			key_list = key_data_list_new_get_by_role (dbconn, KEY_DATA_ROLE_ZSK);
	}
	else
		key_list = key_data_list_new_get(dbconn);

	if (!key_list) {
		client_printf_err(sockfd, "Unable to get list of keys, memory "
			"allocation or database error!\n");
		return 1;
	}

	if (!parsable) {
		client_printf(sockfd,
			"Keys:\nZone:                           Key role:     "
			"DS:          DNSKEY:      RRSIGDNSKEY: RRSIG:       "
			"Pub: Act: Id:\n");
	}

	while ((key = key_data_list_get_next(key_list))) {
        	if (!zonename && zone
            	&& (db_value_cmp(zone_id(zone), key_data_zone_id(key), &cmp)
                || cmp))
        	{
            		zone_free(zone);
			zone = NULL;
        	}
	        if (!zonename && !zone) {
        	    zone = key_data_get_zone(key);
        	}
	    	key_data_cache_key_states(key);
	        hsmkey = key_data_get_hsm_key(key);
		client_printf(sockfd,
			parsable?pfmt:fmt,
			zone_name(zone),
			key_data_role_text(key),
			key_state_state_text(key_data_cached_ds(key)),
			key_state_state_text(key_data_cached_dnskey(key)),
			key_state_state_text(key_data_cached_rrsigdnskey(key)),
			key_state_state_text(key_data_cached_rrsig(key)),
			key_data_publish(key),
			key_data_active_ksk(key) | key_data_active_zsk(key),
			hsm_key_locator(hsmkey));
        	hsm_key_free(hsmkey);
		key_data_free(key);
	}
	key_data_list_free(key_list);
	return 0;
}

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key list               List the keys in the enforcer database.\n"
		"      [--verbose]                (aka -v)  also show additional key parameters.\n"
		"      [--debug]                  (aka -d)  print information about the keystate.\n"
		"      [--parsable]               (aka -p)  output machine parsable list\n"
		"      [--zone <zone>]            (aka -z) print key list for that zone\n"
		"      [--keytype <type>]         (aka -t) print those keys which have that key type\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_list_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	char buf[ODS_SE_MAXLINE];
	#define NARGV 8
	const char *argv[NARGV];
	int argc, bVerbose, bDebug, bParsable;
        const char *zonename = NULL, *type = NULL;
	zone_t *zone = NULL;
	(void)engine;

	ods_log_debug("[%s] %s command", module_str, key_list_funcblock()->cmdname);

	cmd = ods_check_command(cmd, n, key_list_funcblock()->cmdname);
	/* Use buf as an intermediate buffer for the command. */
	strncpy(buf, cmd, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';

	/* separate the arguments */
	argc = ods_str_explode(buf, NARGV, argv);
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
						module_str,key_list_funcblock()->cmdname);
		client_printf(sockfd,"too many arguments\n");
		return -1;
	}

	bVerbose = ods_find_arg(&argc,argv,"verbose","v") != -1;
	bDebug = ods_find_arg(&argc,argv,"debug","d") != -1;
	bParsable = ods_find_arg(&argc,argv,"parsable","p") != -1;
	(void)ods_find_arg_and_param(&argc, argv, "zone", "z", &zonename);
	(void)ods_find_arg_and_param(&argc, argv, "keytype", "t", &type);

	if (type)
		(void)StrToUpper(type);

	if (type && (strlen(type) != 3 || (strncmp(type, "ZSK", 3) && strncmp(type, "KSK", 3)))) {
        	ods_log_warning ("[%s] Error: Unrecognised keytype %s; should be one of KSK or ZSK\n", module_str, type);
                client_printf(sockfd, "Error: Unrecognised keytype %s; should be one of KSK or ZSK\n", type);
                return -1;
        }

	if (zonename && (!(zone = zone_new(dbconn)) || zone_get_by_name(zone, zonename))) {
		ods_log_warning ("[%s] Error: Unable to find a zone named \"%s\" in database\n", module_str, zonename);
                client_printf(sockfd, "Error: Unable to find a zone named \"%s\" in database\n", zonename);
		zone_free(zone);
		zone = NULL;
                return -1;

	}
        zone_free(zone);
        zone = NULL;

	if (argc) {
		ods_log_warning("[%s] unknown arguments for %s command",
						module_str,key_list_funcblock()->cmdname);
		client_printf(sockfd,"unknown arguments\n");
		return -1;
	}

	if (bDebug)
		return perform_keystate_list_debug(sockfd, dbconn, bParsable, zonename, type);
	else if (bVerbose)
		return perform_keystate_list_verbose(sockfd, dbconn, bParsable, zonename, type);
	else
		return perform_keystate_list_compat(sockfd, dbconn, zonename, type);
}

static struct cmd_func_block funcblock = {
	"key list", &usage, NULL, &handles, &run
};

struct cmd_func_block*
key_list_funcblock(void)
{
	return &funcblock;
}
