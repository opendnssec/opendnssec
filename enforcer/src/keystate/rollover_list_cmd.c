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
#include <getopt.h>

#include "db/zone_db.h"
#include "daemon/engine.h"
#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"

#include "keystate/rollover_list_cmd.h"

static const char *module_str = "rollover_list_cmd";

/**
 * Time of next transition. Caller responsible for freeing ret
 * \param zone: zone key belongs to
 * \param key: key to evaluate
 * \return: human readable transition time/event
 */
static char*
map_keytime(const zone_db_t *zone, const key_data_t *key)
{
	time_t t = 0;
	char ct[26];
	struct tm srtm;

	switch(key_data_ds_at_parent(key)) {
		case KEY_DATA_DS_AT_PARENT_SUBMIT:
			return strdup("waiting for ds-submit");
		case KEY_DATA_DS_AT_PARENT_SUBMITTED:
			return strdup("waiting for ds-seen");
		case KEY_DATA_DS_AT_PARENT_RETRACT:
			return strdup("waiting for ds-retract");
		case KEY_DATA_DS_AT_PARENT_RETRACTED:
			return strdup("waiting for ds-gone");
		default: break;
	}

	switch (key_data_role(key)) {
		case KEY_DATA_ROLE_KSK: t = (time_t)zone_db_next_ksk_roll(zone); break;
		case KEY_DATA_ROLE_ZSK: t = (time_t)zone_db_next_zsk_roll(zone); break;
		case KEY_DATA_ROLE_CSK: t = (time_t)zone_db_next_csk_roll(zone); break;
		default: break;
	}
	if (!t) return strdup("No roll scheduled");
	
	localtime_r(&t, &srtm);
	strftime(ct, 26, "%Y-%m-%d %H:%M:%S", &srtm);
	return strdup(ct);
}

static void
print_zone(int sockfd, const char* fmt, const zone_db_t* zone)
{
	key_data_list_t *keylist;
	const key_data_t *key;

	keylist = zone_db_get_keys(zone);
	while ((key = key_data_list_next(keylist))) {
		char *tchange = map_keytime(zone, key);
		client_printf(sockfd, fmt, zone_db_name(zone),
			key_data_role_text(key), tchange);
		free(tchange);
	}
	key_data_list_free(keylist);
}

/**
 * List all keys and their rollover time. If listed_zone is set limit
 * to that zone
 * \param sockfd client socket
 * \param listed_zone name of the zone
 * \param dbconn active database connection
 * \return 0 ok, 1 fail.
 */
static int 
perform_rollover_list(int sockfd, const char *listed_zone,
	db_connection_t *dbconn)
{
	zone_list_db_t *zonelist = NULL;
	zone_db_t *zone = NULL;
	const zone_db_t *zone_walk = NULL;
	const char* fmt = "%-31s %-8s %-30s\n";

	if (listed_zone) {
		zone = zone_db_new_get_by_name(dbconn, listed_zone);
	} else {
		zonelist = zone_list_db_new_get(dbconn);
	}

	if (listed_zone && !zone) {
		ods_log_error("[%s] zone '%s' not found", module_str, listed_zone);
		client_printf(sockfd, "zone '%s' not found\n", listed_zone);
		return 1;
	}

	if (!zone && !zonelist) {
		ods_log_error("[%s] error enumerating zones", module_str);
		client_printf(sockfd, "error enumerating zones\n");
		return 1;
	}

	client_printf(sockfd, "Keys:\n");
	client_printf(sockfd, fmt, "Zone:", "Keytype:", "Rollover expected:");

	if (zone) {
		print_zone(sockfd, fmt, zone);
		zone_db_free(zone);
		return 0;
	}

	while ((zone_walk = zone_list_db_next(zonelist))) {
		print_zone(sockfd, fmt, zone_walk);
	}
	zone_list_db_free(zonelist);
	return 0;
}

static void
usage(int sockfd)
{
	client_printf(sockfd, 
		"rollover list\n"
		"	[--zone <zone>]				aka -z\n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"List the expected dates and times of upcoming rollovers. This can be used to get an idea of upcoming works.\n"
		"\nOptions:\n"
		"zone	name of the zone\n\n");
}

static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
	#define NARGV 4
	const char *argv[NARGV];
	int argc = 0, long_index = 0, opt = 0;
	const char *zone = NULL;
        db_connection_t* dbconn = getconnectioncontext(context);

	static struct option long_options[] = {
		{"zone", required_argument, 0, 'z'},
		{0, 0, 0, 0}
	};
	
	ods_log_debug("[%s] %s command", module_str, rollover_list_funcblock.cmdname);
	
	/* separate the arguments*/
	argc = ods_str_explode(cmd, NARGV, argv);
	if (argc == -1) {
		client_printf_err(sockfd, "too many arguments\n");
		ods_log_error("[%s] too many arguments for %s command",
				module_str, rollover_list_funcblock.cmdname);
		return -1;
	}

	optind = 0;
	while ((opt = getopt_long(argc, (char* const*)argv, "z:", long_options, &long_index)) != -1) {
		switch (opt) {
			case 'z':
				zone = optarg;
				break;
			default:
				client_printf_err(sockfd, "unknown arguments\n");
				ods_log_error("[%s] unknown arguments for %s command",
						module_str, rollover_list_funcblock.cmdname);
				return -1;
		}
	}
	return perform_rollover_list(sockfd, zone, dbconn);
}

struct cmd_func_block rollover_list_funcblock = {
	"rollover list", &usage, &help, NULL, &run
};
