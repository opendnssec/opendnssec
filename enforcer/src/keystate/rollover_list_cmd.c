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

#include "db/dbw.h"
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
map_keytime(const struct dbw_zone *zone, const struct dbw_key *key)
{
    time_t t = 0;
    char ct[26];
    struct tm srtm;

    switch(key->ds_at_parent) {
        case KEY_DATA_DS_AT_PARENT_SUBMIT:
            return strdup("waiting for ds-submit");
        case KEY_DATA_DS_AT_PARENT_SUBMITTED:
            return strdup("waiting for ds-seen");
        case KEY_DATA_DS_AT_PARENT_RETRACT:
            return strdup("waiting for ds-retract");
        case KEY_DATA_DS_AT_PARENT_RETRACTED:
            return strdup("waiting for ds-gone");
    }

    switch (key->role) {
        case KEY_DATA_ROLE_KSK: t = zone->next_ksk_roll; break;
        case KEY_DATA_ROLE_ZSK: t = zone->next_zsk_roll; break;
        case KEY_DATA_ROLE_CSK: t = zone->next_csk_roll; break;
        default: return strdup("No roll scheduled");
    }

    localtime_r(&t, &srtm);
    strftime(ct, 26, "%Y-%m-%d %H:%M:%S", &srtm);
    return strdup(ct);
}

static void
print_key(int sockfd, const char* fmt, const struct dbw_key *key)
{
    const char *role;
    switch (key->role) {
        case KEY_DATA_ROLE_KSK: role = "KSK"; break;
        case KEY_DATA_ROLE_ZSK: role = "ZSK"; break;
        case KEY_DATA_ROLE_CSK: role = "CSK"; break;
        default:
            assert(0);
    }
    char *tchange = map_keytime(key->zone, key);
    client_printf(sockfd, fmt, key->zone->name, role, tchange);
    free(tchange);
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
    struct dbw_list *keys;
    const char* fmt = "%-31s %-8s %-30s\n";

    struct dbw_db *db = dbw_fetch(dbconn);
    /*struct dbw_list *policies = dbw_policies_all_filtered(dbconn, NULL, listed_zone, 0);*/

    if (!db) {
        ods_log_error("[%s] error enumerating rollovers", module_str);
        client_printf(sockfd, "error enumerating rollovers\n");
        return 1;
    }
    client_printf(sockfd, "Keys:\n");
    client_printf(sockfd, fmt, "Zone:", "Keytype:", "Rollover expected:");

    for (size_t p = 0; p < db->policies->n; p++) {
        struct dbw_policy *policy = (struct dbw_policy *)db->policies->set[p];
        for (size_t z = 0; z < policy->zone_count; z++) {
            struct dbw_zone *zone = policy->zone[z];
            if (listed_zone && strcmp(listed_zone, zone->name)) continue;
            for (size_t k = 0; k < zone->key_count; k++) {
                struct dbw_key *key = zone->key[k];
                print_key(sockfd, fmt, key);
            }
        }
    }
    dbw_free(db);
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
