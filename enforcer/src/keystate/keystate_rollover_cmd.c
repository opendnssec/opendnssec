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

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "str.h"
#include "enforcer/enforce_task.h"
#include "clientpipe.h"
#include "db/zone_db.h"
#include "log.h"
#include "file.h"
#include "longgetopt.h"

#include "keystate/keystate_rollover_cmd.h"

static const char *module_str = "keystate_rollover_cmd";

static int
perform_keystate_rollover(int sockfd, db_connection_t *dbconn, const char * policyname,
	const char *zonename, int nkeyrole)
{
	policy_t* policy = NULL;
	zone_db_t* zone = NULL;
	zone_list_db_t *zonelist = NULL;
	int reterror = 0;
	int error = 0;
	int listsize = 0;

	if (policyname) {
		policy = policy_new(dbconn);
		if (policy_get_by_name(policy, policyname)){
			policy_free(policy);
			policy = NULL;
			client_printf_err(sockfd, "unknown policy %s\n", policyname);
			return -1;
		}
                if (policy_retrieve_zone_list(policy)) {
			ods_log_error("[%s] Error fetching zones", module_str);
                        client_printf_err(sockfd, "[%s] Error fetching zones", module_str);
			policy_free(policy);
			policy = NULL;
	                return 1;
                }
                zonelist = policy_zone_list(policy);
                listsize = zone_list_db_size(zonelist);
		if (listsize == 0) {
			client_printf (sockfd, "No zones on policy %s\n", policy_name(policy));
			client_printf (sockfd, "No keys to be rolled\n");
			policy_free(policy);
			return 0;
		}
                zone = zone_list_db_get_next(zonelist);
	}
	else if (zonename) {
		listsize = 1;
		if (!(zone = zone_db_new_get_by_name(dbconn, zonename))) {
			client_printf(sockfd, "zone %s not found\n", zonename);
			return 1;
		}
	}
	
	while (listsize > 0) {
		error = 0;
		switch (nkeyrole) {
			case 0:
				if (zone_db_set_roll_ksk_now(zone, 1) ||
					zone_db_set_roll_zsk_now(zone, 1) ||
					zone_db_set_roll_csk_now(zone, 1)) {error = 1; break;}
				client_printf(sockfd, "rolling all keys for zone %s\n", zone_db_name(zone));
				ods_log_info("[%s] Manual rollover initiated for all keys on Zone: %s",
					module_str, zone_db_name(zone));
				break;
			case KEY_DATA_ROLE_KSK:
				if (zone_db_set_roll_ksk_now(zone, 1)) {error = 1; break;};
				client_printf(sockfd, "rolling KSK for zone %s\n", zone_db_name(zone));
				ods_log_info("[%s] Manual rollover initiated for KSK on Zone: %s", module_str, zone_db_name(zone));
				break;
			case KEY_DATA_ROLE_ZSK:
				if (zone_db_set_roll_zsk_now(zone, 1)) {error = 1; break;}
				client_printf(sockfd, "rolling ZSK for zone %s\n", zone_db_name(zone));
				ods_log_info("[%s] Manual rollover initiated for ZSK on Zone: %s", module_str, zone_db_name(zone));
				break;
			case KEY_DATA_ROLE_CSK:
				if (zone_db_set_roll_csk_now(zone, 1)) {error = 1; break;}
				client_printf(sockfd, "rolling CSK for zone %s\n", zone_db_name(zone));
				ods_log_info("[%s] Manual rollover initiated for CSK on Zone: %s", module_str, zone_db_name(zone));
				break;
			default:
				ods_log_assert(false && "nkeyrole out of range");
				ods_log_error_and_printf(sockfd, module_str,
					"nkeyrole out of range");
				error = 1;
		}
		error = error || zone_db_set_next_change(zone, 0) || zone_db_update(zone);
		if (error) {
			ods_log_error_and_printf(sockfd, module_str,
				"updating zone %s in the database failed", zone_db_name(zone));
		}
		reterror = error || reterror;
		listsize--;
		zone_db_free(zone);
		if (listsize > 0)
			zone = zone_list_db_get_next(zonelist);
	}
	policy_free(policy);
	return reterror;
}

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key rollover\n"
		"	--zone <zone> | --policy <policy>	aka -z | -p \n"
		"	[--keytype <keytype>]			aka -t\n"
	);

}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"Start a key rollover of the desired type *now*. The process is the same\n"
		"as for the scheduled automated rollovers however it does not wait for\n"
		"the keys lifetime to expire before rolling. The next rollover is due\n"
		"after the newest key aged passed its lifetime.\n"
		"\nOptions:\n"
		"zone		limit the output to the given the zone\n"
		"policy		limit the output to the given the policy\n"
		"keytype		limit the output to the given type, can be KSK, ZSK or CSK (default is all)\n\n"
	);
}

static int
run(cmdhandler_ctx_type* context, int argc, char* argv[])
{
    int sockfd = context->sockfd;
    struct longgetopt optctx;
	int error, nkeytype = 0;
	int long_index = 0, opt = 0;
	const char *zone = NULL, *keytype = NULL, *policy = NULL;
        db_connection_t* dbconn = getconnectioncontext(context);
        engine_type* engine = getglobalcontext(context);

	static struct option long_options[] = {
		{"zone", required_argument, 0, 'z'},
		{"policy", required_argument, 0, 'p'},
		{"keytype", required_argument, 0, 't'},
		{0, 0, 0, 0}
	};

	for(opt = longgetopt(argc, argv, "p:z:t:", long_options, &long_index, &optctx); opt != -1;
	    opt = longgetopt(argc, argv, NULL,     long_options, &long_index, &optctx)) {
		switch (opt) {
			case 'z':
				zone = optctx.optarg;
				break;
			case 'p':
				policy = optctx.optarg;
				break;
			case 't':
				keytype = optctx.optarg;
				break;
			default:
				client_printf_err(sockfd, "unknown arguments\n");
				ods_log_error("[%s] unknown arguments for key rollover command", module_str);
				return -1;
		}
	}

	if (!zone && !policy) {
		ods_log_warning("[%s] expected either --zone <zone> or --policy <policy> for key rollover command", module_str);
		client_printf(sockfd,"expected either --zone <zone> or --policy <policy> option\n");
		return -1;
	}
	else if (zone && policy) {
		 ods_log_warning("[%s] expected either --zone <zone> or --policy <policy> for key rollover command", module_str);
                client_printf(sockfd,"expected either --zone <zone> or --policy <policy> option\n");
                return -1;
	}

	if (keytype) {
		if (!strncasecmp(keytype, "KSK", 3)) {
			nkeytype = KEY_DATA_ROLE_KSK;
		} else if (!strncasecmp(keytype, "ZSK", 3)) {
			nkeytype = KEY_DATA_ROLE_ZSK;
		} else if (!strncasecmp(keytype, "CSK", 3)) {
			nkeytype = KEY_DATA_ROLE_CSK;
		} else {
			ods_log_warning("[%s] given keytype \"%s\" invalid",
				module_str,keytype);
			client_printf(sockfd, "given keytype \"%s\" invalid\n",
				keytype);
			return 1;
		}
	}

	error = perform_keystate_rollover(sockfd, dbconn, policy, zone, nkeytype);
	
	/* YBS: TODO only affected zones */
	enforce_task_flush_all(engine, dbconn);
	return error;
}

struct cmd_func_block key_rollover_funcblock = {
	"key rollover", &usage, &help, NULL, NULL, &run, NULL
};
