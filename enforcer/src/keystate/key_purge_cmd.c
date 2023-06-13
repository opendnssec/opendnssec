/*
 * Copyright (c) 2017 NLNet Labs. All rights reserved.
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
#include "daemon/engine.h"
#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "longgetopt.h"
#include "enforcer/enforce_task.h"
#include "db/key_data.h"
#include "keystate/key_purge.h"

#include "keystate/key_purge_cmd.h"

#include <getopt.h>

static const char *module_str = "key_purge_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key purge\n"
		"	--policy <policy> | --zone <zone>	aka -p | -z\n"
                "       --delete or -d\n");
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"This command will remove keys from the database (and HSM) that "
		"are dead. Use with caution.\n"
		"\nOptions:\n"
		"policy		limit the purge to the given policy\n"
		"zone		limit the purge to the given zone\n"
                "the -d flag will cause the keys to be deleted from the HSM\n\n"
	);
}


/**
 * Purge
 * @param dbconn, Active database connection
 *
 * @return: error status, >0 on error
 */

static int
run(cmdhandler_ctx_type* context, int argc, char* argv[])
{
    int sockfd = context->sockfd;
    struct longgetopt optctx;
	zone_db_t *zone;
	policy_t *policy;
	const char *zone_name = NULL;
	const char *policy_name = NULL;
	int long_index = 0, opt = 0;
	int error = 0;
        int hsmPurge = 0;
        db_connection_t* dbconn = getconnectioncontext(context);

	static struct option long_options[] = {
		{"zone", required_argument, 0, 'z'},
		{"policy", required_argument, 0, 'p'},
		{"delete", no_argument, 0, 'd'},
		{0, 0, 0, 0}
	};

        if (!dbconn) return 1;

	for(opt = longgetopt(argc, argv, "z:p:d", long_options, &long_index, &optctx); opt != -1;
	    opt = longgetopt(argc, argv, NULL,    long_options, &long_index, &optctx)) {
		switch (opt) {
			case 'z':
				zone_name = optctx.optarg;
				break;
			case 'p':
				policy_name = optctx.optarg;
				break;
			case 'd':
				hsmPurge = 1;
				break;
			default:
				client_printf_err(sockfd, "unknown arguments\n");
				ods_log_error("[%s] unknown arguments for key purge command", module_str);
				return -1;
		}
	}

        if ((!zone_name && !policy_name) || (zone_name && policy_name)) {
                ods_log_error("[%s] expected either --zone or --policy", module_str);
                client_printf_err(sockfd, "expected either --zone or --policy \n");
                return -1;
        }
	
	if (zone_name) {
		zone = zone_db_new(dbconn);
		if (zone_db_get_by_name(zone, zone_name)) {
			client_printf_err(sockfd, "unknown zone %s\n", zone_name);
			zone_db_free(zone);
			zone = NULL;
			return -1;
		}
		error = removeDeadKeysNow(sockfd, dbconn, NULL, zone, hsmPurge);
		zone_db_free(zone);
		zone = NULL;
		return error;
	}

	/* have policy_name since it is mutualy exlusive with zone_name */
	policy = policy_new(dbconn);
	if (policy_get_by_name(policy, policy_name)){
		policy_free(policy);
		policy = NULL;
		client_printf_err(sockfd, "unknown policy %s\n", policy_name);
		return -1;
	}
	error = removeDeadKeysNow(sockfd, dbconn, policy, NULL, hsmPurge);
	policy_free(policy);
	policy = NULL;
	return error;
}

struct cmd_func_block key_purge_funcblock = {
	"key purge", &usage, &help, NULL, NULL, &run, NULL};
