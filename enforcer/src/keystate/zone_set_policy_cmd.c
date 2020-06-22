 /*
 * Copyright (c) 2017 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2017 OpenDNSSEC AB (svb)
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

#include "daemon/engine.h"
#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "file.h"
#include "str.h"
#include "log.h"
#include "clientpipe.h"
#include "keystate/zonelist_export.h"

#include "keystate/zone_set_policy_cmd.h"

#include <limits.h>
#include <getopt.h>

static const char *module_str = "zone_set_policy_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"zone set-policy\n"
		"	--zone <zone>				aka -z\n"
		"	--policy <policy>			aka -p\n"
	);
	client_printf(sockfd,
		"	[--xml]					aka -u\n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"Change the policy of an existing zone in the enforcer database.\n"
		"\nOptions:\n"
		"zone		name of the zone\n"
		"policy		name of the new policy\n"
		"xml		update the zonelist.xml file\n\n"
	);
}

static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
	#define NARGV 18
	const char* argv[NARGV];
	int argc = 0;
	const char *zone_name = NULL;
	char *policy_name = NULL;
	int write_xml = 0;
	int long_index = 0, opt = 0;
	int ret = 0;
	char path[PATH_MAX];
	db_connection_t* dbconn = getconnectioncontext(context);
	engine_type* engine = getglobalcontext(context);

	static struct option long_options[] = {
		{"zone", required_argument, 0, 'z'},
		{"policy", required_argument, 0, 'p'},
		{"xml", no_argument, 0, 'u'},
		{0, 0, 0, 0}
	};

	ods_log_debug("[%s] %s command", module_str, zone_set_policy_funcblock.cmdname);

	argc = ods_str_explode(cmd, NARGV, argv);
	if (argc == -1) {
		client_printf_err(sockfd, "too many arguments\n");
		ods_log_error("[%s] too many arguments for %s command",
					  module_str, zone_set_policy_funcblock.cmdname);
		return -1;
	}

	optind = 0;
	while ((opt = getopt_long(argc, (char* const*)argv, "z:p:u", long_options, &long_index)) != -1) {
		switch (opt) {
			case 'z':
				zone_name = optarg;
				break;
			case 'p':
				policy_name = strdup(optarg);
				break;
			case 'u':
				write_xml = 1;
				break;
			default:
				client_printf_err(sockfd, "unknown arguments\n");
				ods_log_error("[%s] unknown arguments for %s command",
							  module_str, zone_set_policy_funcblock.cmdname);
				return -1;
		}
	}

	if (!zone_name) {
		client_printf_err(sockfd, "expected option --zone <zone>\n");
		if (policy_name) {
			free(policy_name);
		}
		return -1;
	} else if (!policy_name) {
		client_printf_err(sockfd, "expected option --policy <policy>\n");
		return -1;
	}

        struct dbw_db *db = dbw_fetch(dbconn, "zones, one specific writable, and all policies ro without keys", zone_name);
        struct dbw_zone *zone = dbw_FIND(struct dbw_zone*, db->zones, name, db->nzones, zone_name);
        struct dbw_policy *policy = dbw_FIND(struct dbw_policy*, db->policies, name, db->npolicies, policy_name);
	free((void*)policy_name);
	if (!zone) {
		client_printf_err(sockfd, "Unable to update zone, zone does not exist!\n");
	} else if (!policy) {
		client_printf_err(sockfd, "Unable to update zone, policy does not exist!\n");
	} else {
            zone->policy_id = policy->id;
            dbw_mark_dirty(zone);
            dbw_commit(db);
        }
        dbw_free(db);

	if (write_xml) {
		if (zonelist_export(sockfd, dbconn, engine->config->zonelist_filename_enforcer, 1) != ZONELIST_EXPORT_OK) {
			ods_log_error("[%s] zonelist exported to %s failed", module_str, engine->config->zonelist_filename_enforcer);
			client_printf_err(sockfd, "Exported zonelist to %s failed!\n", engine->config->zonelist_filename_enforcer);
			ret = 1;
		} else {
			ods_log_info("[%s] zonelist exported to %s successfully", module_str, engine->config->zonelist_filename_enforcer);
			client_printf(sockfd, "Exported zonelist to %s successfully\n", engine->config->zonelist_filename_enforcer);
		}
	}

	if (snprintf(path, sizeof(path), "%s/%s", engine->config->working_dir_enforcer, OPENDNSSEC_ENFORCER_ZONELIST) >= (int)sizeof(path)
		|| zonelist_export(sockfd, dbconn, path, 0) != ZONELIST_EXPORT_OK)
	{
		ods_log_error("[%s] internal zonelist update failed", module_str);
		client_printf_err(sockfd, "Unable to update the internal zonelist %s, updates will not reach the Signer!\n", path);
		ret = 1;
	} else {
		ods_log_info("[%s] internal zonelist updated successfully", module_str);
	}

	return ret;
}

struct cmd_func_block zone_set_policy_funcblock = {
	"zone set-policy", &usage, &help, NULL, &run
};
