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
#include "db/zone_db.h"
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

static int set_zone_policy(int sockfd, db_connection_t* dbconn, zone_db_t* zone, policy_t* policy) {
	const db_value_t* wanted_policy_id = policy_id(policy);
	int cmp;

	if (db_value_cmp(zone_db_policy_id(zone), wanted_policy_id, &cmp)) {
		client_printf_err(sockfd, "Unable to update zone, database error!\n");
		return 1;
	}
	if (!cmp) {
		client_printf_err(sockfd, "Policy same as before, not updating.\n");
		return 0;
	}

	if (zone_db_set_policy_id(zone, wanted_policy_id)) {
		client_printf_err(sockfd, "Unable to update zone, database error!\n");
		return 1;
	}

	if (zone_db_update(zone)) {
		client_printf(sockfd, "Failed to update zone in database.\n");
		return 1;
	}
	ods_log_info("[%s] zone %s policy updated to %s", module_str, zone_db_name(zone), policy_name(policy));
	client_printf(sockfd, "Zone %s policy successfully set to %s\n", zone_db_name(zone), policy_name(policy));
	return 0;
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
		free(zone_name);
		return -1;
	}

	//validation

	zone_db_t* zone = zone_db_new_get_by_name(dbconn, zone_name);
	free((void*)zone_name);
	if (!zone) {
		client_printf_err(sockfd, "Unable to update zone, zone does not exist!\n");
		free(policy_name);
		return 1;
	}

	policy_t* policy = policy_new_get_by_name(dbconn, policy_name);
	free(policy_name);
	if (!policy) {
		client_printf_err(sockfd, "Unable to update zone, policy does not exist!\n");
		zone_db_free(zone);
		return 1;
	}

	/* input looks okay, lets update the database */
	ret = set_zone_policy(sockfd, dbconn, zone, policy);

	zone_db_free(zone);
	policy_free(policy);

	if (write_xml) {
		if (zonelist_export(sockfd, dbconn, engine->config->zonelist_filename_signer, 1) != ZONELIST_EXPORT_OK) {
			ods_log_error("[%s] zonelist exported to %s failed", module_str, engine->config->zonelist_filename_signer);
			client_printf_err(sockfd, "Exported zonelist to %s failed!\n", engine->config->zonelist_filename_signer);
			ret = 1;
		} else {
			ods_log_info("[%s] zonelist exported to %s successfully", module_str, engine->config->zonelist_filename_signer);
			client_printf(sockfd, "Exported zonelist to %s successfully\n", engine->config->zonelist_filename_signer);
		}
	}

	if (snprintf(path, sizeof(path), "%s/%s", engine->config->working_dir_signer, OPENDNSSEC_ENFORCER_ZONELIST) >= (int)sizeof(path)
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
