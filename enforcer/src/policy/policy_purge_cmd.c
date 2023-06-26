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
#include "db/policy.h"

#include "policy/policy_purge_cmd.h"

static const char *module_str = "policy_purge_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"policy purge\n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"This command will remove any policies from the database which have no\n"
		"associated zones. Use with caution.\n\n"
	);
}

static int
run(cmdhandler_ctx_type* context, int argc, char* argv[])
{
    int sockfd = context->sockfd;
    db_connection_t* dbconn = getconnectioncontext(context);
	policy_list_t* policy_list;
	policy_t* policy;
	zone_list_db_t* zonelist;
	const char* name;
	size_t listsize;
	int result = 0;

	client_printf(sockfd, "Purging policies\n");

	policy_list = policy_list_new_get(dbconn);
	if (!policy_list) return 1;

	while ((policy = policy_list_get_next(policy_list))) {
		name = policy_name(policy);
		/*fetch zonelist from db, owned by policy*/
		if (policy_retrieve_zone_list(policy)) {
			result = 1;
			client_printf(sockfd, "Error fetching zones\n");
			break;
		}
		zonelist = policy_zone_list(policy);
		listsize = zone_list_db_size(zonelist);
		if (listsize == 0) {
			ods_log_info("[%s] No zones on policy %s; purging...", module_str, name);
			client_printf(sockfd, "No zones on policy %s; purging...\n", name);
			if (policy_delete(policy)) {
				ods_log_crit("[%s] Error while purging policy from database", module_str);
				client_printf(sockfd, "Error while updating database\n");
				result++;
			}
		}
		policy_free(policy);
	}
	policy_list_free(policy_list);
	return result;
}

struct cmd_func_block policy_purge_funcblock = {
	"policy purge", &usage, &help, NULL, NULL, &run, NULL
};
