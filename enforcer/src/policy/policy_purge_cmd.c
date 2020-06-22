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
#include "enforcer/enforce_task.h"
#include "db/dbw.h"

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

/**
 * Purge
 * @param dbconn, Active database connection
 *
 * @return: error status, >0 on error
 */
static int
purge_policies(int sockfd, db_connection_t *dbconn)
{
    client_printf(sockfd, "Purging policies\n");
    struct dbw_db *db = dbw_fetch(dbconn, "writable policies, with count of zones");
    if (!db) return 1;
    for (int i = 0; i < db->npolicies; i++) {
        if (db->policies[i]->zone_count == 0) {
            ods_log_info("[%s] No zones on policy %s; purging...", module_str, db->policies[i]->name);
            client_printf(sockfd, "No zones on policy %s; purging...\n", db->policies[i]->name);
            for (size_t pk = 0; pk < db->policies[i]->policykey_count; pk++) {
                db->policies[i]->policykey[pk] = NULL;
            }
            for (size_t hk = 0; hk < db->policies[i]->hsmkey_count; hk++) {
                db->policies[i]->hsmkey[hk] = NULL;
            }
            db->policies[i] = NULL;
        }
    }
    if (dbw_commit(db)) {
        ods_log_crit("[%s] Failed to apply changes to the database", module_str);
        client_printf(sockfd, "Failed to apply changes to the database\n");
        dbw_free(db);
        return 1;
    }
    dbw_free(db);
    return 0;
}

static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
    db_connection_t* dbconn = getconnectioncontext(context);
    (void) cmd;
    ods_log_debug("[%s] %s command", module_str, policy_purge_funcblock.cmdname);
    return purge_policies(sockfd, dbconn);
}

struct cmd_func_block policy_purge_funcblock = {
	"policy purge", &usage, &help, NULL, &run
};
