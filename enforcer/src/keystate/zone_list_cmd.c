/*
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
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

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "duration.h"
#include "clientpipe.h"
#include "longgetopt.h"
#include "db/zone_db.h"
#include "db/policy.h"
#include "db/db_value.h"

#include "keystate/zone_list_cmd.h"

static const char *module_str = "zone_list_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"zone list\n");
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "List all zones currently in the database.\n\n"
    );
}

static int
run(cmdhandler_ctx_type* context, int argc, char* argv[])
{
    int sockfd = context->sockfd;
    const char* fmt = "%-31s %-13s %-26s %-34s\n";
    zone_list_db_t* zone_list;
    const zone_db_t* zone;
    policy_t* policy = NULL;
    const char* nctime;
    char buf[32];
    int cmp;
    db_connection_t* dbconn = getconnectioncontext(context);
    engine_type* engine = getglobalcontext(context);

	if (!(zone_list = zone_list_db_new_get(dbconn))) {
	    client_printf_err(sockfd, "Unable to get list of zones, memory allocation or database error!\n");
	    return 1;
	}

    client_printf(sockfd, "Database set to: %s\n", engine->config->datastore);
    if (!(zone = zone_list_db_next(zone_list))) {
        client_printf(sockfd, "No zones in database.\n");
        zone_list_db_free(zone_list);
        return 0;
    }

    client_printf(sockfd, "Zones:\n");
    client_printf(sockfd, fmt, "Zone:", "Policy:", "Next change:",
        "Signer Configuration:");
    while (zone) {
        if (zone_db_next_change(zone) >= time_now()) {
            if (!ods_ctime_r(buf, sizeof(buf), zone_db_next_change(zone))) {
                nctime = "invalid date/time";
            }
            else {
                nctime = buf;
            }
        } else if (zone_db_next_change(zone) >= 0) {
            nctime = "as soon as possible";
        } else {
            nctime = "no changes scheduled";
        }

        if (policy) {
            /*
             * If we already have a policy object; If policy_id compare fails
             * or if they are not the same free the policy object to we will
             * later retrieve the correct policy
             */
            if (db_value_cmp(policy_id(policy), zone_db_policy_id(zone), &cmp)
                || cmp)
            {
                policy_free(policy);
                policy = NULL;
            }
        }
        if (!policy) {
            policy = zone_db_get_policy(zone);
        }

        client_printf(sockfd, fmt,
            zone_db_name(zone),
            (policy ? policy_name(policy) : "NOT_FOUND"),
            nctime,
            zone_db_signconf_path(zone));

        zone = zone_list_db_next(zone_list);
    }
    policy_free(policy);
    zone_list_db_free(zone_list);

    return 0;
}

struct cmd_func_block zone_list_funcblock = {
	"zone list", &usage, &help, NULL, NULL, &run, NULL
};
