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
#include "shared/str.h"
#include "enforcer/enforce_task.h"
#include "clientpipe.h"
#include "db/zone.h"
#include "shared/log.h"
#include "shared/file.h"

#include "keystate/keystate_rollover_cmd.h"

static const char *module_str = "keystate_rollover_cmd";

static int
perform_keystate_rollover(int sockfd, db_connection_t *dbconn,
	const char *zonename, int nkeyrole)
{
	zone_t* zone;
	int error = 0;

	if (!(zone = zone_new_get_by_name(dbconn, zonename))) {
		client_printf(sockfd, "zone %s not found\n", zonename);
		return 1;
	}
	
	switch (nkeyrole) {
		case 0:
			if (zone_set_roll_ksk_now(zone, 1) ||
				zone_set_roll_zsk_now(zone, 1) ||
				zone_set_roll_csk_now(zone, 1)) {error = 1; break;}
			client_printf(sockfd, "rolling all keys for zone %s\n", zonename);
			ods_log_info("[%s] Manual rollover initiated for all keys on Zone: %s",
				module_str, zonename);
			break;
		case KEY_DATA_ROLE_KSK:
			if (zone_set_roll_ksk_now(zone, 1)) {error = 1; break;};
			client_printf(sockfd, "rolling KSK for zone %s\n", zonename);
			ods_log_info("[%s] Manual rollover initiated for KSK on Zone: %s", module_str, zonename);
			break;
		case KEY_DATA_ROLE_ZSK:
			if (zone_set_roll_zsk_now(zone, 1)) {error = 1; break;}
			client_printf(sockfd, "rolling ZSK for zone %s\n", zonename);
			ods_log_info("[%s] Manual rollover initiated for ZSK on Zone: %s", module_str, zonename);
			break;
		case KEY_DATA_ROLE_CSK:
			if (zone_set_roll_csk_now(zone, 1)) {error = 1; break;}
			client_printf(sockfd, "rolling CSK for zone %s\n", zonename);
			ods_log_info("[%s] Manual rollover initiated for CSK on Zone: %s", module_str, zonename);
			break;
		default:
			ods_log_assert(false && "nkeyrole out of range");
			ods_log_error_and_printf(sockfd, module_str,
				"nkeyrole out of range");
			error = 1;
	}
	error = error || zone_set_next_change(zone, 0) || zone_update(zone);
	zone_free(zone);
	if (error) {
		ods_log_error_and_printf(sockfd, module_str,
			"updating zone in the database failed");
	}
	return error;
}

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key rollover           Perform a manual key rollover.\n"
		"      --zone <zone>              (aka -z)  zone.\n"
		"      [--keytype <keytype>]      (aka -t)  KSK or ZSK (default all).\n"
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
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_rollover_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	char buf[ODS_SE_MAXLINE];
	#define NARGV 8
	const char *argv[NARGV];
	int argc, error, nkeytype = 0;
	const char *zone = NULL, *keytype = NULL;

	ods_log_debug("[%s] %s command", module_str, key_rollover_funcblock()->cmdname);

	cmd = ods_check_command(cmd, n, key_rollover_funcblock()->cmdname);

	/* Use buf as an intermediate buffer for the command. */
	strncpy(buf, cmd, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';

	/* separate the arguments */
	argc = ods_str_explode(buf, NARGV, argv);
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
						module_str, key_rollover_funcblock()->cmdname);
		client_printf(sockfd,"too many arguments\n");
		return -1;
	}

	(void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
	(void)ods_find_arg_and_param(&argc,argv,"keytype","t",&keytype);
	if (argc) {
		ods_log_warning("[%s] unknown arguments for %s command",
			module_str, key_rollover_funcblock()->cmdname);
		client_printf(sockfd,"unknown arguments\n");
		return -1;
	}
	if (!zone) {
		ods_log_warning("[%s] expected option --zone <zone> for %s command",
			module_str, key_rollover_funcblock()->cmdname);
		client_printf(sockfd,"expected --zone <zone> option\n");
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

	error = perform_keystate_rollover(sockfd, dbconn, zone, nkeytype);
	flush_enforce_task(engine, 0);
	return error;
}

static struct cmd_func_block funcblock = {
	"key rollover", &usage, &help, &handles, &run
};

struct cmd_func_block*
key_rollover_funcblock(void)
{
	return &funcblock;
}
