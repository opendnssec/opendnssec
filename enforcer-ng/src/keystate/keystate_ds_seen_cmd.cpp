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

#include "daemon/engine.h"
#include "daemon/cmdhandler.h"
#include "keystate/keystate_ds_seen_task.h"
#include "enforcer/enforce_task.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/clientpipe.h"

#include "keystate/keystate_ds_seen_cmd.h"

static const char *module_str = "keystate_ds_seen_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key ds-seen            Issue a ds-seen to the enforcer for a KSK.\n"
		"                       (This command with no parameters lists eligible keys.)\n"
		"      --zone <zone>              (aka -z)  zone.\n"
		"      --keytag <keytag> | --cka_id <CKA_ID>      (aka -x | -k)\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_ds_seen_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
	char buf[ODS_SE_MAXLINE];
	const int NARGV = 8;
	const char *argv[NARGV];
	int argc;

	ods_log_debug("[%s] %s command", module_str, key_ds_seen_funcblock()->cmdname);
	cmd = ods_check_command(cmd, n, key_ds_seen_funcblock()->cmdname);

	/* consume command */
	cmd = ods_check_command(cmd, n, key_ds_seen_funcblock()->cmdname);

	// Use buf as an intermediate buffer for the command.
	strncpy(buf, cmd, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';

	// separate the arguments
	argc = ods_str_explode(buf,NARGV,argv);
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
						module_str, key_ds_seen_funcblock()->cmdname);
		client_printf(sockfd,"too many arguments\n");
		return -1;
	}

	const char *zone = NULL;
	const char *cka_id = NULL;
	const char *keytag = NULL;
	(void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
	(void)ods_find_arg_and_param(&argc,argv,"cka_id","k",&cka_id);
	(void)ods_find_arg_and_param(&argc,argv,"keytag","x",&keytag);

	// Check for unknown parameters on the command line
	if (argc) {
		ods_log_warning("[%s] unknown arguments for %s command",
						module_str, key_ds_seen_funcblock()->cmdname);
		client_printf(sockfd,"unknown arguments\n");
		return -1;
	}

	// Check for too many parameters on the command line
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
						module_str, key_ds_seen_funcblock()->cmdname);
		client_printf(sockfd,"too many arguments\n");
		return -1;
	}

	// Either no option or combi of zone & cka_id or zone & keytag needs to be 
	// present. But not both cka_id and keytag
	uint16_t nkeytag = 0;
	if (zone || cka_id || keytag) {
		if (!zone) {
			ods_log_warning("[%s] expected option --zone <zone> for %s command",
							module_str, key_ds_seen_funcblock()->cmdname);
			client_printf(sockfd,"expected --zone <zone> option\n");
			return -1;
		}
		if (!cka_id && !keytag) {
			ods_log_warning("[%s] expected option --cka_id <cka_id> or "
							"--keytag <keytag> for %s command",
							module_str, key_ds_seen_funcblock()->cmdname);
			client_printf(sockfd,"expected --cka_id <cka_id> or "
						   "--keytag <keytag> option\n");
			return -1;
		} else {
			if (cka_id && keytag) {
				ods_log_warning("[%s] both --cka_id <cka_id> and --keytag <keytag> given, "
								"please only specify one for %s command",
								module_str, key_ds_seen_funcblock()->cmdname);
				client_printf(sockfd,
							   "both --cka_id <cka_id> and --keytag <keytag> given, "
							   "please only specify one\n");
				return -1;
			}
		}
		if (keytag) {
			int kt = atoi(keytag);
			if (kt<=0 || kt>=65536) {
				ods_log_warning("[%s] value \"%s\" for --keytag is invalid",
								module_str,keytag);
				client_printf(sockfd,
							   "value \"%s\" for --keytag is invalid\n",
							   keytag);
				return 1;
			}
			nkeytag = (uint16_t )kt;
		}
	}
	perform_keystate_ds_seen(sockfd,engine->config,zone,cka_id,nkeytag);
	flush_enforce_task(engine, 0);
	return 0;
}

static struct cmd_func_block funcblock = {
	"key ds-seen", &usage, NULL, &handles, &run
};

struct cmd_func_block*
key_ds_seen_funcblock(void)
{
	return &funcblock;
}
