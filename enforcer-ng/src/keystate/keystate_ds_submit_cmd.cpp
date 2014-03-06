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
#include "keystate/keystate_ds_submit_task.h"
#include "shared/file.h"
#include "shared/str.h"

#include "keystate/keystate_ds_submit_cmd.h"

static const char *module_str = "keystate_ds_submit_cmd";

static void
usage(int sockfd)
{
	ods_printf(sockfd,
		"key ds-submit          Issue a ds-submit to the enforcer for a KSK.\n"
		"                       (This command with no parameters lists eligible keys.)\n"
		"      --zone <zone>              (aka -z)  zone.\n"
		"      --cka_id <CKA_ID>          (aka -k)  cka_id <CKA_ID> of the key.\n"
		"      [--auto]                   (aka -a)  perform submit for all keys that\n"
		"                                           have the submit flag set.\n"
		"      [--force]                  (aka -f)  force even if there is no configured\n"
		"                                           DelegationSignerSubmitCommand.\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_ds_submit_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
	char buf[ODS_SE_MAXLINE];
	const int NARGV = 8;
	const char *argv[NARGV];
	int argc;
	task_type *task;
	ods_status status;

	ods_log_debug("[%s] %s command", module_str, key_ds_submit_funcblock()->cmdname);

	// Use buf as an intermediate buffer for the command.
	strncpy(buf, cmd, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';

	// separate the arguments
	argc = ods_str_explode(&buf[0], NARGV, &argv[0]);
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
						module_str, key_ds_submit_funcblock()->cmdname);
		ods_printf(sockfd,"too many arguments\n");
		return -1;
	}

	const char *zone = NULL;
	const char *cka_id = NULL;
	(void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
	(void)ods_find_arg_and_param(&argc,argv,"cka_id","k",&cka_id);
	bool force = ods_find_arg(&argc,argv,"force","f") != -1;
	bool bAutomatic = ods_find_arg(&argc,argv,"auto","a") != -1;
	if (argc) {
		ods_log_warning("[%s] unknown arguments for %s command",
						module_str, key_ds_submit_funcblock()->cmdname);
		ods_printf(sockfd,"unknown arguments\n");
		return -1;
	}

	/* perform task immediately */
	perform_keystate_ds_submit(sockfd,engine->config,zone,cka_id,bAutomatic?1:0, force);
	return 0;
}

static struct cmd_func_block funcblock = {
	"key ds-submit", &usage, NULL, &handles, &run
};

struct cmd_func_block*
key_ds_submit_funcblock(void)
{
	return &funcblock;
}
