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

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "enforcer/enforce_task.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "db/key_data.h"
#include "keystate/keystate_ds.h"
#include "keystate/keystate_ds_submit_task.h"

#include "keystate/keystate_ds_submit_cmd.h"

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key ds-submit\n"
		"	--zone <zone>				aka -z\n"
		"	--keytag <keytag> | --cka_id <CKA_ID>	aka -x | -k\n"
/*		"      [--force]                  (aka -f)  force even if there is no configured\n"
		"                                           DelegationSignerSubmitCommand.\n" */
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"Issue a ds-submit to the enforcer for a KSK.\n"
		"(This command with no parameters lists eligible keys.)\n"
		"\nOptions:\n"
		"zone		name of the zone\n"
		"keytag|cka_id	specify the key tag or the locator of the key\n\n");
}

static int
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
	int error;
        db_connection_t* dbconn = getconnectioncontext(context);
        engine_type* engine = getglobalcontext(context);
	/* TODO, this changes the state, but sbmt cmd is not exec. */
	error = run_ds_cmd(sockfd, cmd, dbconn,
		KEY_DATA_DS_AT_PARENT_SUBMIT,
		KEY_DATA_DS_AT_PARENT_SUBMITTED, engine);
	if (error == 0) {
		/* YBS: TODO only affected zones */
		enforce_task_flush_all(engine, dbconn);
	}
	return error;

}

struct cmd_func_block key_ds_submit_funcblock = {
	"key ds-submit", &usage, &help, NULL, &run
};
