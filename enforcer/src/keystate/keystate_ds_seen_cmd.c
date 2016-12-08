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
#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "enforcer/enforce_task.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "db/key_data.h"
#include "keystate/keystate_ds.h"

#include "keystate/keystate_ds_seen_cmd.h"

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key ds-seen\n"
		"	--zone <zone>				aka -z \n"
		"	--keytag <keytag> | --cka_id <CKA_ID>	aka -x | -k\n"
		"key ds-seen\n"
		"	--all					aka -a \n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"Issue a ds-seen to the enforcer for a KSK/ or all 'ready for ds-seen' KSKs. This command indicates to OpenDNSSEC taht a submitted DS record has appreared in the parent zone, and thereby trigger the completion of KSK rollover.\n"
		"(This command with no parameters lists eligible keys.)\n"
		"\nOptions:\n"
		"zone		name of the zone\n"
		"keytag|cka_id	specify the keytag or the locator of the key\n\n"
		"all		for all 'ready for ds-seen' KSKs");
}

static int
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
	int error;
        db_connection_t* dbconn = getconnectioncontext(context);
        engine_type* engine = getglobalcontext(context);
	error = run_ds_cmd(sockfd, cmd, dbconn,
		KEY_DATA_DS_AT_PARENT_SUBMITTED,
		KEY_DATA_DS_AT_PARENT_SEEN, engine);
	if (error == 0) {
		/* YBS: TODO only affected zones */
		enforce_task_flush_all(engine, dbconn);
	}
	return error;

}

struct cmd_func_block key_ds_seen_funcblock = {
	"key ds-seen", &usage, &help, NULL, &run
};
