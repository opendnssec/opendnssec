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
#include "signconf/signconf_task.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"

#include "signconf/signconf_cmd.h"

static const char *module_str = "signconf_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"signconf\n"
	);
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Force write of signer configuration files for all zones.\n\n"
    );
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, signconf_funcblock()->cmdname) ? 1 : 0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
    (void)engine; (void)cmd; (void)n;

	ods_log_debug("[%s] %s command", module_str, signconf_funcblock()->cmdname);

	return perform_signconf(sockfd, dbconn, 1);
}

static struct cmd_func_block funcblock = {
	"signconf", &usage, &help, &handles, &run
};

struct cmd_func_block*
signconf_funcblock(void)
{
	return &funcblock;
}
