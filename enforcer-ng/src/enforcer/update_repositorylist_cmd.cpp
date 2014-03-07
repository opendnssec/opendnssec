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
#include "shared/str.h"
#include "shared/file.h"
#include "daemon/engine.h"
#include "enforcer/update_repositorylist_task.h"
#include "daemon/clientpipe.h"

#include "enforcer/update_repositorylist_cmd.h"


static const char *module_str = "update_repositorylist_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"update repositorylist  Import respositories from conf.xml "
		"into the enforcer.\n");
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, update_repositorylist_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
	(void)cmd; (void)n;
	ods_log_debug("[%s] %s command", module_str, 
		update_repositorylist_funcblock()->cmdname);

	if (!perform_update_repositorylist(sockfd, engine)) {
		ods_log_error_and_printf(sockfd, module_str,
			"unable to update repositorylist.");
		return 1;
	}
	return 0;
}


static struct cmd_func_block funcblock = {
	"update repositorylist", &usage, NULL, &handles, &run
};

struct cmd_func_block*
update_repositorylist_funcblock(void)
{
	return &funcblock;
}
