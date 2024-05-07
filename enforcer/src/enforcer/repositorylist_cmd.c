/*
 * Copyright (c) 2015 Stichting NLnet Labs
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

#include "enforcer/repositorylist_cmd.h"
#include "daemon/engine.h"
#include "clientpipe.h"
#include "longgetopt.h"
#include "log.h"
#include "str.h"
#include "file.h"

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"repository list\n");
}

static void
help(int sockfd)
{
	client_printf(sockfd, "List repositories.\n\n");
}

static int
run(cmdhandler_ctx_type* context, int argc, char* argv[])
{
    int sockfd = context->sockfd;
    engine_type* engine = (engine_type*)context->globalcontext;

    client_printf(sockfd, "Repositories:\n");
    client_printf(sockfd, "%-31s %-13s %-13s\n", "Name:", "Capacity:", "RequireBackup:");

    for(struct engineconfig_repository*repo = engine->config->repositories; repo; repo=repo->next) {
        client_printf(sockfd, "%-31s %-13s %-13s\n", repo->name, /* capacity */ "-", repo->require_backup?"Yes":"No");
    }

    return 0;
}

struct cmd_func_block repositorylist_funcblock = {
	"repository list", &usage, &help, NULL, NULL, &run, NULL
};
