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
#include "enforcer/enforce_task.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "daemon/clientpipe.h"

#include "enforcer/enforce_cmd.h"

static const char *module_str = "enforce_cmd";

/**
 * Print help for the 'enforce' command
 *
 */
static void
usage(int sockfd)
{
	client_printf(sockfd,
		"enforce                Force the enforcer to run once for every zone.\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, enforce_funcblock()->cmdname)?1:0;
}

static void
reschedule_enforce(task_type *task, time_t t_when, const char *z_when)
{
	ods_log_assert(task->allocator);
	ods_log_assert(task->who);
	allocator_deallocate(task->allocator,(void*)task->who);
	task->who = allocator_strdup(task->allocator, z_when);
	task->when = t_when;
	task->backoff = 0;
}

/**
 * Handle the 'enforce' command.
 *
 */
static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	time_t t_next;
	task_type *task;
	(void)cmd; (void)n;
	ods_log_debug("[%s] %s command", module_str, enforce_funcblock()->cmdname);

	task = enforce_task(engine, 1);

	t_next = perform_enforce_lock(sockfd, engine, 1, task, dbconn);
	reschedule_enforce(task, t_next, "next zone");
	schedule_task(engine->taskq, task);
	return 0;
}

static struct cmd_func_block funcblock = {
	"enforce", &usage, NULL, &handles, &run
};

struct cmd_func_block*
enforce_funcblock(void)
{
	return &funcblock;
}
