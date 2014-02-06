/*
 * $Id$
 *
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

#include "enforcer/update_repositorylist_cmd.h"
#include "enforcer/update_repositorylist_task.h"

#include "hsmkey/update_hsmkeys_task.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "hsmkey/hsmkey.pb.h"
#include "shared/str.h"
#include "shared/file.h"

static const char *module_str = "update_repositorylist_cmd";

void
help_update_repositorylist_cmd(int sockfd)
{
	ods_printf(sockfd,
		"update repositorylist  Import respositories from conf.xml "
		"into the enforcer.\n");
}

static void
flush_all_tasks(int sockfd, engine_type* engine)
{
	ods_log_debug("[%s] flushing all tasks...", module_str);
	ods_printf(sockfd,"flushing all tasks...\n");

	ods_log_assert(engine);
	ods_log_assert(engine->taskq);
	lock_basic_lock(&engine->taskq->schedule_lock);
	/* [LOCK] schedule */
	schedule_flush(engine->taskq, TASK_NONE);
	/* [UNLOCK] schedule */
	lock_basic_unlock(&engine->taskq->schedule_lock);
	engine_wakeup_workers(engine);
}

int
handled_update_repositorylist_cmd(int sockfd, engine_type* engine, 
	const char *cmd, ssize_t n)
{
	const char *scmd = "update repositorylist";

	cmd = ods_check_command(cmd,n,scmd);
	if (!cmd)
		return 0; // not handled

	ods_log_debug("[%s] %s command", module_str, scmd);
	time_t tstart = time(NULL);

	if (perform_update_repositorylist(sockfd, engine, cmd, n)) {
		kill(engine->pid, SIGHUP);
		ods_printf(sockfd, "Notifying enforcer of new respositories! \n");
	}

	ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
	return 1;
}


