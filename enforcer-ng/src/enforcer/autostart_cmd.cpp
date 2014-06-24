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
#include "enforcer/enforce_task.h"
#include "policy/policy_resalt_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/orm.h"
#include "protobuf-orm/pb-orm.h"
#include "policy/kasp.pb.h"

#include "enforcer/autostart_cmd.h"


static const char *module_str = "autostart_cmd";

static void 
schedule_task(engine_type* engine, task_type *task, const char * what)
{
    /* schedule task */
    if (!task) {
        ods_log_crit("[%s] failed to create %s task", module_str, what);
    } else {
        task->when += 2; /* quick fix race condition at startup
            Allow orm/database to come up fully and prevent backoff */
        char buf[ODS_SE_MAXLINE];
        ods_status status = lock_and_schedule_task(engine->taskq, task, 0);
        if (status != ODS_STATUS_OK) {
            ods_log_crit("[%s] failed to create %s task", module_str, what);
        } else {
            ods_log_debug("[%s] scheduled %s task", module_str, what);
            engine_wakeup_workers(engine);
        }
    }
}

int
database_ready(engineconfig_type* config)
{
	/* Try to select from policies. This is only used to probe if the
	 * database is already setup. If not, we don't schedule tasks which
	 * would otherwise pollute the logs repeatedly.
	 * TODO: I'd like to see a better probe which does not log an error */
	OrmConnRef conn;
	OrmResultRef rows;
	::ods::kasp::Policy policy;

	if (!config) return 0;

	if (!ods_orm_connect(-1, config, conn) ||
		!OrmMessageEnum(conn, policy.descriptor(), rows))
	{
		return 0;
	}
	rows.release();
	return 1;
}

void
autostart(engine_type* engine)
{
	task_type *resalt_task, *task;
	ods_log_debug("[%s] autostart", module_str);

	/* Remove old tasks in queue */
	while ((task = schedule_pop_task(engine->taskq))) {
		ods_log_verbose("popping task \"%s\" from queue", task->who);
	}
	if (!engine->database_ready) return;

	if (resalt_task = policy_resalt_task(engine)) {
		/* race condition at startup. Make sure resalt loses over
		 * enforce. Not fatal but disturbs test. */
		resalt_task->when += 3;
	}
	schedule_task(engine, resalt_task, "resalt");
	schedule_task(engine, enforce_task(engine, 1), "enforce");
}
