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

#include <ctime>
#include <iostream>
#include <cassert>

#include "enforcer/autostart_cmd.h"

#include "enforcer/enforce_task.h"
#include "policy/policy_resalt_task.h"

#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"
#include "policy/kasp.pb.h"

static const char *module_str = "autostart_cmd";

static void 
schedule_task(engine_type* engine, task_type *task, const char * what)
{
    /* schedule task */
    if (!task) {
        ods_log_crit("[%s] failed to create %s task", module_str, what);
    } else {
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
 
void
autostart(engine_type* engine)
{
    ods_log_debug("[%s] autostart", module_str);

	/* Try to select from policies. This is only used to probe if the
	 * database is already setup. If not, we don't schedule tasks which
	 * would otherwise pollute the logs repeatedly. 
	 * TODO: I'd like to see a better probe which does not log an error */
	OrmConnRef conn;
	OrmResultRef rows;
	::ods::kasp::Policy policy;
	if (!ods_orm_connect(-1, engine->config, conn)) {
		ods_log_crit("Could not connect to database.");
		return;
	}
	if (!OrmMessageEnum(conn, policy.descriptor(), rows)) {
		ods_log_info("[%s] Database is not set up yet."
			" Not scheduling tasks.", module_str);
		ods_log_info("[%s] Run the 'ods-enforcer setup'"
		    " command to create the database.", module_str);	
		return;
	}
	rows.release();
    
    schedule_task(engine, policy_resalt_task(engine->config), "resalt");
    schedule_task(engine, enforce_task(engine, 1), "enforce");
}
