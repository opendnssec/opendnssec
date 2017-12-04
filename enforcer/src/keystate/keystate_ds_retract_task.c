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

#include "clientpipe.h"
#include "scheduler/task.h"
#include "daemon/engine.h"
#include "duration.h"
#include "keystate/keystate_ds.h"

#include "keystate/keystate_ds_retract_task.h"

static time_t
keystate_ds_retract_task_perform(task_type* task, char const *zonename, void *userdata,
	void* context)
{
    db_connection_t* dbconn = (db_connection_t*) context;
	(void)change_keys_from_to(dbconn, -1, zonename, NULL, -1,
		KEY_DATA_DS_AT_PARENT_RETRACT, KEY_DATA_DS_AT_PARENT_RETRACTED,
		(engine_type*)userdata, 0);
	return schedule_SUCCESS;
}

task_type *
keystate_ds_retract_task(engine_type *engine, char const *owner)
{
	return task_create(strdup(owner), TASK_CLASS_ENFORCER, TASK_TYPE_DSRETRACT,
		keystate_ds_retract_task_perform, engine, NULL, time_now());
}
