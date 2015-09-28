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

/* static const char *module_str = "keystate_ds_retract_task"; */

/* executed headless */
static task_type * 
keystate_ds_retract_task_perform(task_type *task)
{
	assert(task);

	(void)change_keys_from_to(task->dbconn, -1, NULL, NULL, 0,
		KEY_DATA_DS_AT_PARENT_RETRACT, KEY_DATA_DS_AT_PARENT_RETRACTED,
		(engine_type*)task->context);
	task_cleanup(task);
	return NULL;
}

task_type *
keystate_ds_retract_task(engine_type *engine)
{
	task_id what_id;
	const char *what = "ds-retract";
	const char *who = "KSK keys with retract flag set";
	
	what_id = task_register(what, "keystate_ds_retract_task_perform",
		keystate_ds_retract_task_perform);
	return task_create(what_id, time_now(), who, what, engine, NULL);
}
