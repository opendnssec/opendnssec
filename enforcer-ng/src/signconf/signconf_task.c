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

#include "signconf/signconf.h"
#include "shared/duration.h"
#include "shared/log.h"
#include "shared/file.h"

#include "signconf/signconf_task.h"

static const char *module_str = "signconf_cmd";

int perform_signconf(int sockfd, const db_connection_t* dbconn, int force) {
    int ret;
    char cmd[SYSTEM_MAXLEN];

    ods_log_info("[%s] performing signconf for all zones", module_str);
    ret = signconf_export_all(sockfd, dbconn, force);
    if (ret == SIGNCONF_EXPORT_NO_CHANGE) {
        ods_log_info("[%s] signconf done, no change", module_str);
        return 0;
    }
    if (ret != SIGNCONF_EXPORT_OK) {
        ods_log_error("[%s] signconf failed", module_str);
        return 1;
    }

    ods_log_info("[%s] signconf done, notifying signer", module_str);
    /* TODO: do this better, connect directly or use execve() */
    if (snprintf(cmd, sizeof(cmd), "%s --all", SIGNER_CLI_UPDATE) >= (int)sizeof(cmd)
        || system(cmd))
    {
        ods_log_error("[%s] unable to notify signer of signconf changes!", module_str);
        return 1;
    }

	return 0;
}


static task_type* signconf_task_perform(task_type* task) {
    perform_signconf(-1, task->dbconn, 0);
    task_cleanup(task);
    return NULL;
}

task_type* signconf_task(const db_connection_t* dbconn, const char* what, const char* who) {
    task_id what_id = task_register(what, "signconf_task_perform", signconf_task_perform);
	return task_create(what_id, time_now(), who, what, (void*)dbconn);
}
