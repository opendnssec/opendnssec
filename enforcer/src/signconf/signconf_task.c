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
#include "duration.h"
#include "log.h"
#include "file.h"

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


static time_t
signconf_task_perform(char const *owner, void *context,
    db_connection_t* dbconn)
{
    (void)perform_signconf(-1, dbconn, 0);
    return -1;
}

task_t*
signconf_task(const char* who)
{
    return task_create(strdup(who), TASK_CLASS_ENFORCER,
        TASK_TYPE_SIGNCONF, signconf_task_perform, NULL, NULL, time_now());
}
