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

#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/kasp.pb.h"

#include "policy/policy_import_cmd.h"
#include "policy/update_kasp_task.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "policy_import_cmd";

void
help_policy_import_cmd(int sockfd)
{
    ods_printf(sockfd,
			   "policy import          Import policies from kasp.xml into the enforcer database.\n");
}

int
handled_policy_import_cmd(int sockfd, engine_type* engine, const char *cmd,
                        ssize_t n)
{
    const char *scmd = "policy import";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

    time_t tstart = time(NULL);
	
   /* perform_policy_import(sockfd, engine->config); */
    perform_update_kasp(sockfd, engine->config);

	//TODO: Need error checking so we only do this if the update succeeds
	perform_hsmkey_gen(sockfd, engine->config, 0 /* automatic */,
					   engine->config->automatic_keygen_duration);

    flush_all_tasks(sockfd, engine);
	
    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    return 1;
}
