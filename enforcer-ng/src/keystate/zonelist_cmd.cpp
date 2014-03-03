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

#include "keystate/zonelist_cmd.h"
#include "keystate/zonelist_task.h"
#include "enforcer/enforce_task.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "shared/str.h"
#include "shared/file.h"
#include "keystate/update_keyzones_task.h"

static const char *module_str = "zonelist_cmd";

void
help_zonelist_export_cmd(int sockfd)
{
    ods_printf(sockfd,
            "zonelist export        Export zones from database in zonelist.xml format.\n"
            );
}

void
help_zonelist_import_cmd(int sockfd)
{
    ods_printf(sockfd,
            "zonelist import        Sync database with contents of zonelist.xml.\n"
            );
}

int
handled_zonelist_export_cmd(int sockfd, engine_type* engine, const char *cmd,
                     ssize_t n)
{
    const char *scmd = "zonelist export";

    cmd = ods_check_command(cmd, n, scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

    perform_zonelist_export_to_fd(sockfd, engine->config);
    return 1;
}

int
handled_zonelist_import_cmd(int sockfd, engine_type* engine, const char *cmd,
                     ssize_t n)
{
    const char *scmd = "zonelist import";

    cmd = ods_check_command(cmd, n, scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

    perform_update_keyzones(sockfd, engine->config);
	// TODO: Do error checking once we have the return codes sorted out...
	perform_hsmkey_gen(sockfd, engine->config, 0 /* automatic */,
		engine->config->automatic_keygen_duration);

    flush_enforce_task(engine, 1);
    return 1;
}
