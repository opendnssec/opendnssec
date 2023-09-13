/*
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
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

#include "daemon/engine.h"
#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "longgetopt.h"
#include "utils/kc_helper.h"

#include "enforcer/update_conf_cmd.h"

#include <pthread.h>


static void
usage(int sockfd)
{
	client_printf(sockfd, 
		"update conf\n");
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Update the configuration from conf.xml and reload the Enforcer.\n\n"
    );
}

static int
run(cmdhandler_ctx_type* context, int argc, char* argv[])
{
    int sockfd = context->sockfd;
    char *kasp = NULL;
    char *zonelist = NULL;
    char **repositories = NULL;
    int repository_count = 0;
    int i;
    engine_type* engine = getglobalcontext(context);

    if (check_conf(engine->config->cfg_filename, &kasp, &zonelist, &repositories, &repository_count, (ods_log_verbosity() >= 3))) {
        client_printf_err(sockfd, "Unable to validate '%s' consistency.",
            engine->config->cfg_filename);

        free(kasp);
        free(zonelist);
        if (repositories) {
            for (i = 0; i < repository_count; i++) {
                free(repositories[i]);
            }
            free(repositories);
        }
        return 1;
    }

    free(kasp);
    free(zonelist);
    if (repositories) {
        for (i = 0; i < repository_count; i++) {
            free(repositories[i]);
        }
        free(repositories);
    }

    engine->need_to_reload = 1;
    pthread_cond_signal(&engine->signal_cond);

    return 0;
}

struct cmd_func_block update_conf_funcblock = {
	"update conf", &usage, &help, NULL, NULL, &run, NULL
};
