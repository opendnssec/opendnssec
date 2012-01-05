#include <ctime>
#include <iostream>
#include <cassert>

#include "hsmkey/hsmkey.pb.h"

#include "hsmkey/update_hsmkeys_cmd.h"
#include "hsmkey/update_hsmkeys_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "update_hsmkeys_cmd";

void
help_update_hsmkeys_cmd(int sockfd)
{
    ods_printf(sockfd,
        "update hsmkeys  import the keys found in all configured HSMs\n"
        "                into the database.\n"
        );
}

int
handled_update_hsmkeys_cmd(int sockfd, engine_type* engine, const char *cmd,
                           ssize_t n)
{
    const char *scmd = "update hsmkeys";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

    time_t tstart = time(NULL);

    perform_update_hsmkeys(sockfd,engine->config,true);
	
    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
	return 1;
}
