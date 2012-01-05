#include <ctime>
#include <iostream>
#include <cassert>

#include "keystate/update_keyzones_cmd.h"
#include "keystate/update_keyzones_task.h"
#include "enforcer/enforce_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "update_keyzones_cmd";

void
help_update_keyzones_cmd(int sockfd)
{
    ods_printf(sockfd,
             "update zonelist update zonelist by importing zonelist.xml\n"
        );
}

int
handled_update_keyzones_cmd(int sockfd, engine_type* engine, const char *cmd,
                            ssize_t n)
{
    const char *scmd = "update zonelist";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);
    
    time_t tstart = time(NULL);
	
    perform_update_keyzones(sockfd,engine->config);
	
    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);

    flush_enforce_task(engine);
    return 1;
}
