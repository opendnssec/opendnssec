#include <ctime>
#include <iostream>
#include <cassert>

#include "keystate/zone_list_cmd.h"
#include "keystate/zone_list_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "zone_list_cmd";

void help_zone_list_cmd(int sockfd)
{
    ods_printf(sockfd,"zone list       list zones\n");
}

int handled_zone_list_cmd(int sockfd, engine_type* engine, const char *cmd, 
						  ssize_t n)
{
    const char *scmd =  "zone list";
    
    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled
    
    ods_log_debug("[%s] %s command", module_str, scmd);

    time_t tstart = time(NULL);

    perform_zone_list(sockfd,engine->config);

    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    return 1;
}
