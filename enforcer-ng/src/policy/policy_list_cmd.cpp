#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/policy_list_cmd.h"
#include "policy/policy_list_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "policy_list_cmd";

void help_policy_list_cmd(int sockfd)
{
    ods_printf(sockfd,"policy list     list policies\n");
}

int handled_policy_list_cmd(int sockfd, engine_type* engine, const char *cmd, 
                                ssize_t n)
{
    const char *scmd =  "policy list";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);
    
    time_t tstart = time(NULL);

    perform_policy_list(sockfd, engine->config);

    ods_printf(sockfd, "%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    return 1;
}
