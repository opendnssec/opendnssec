#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/policy_resalt_cmd.h"
#include "policy/policy_resalt_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "policy_resalt_cmd";

void
help_policy_resalt_cmd(int sockfd)
{
	ods_printf(sockfd,
			"policy resalt   generate new NSEC3 salts for policies that have\n"
			"                salts older than the resalt duration.\n"
             );
}

int
handled_policy_resalt_cmd(int sockfd, engine_type* engine, const char *cmd,
                          ssize_t n)
{
    const char *scmd =  "policy resalt";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

    time_t tstart = time(NULL);
	
    perform_policy_resalt(sockfd, engine->config);
	
    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    return 1;
}
