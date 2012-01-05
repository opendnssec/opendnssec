#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/kasp.pb.h"

#include "policy/update_kasp_cmd.h"
#include "policy/update_kasp_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "update_kasp_cmd";

void
help_update_kasp_cmd(int sockfd)
{
    ods_printf(sockfd,
	   "update kasp     import policies from kasp.xml into the enforcer.\n");
}

int
handled_update_kasp_cmd(int sockfd, engine_type* engine, const char *cmd,
                        ssize_t n)
{
    const char *scmd = "update kasp";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

    time_t tstart = time(NULL);
	
    perform_update_kasp(sockfd, engine->config);
	
    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    return 1;
}
