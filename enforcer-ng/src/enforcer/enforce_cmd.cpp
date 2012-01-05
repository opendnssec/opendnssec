#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/kasp.pb.h"
#include "enforcer/enforcerdata.h"
#include "enforcer/enforcer.h"

#include "enforcer/enforce_cmd.h"
#include "enforcer/enforce_task.h"
#include "signconf/signconf_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "enforce_cmd";

/**
 * Print help for the 'enforce' command
 *
 */
void help_enforce_zones_cmd(int sockfd)
{
    ods_printf(sockfd,
		    "enforce         force the enforcer to run once for every zone.\n");
}

/**
 * Handle the 'enforce' command.
 *
 */
int handled_enforce_zones_cmd(int sockfd, engine_type* engine, const char *cmd,
							  ssize_t n)
{
    const char *scmd = "enforce";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

	time_t tstart = time(NULL);

	perform_enforce(sockfd, engine, 1, NULL);
	
	ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    return 1;
}
