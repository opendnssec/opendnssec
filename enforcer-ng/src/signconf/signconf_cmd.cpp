#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/kasp.pb.h"

#include "signconf/signconf_cmd.h"
#include "signconf/signconf_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "signconf_cmd";

void
help_signconf_cmd(int sockfd)
{
    ods_printf(sockfd,
        "signconf        force the writing of signer configuration files "
                        "for all zones.\n"
        );
}

int
handled_signconf_cmd(int sockfd, engine_type* engine, const char *cmd,
                     ssize_t n)
{
    const char *scmd = "signconf";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

    time_t tstart = time(NULL);
	
    perform_signconf(sockfd, engine->config,1);
	
    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    return 1;
}
