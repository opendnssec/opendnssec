#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/kasp.pb.h"

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "signconf/signconf_cmd.h"
#include "signconf/signconf_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
}

static const char *module_str = "signconf_cmd";

void
help_signconf_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "signconf        force the writing of signer configuration files "
                        "for all zones.\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

int
handled_signconf_cmd(int sockfd, engine_type* engine, const char *cmd,
                     ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    const char *scmd = "signconf";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

    /* perform task immediately */
    time_t tstart = time(NULL);
    perform_signconf(sockfd, engine->config,1);
    (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                   scmd,time(NULL)-tstart);
    ods_writen(sockfd, buf, strlen(buf));

    return 1;
}
