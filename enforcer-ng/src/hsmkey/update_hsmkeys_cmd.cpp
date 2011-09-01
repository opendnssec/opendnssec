#include <ctime>
#include <iostream>
#include <cassert>

#include "hsmkey/hsmkey.pb.h"

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "hsmkey/update_hsmkeys_cmd.h"
#include "hsmkey/update_hsmkeys_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
}

static const char *module_str = "update_hsmkeys_cmd";

void
help_update_hsmkeys_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "update hsmkeys  import the keys found in all configured HSMs\n"
        "                into the database.\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

int
handled_update_hsmkeys_cmd(int sockfd, engine_type* engine, const char *cmd,
                           ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    const char *scmd = "update hsmkeys";
    ssize_t ncmd = strlen(scmd);

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

    /* perform task immediately */
    time_t tstart = time(NULL);
    perform_update_hsmkeys(sockfd,engine->config);
    (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                   scmd,time(NULL)-tstart);
    ods_writen(sockfd, buf, strlen(buf));

    return 1;
}
