#include <ctime>
#include <iostream>
#include <cassert>

#include "hsmkey/hsmkey_gen_cmd.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "hsmkey_gen_cmd";

/**
 * Print help for the 'hsmkey_gen' command
 *
 */
void help_hsmkey_gen_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "hsm key gen     pre-generate a collection of cryptographic keys\n"
        "                before they are actually needed by the enforcer\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

int handled_hsmkey_gen_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    const char *scmd = "hsm key gen";
    
    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

    /* perform task immediately */
    time_t tstart = time(NULL);
    perform_hsmkey_gen(sockfd,engine->config,1);
    (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                   scmd,time(NULL)-tstart);
    ods_writen(sockfd, buf, strlen(buf));
    
    return 1;
}
