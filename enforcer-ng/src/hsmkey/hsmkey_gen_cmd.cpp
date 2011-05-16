#include <ctime>
#include <iostream>
#include <cassert>

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "hsmkey/hsmkey_gen_cmd.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "daemon/engine.h"
}

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
    ssize_t ncmd = strlen(scmd);
    
    if (n < ncmd || strncmp(cmd, scmd, ncmd) != 0) return 0;
    ods_log_debug("[%s] %s command", module_str, scmd);
    
    if (cmd[ncmd] == '\0') {
        cmd = "";
    } else if (cmd[ncmd] != ' ') {
        return 0;
    } else {
        cmd = &cmd[ncmd+1];
    }
    
    if (strncmp(cmd, "--task", 7) == 0) {
        /* schedule task */
        task = hsmkey_gen_task(engine->config,scmd);
        if (!task) {
            ods_log_crit("[%s] failed to create %s task",
                         module_str,scmd);
        } else {
            status = schedule_task_from_thread(engine->taskq, task, 0);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to create %s task", module_str, scmd);
                (void)snprintf(buf, ODS_SE_MAXLINE,
                               "Unable to schedule %s task.\n",scmd);
                ods_writen(sockfd, buf, strlen(buf));
            } else {
                (void)snprintf(buf, ODS_SE_MAXLINE,
                               "Scheduled %s generator task.\n",scmd);
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
    } else {
        time_t tstart = time(NULL);
        perform_hsmkey_gen(sockfd,engine->config);
        (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                       scmd,time(NULL)-tstart);
        ods_writen(sockfd, buf, strlen(buf));
    }
    
    return 1;
}
