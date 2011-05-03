#include <ctime>
#include <iostream>
#include <cassert>


// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "policy/policy_resalt_cmd.h"
#include "policy/policy_resalt_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "daemon/engine.h"
}

static const char *policy_resalt_cmd_str = "policy_resalt_cmd";

void help_policy_resalt_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
                    "policy resalt   resalt policies\n"
                    );
    ods_writen(sockfd, buf, strlen(buf));
}

int handled_policy_resalt_cmd(int sockfd, engine_type* engine, const char *cmd, 
                                ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    const char *scmd =  "policy resalt";
    ssize_t ncmd = strlen(scmd);
    
    if (n < ncmd || strncmp(cmd,scmd, ncmd) != 0) return 0;
    ods_log_debug("[%s] %s command", policy_resalt_cmd_str, scmd);
    if (cmd[ncmd] == '\0') {
        cmd = "";
    } else if (cmd[ncmd] != ' ') {
        return 0;
    } else {
        cmd = &cmd[ncmd+1];
    }
    
    if (strncmp(cmd, "--task", 7) == 0) {
        /* schedule task */
        task = policy_resalt_task(engine->config);
        if (!task) {
            ods_log_crit("[%s] failed to create %s task",
                         policy_resalt_cmd_str,scmd);
        } else {
            status = schedule_task_from_thread(engine->taskq, task, 0);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to create %s task",
                             policy_resalt_cmd_str,scmd);
                
                (void)snprintf(buf, ODS_SE_MAXLINE, 
                               "Unable to schedule %s task.\n",scmd);
                ods_writen(sockfd, buf, strlen(buf));
            } else  {
                (void)snprintf(buf, ODS_SE_MAXLINE,
                               "Scheduled %s task.\n",scmd);
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
    } else {
        /* Do the update directly, giving the update process the chance to 
         * report back any problems directly via sockfd.
         */
        perform_policy_resalt(sockfd, engine->config);
        (void)snprintf(buf, ODS_SE_MAXLINE, "%s complete.\n",scmd);
        ods_writen(sockfd, buf, strlen(buf));
    }
    return 1;
}
