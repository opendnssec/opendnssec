#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/kasp.pb.h"
#include "enforcer/enforcerdata.h"
#include "enforcer/enforcer.h"

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "enforcer/enforce_cmd.h"
#include "enforcer/enforce_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "daemon/engine.h"
}

static const char *enforce_cmd_str = "enforce_cmd";

/**
 * Print help for the 'enforce' command
 *
 */
void help_enforce_zones_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
    "enforce         enumerate all zones and run the enforcer once for every "
                    "zone.\n");
// "enforce <zone>  read zone and schedule for immediate enforcement.\n"
// "enforce --all   read all zones and schedule all for enforcement.\n"
    ods_writen(sockfd, buf, strlen(buf));
}

/**
 * Handle the 'enforce' command.
 *
 */
int handled_enforce_zones_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    // Start a task that will go through all zones and run enforce on every one
    // of them
    char buf[ODS_SE_MAXLINE];
    ods_status status = ODS_STATUS_OK;
    
    if (n < 7 || strncmp(cmd, "enforce", 7) != 0) return 0;
    ods_log_debug("[%s] enforce command", enforce_cmd_str);
    
    if (cmd[7] == '\0') {
        cmd = "";
    } else if (cmd[7] != ' ') {
        return 0;
    } else {
        cmd = &cmd[7+1];
    }

    if (strncmp(cmd, "--task", 7) == 0) {
        /* start the enforcer task */
        /* schedule task */
        task_type *task = enforce_task(engine->config);
        if (!task) {
            ods_log_crit("[%s] failed to create enforce task",
                         enforce_cmd_str);
        } else {
            status = schedule_task_from_thread(engine->taskq, task, 0);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to create enforce task",
                             enforce_cmd_str);
                
                (void)snprintf(buf, ODS_SE_MAXLINE, "Unable to schedule enforce "
                               "task.\n");
                ods_writen(sockfd, buf, strlen(buf));
            } else  {
                (void)snprintf(buf, ODS_SE_MAXLINE, "Scheduled enforce task.\n");
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
    } else {
        perform_enforce(sockfd,engine->config);
    }
    
    return 1;
}
