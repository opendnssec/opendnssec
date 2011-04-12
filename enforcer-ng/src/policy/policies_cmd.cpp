#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/kasp.pb.h"

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "policy/policies_cmd.h"
#include "policy/policies_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "daemon/engine.h"
}

static const char *policies_cmd_str = "policies_cmd";

/**
 * Print help for the 'policies' command
 *
 */
void help_policies_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "policies        import policies from kasp.xml into the enforcer.\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

int handled_policies_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    
    if (n < 8 || strncmp(cmd, "policies", 8) != 0) return 0;
    ods_log_debug("[%s] policies command", policies_cmd_str);
    
    if (cmd[8] == '\0') {
        cmd = "";
    } else if (cmd[8] != ' ') {
        return 0;
    } else {
        cmd = &cmd[9];
    }
    
    if (strncmp(cmd, "--task", 7) == 0) {
        /* start the policy reader task */
        /* schedule task */
        task = policies_task(engine->config);
        if (!task) {
            ods_log_crit("[%s] failed to create policy reader task",
                         policies_cmd_str);
        } else {
            status = schedule_task_from_thread(engine->taskq, task, 0);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to create policy reader task",
                             policies_cmd_str);

                (void)snprintf(buf, ODS_SE_MAXLINE, "Unable to schedule policy "
                               "reader task.\n");
                ods_writen(sockfd, buf, strlen(buf));
            } else {
                (void)snprintf(buf, ODS_SE_MAXLINE, "Scheduled policy reader "
                               "task.\n");
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
    } else {
        perform_policies(sockfd,engine->config);
    }
    
    return 1;
}
