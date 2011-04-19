#include <ctime>
#include <iostream>
#include <cassert>

#include "hsmkey/hsmkey.pb.h"

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "hsmkey/keypregen_cmd.h"
#include "hsmkey/keypregen_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "daemon/engine.h"
}

static const char *keypregen_cmd_str = "keypregen_cmd";

/**
 * Print help for the 'keypregen' command
 *
 */
void help_keypregen_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "keypregen       pre-generate a collection of cryptographic keys\n"
        "                before they are actually needed by the enforcer\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

int handled_keypregen_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    
    if (n < 9 || strncmp(cmd, "keypregen", 9) != 0) return 0;
    ods_log_debug("[%s] keypregen command", keypregen_cmd_str);
    
    if (cmd[9] == '\0') {
        cmd = "";
    } else if (cmd[9] != ' ') {
        return 0;
    } else {
        cmd = &cmd[9+1];
    }
    
    if (strncmp(cmd, "--task", 7) == 0) {
        /* start the policy reader task */
        /* schedule task */
        task = keypregen_task(engine->config);
        if (!task) {
            ods_log_crit("[%s] failed to create policy reader task",
                         keypregen_cmd_str);
        } else {
            status = schedule_task_from_thread(engine->taskq, task, 0);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to create policy reader task",
                             keypregen_cmd_str);

                (void)snprintf(buf, ODS_SE_MAXLINE, "Unable to schedule key "
                               "pre-generator task.\n");
                ods_writen(sockfd, buf, strlen(buf));
            } else {
                (void)snprintf(buf, ODS_SE_MAXLINE, "Scheduled key "
                               "pre-generator task.\n");
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
    } else {
        perform_keypregen(sockfd,engine->config);
    }
    
    return 1;
}
