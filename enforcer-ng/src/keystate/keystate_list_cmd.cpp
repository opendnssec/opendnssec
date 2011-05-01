#include <ctime>
#include <iostream>
#include <cassert>

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "keystate/keystate_list_cmd.h"
#include "keystate/keystate_list_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "daemon/engine.h"
}

static const char *keystate_list_cmd_str = "keystate_list_cmd";

/**
 * Print help for the 'key list' command
 *
 */
void help_keystate_list_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "key list        list all the keys used by a zone\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

int handled_keystate_list_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    const char *scmd = "key list";
    ssize_t ncmd = strlen(scmd);
    
    if (n < ncmd || strncmp(cmd, scmd, ncmd) != 0) return 0;
    ods_log_debug("[%s] %s command", keystate_list_cmd_str,scmd);
    
    if (cmd[ncmd] == '\0') {
        cmd = "";
    } else if (cmd[ncmd] != ' ') {
        return 0;
    } else {
        cmd = &cmd[ncmd+1];
    }
    
    if (strncmp(cmd, "--task", 7) == 0) {
        /* start the policy reader task */
        /* schedule task */
        task = keystate_list_task(engine->config);
        if (!task) {
            ods_log_crit("[%s] failed to create key list task",
                         keystate_list_cmd_str);
        } else {
            status = schedule_task_from_thread(engine->taskq, task, 0);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to create key list task",
                             keystate_list_cmd_str);

                (void)snprintf(buf, ODS_SE_MAXLINE, "Unable to schedule "
                               "key list task.\n");
                ods_writen(sockfd, buf, strlen(buf));
            } else {
                (void)snprintf(buf, ODS_SE_MAXLINE, "Scheduled key "
                               "list task.\n");
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
    } else {
        perform_keystate_list(sockfd,engine->config);
        (void)snprintf(buf, ODS_SE_MAXLINE, "key list complete.\n");
        ods_writen(sockfd, buf, strlen(buf));
    }
    
    return 1;
}
