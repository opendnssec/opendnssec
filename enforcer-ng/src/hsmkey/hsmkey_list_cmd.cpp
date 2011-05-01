#include <ctime>
#include <iostream>
#include <cassert>

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "hsmkey/hsmkey_list_cmd.h"
#include "hsmkey/hsmkey_list_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "daemon/engine.h"
}

static const char *hsmkey_list_cmd_str = "hsmkey_list_cmd";

/**
 * Print help for the 'hsm key list' command
 *
 */
void help_hsmkey_list_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "hsm key list    list all the cryptographic keys present in the\n"
        "                configured hardware security modules\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

int handled_hsmkey_list_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    ssize_t cmdlen = strlen("hsm key list");
    
    if (n < cmdlen || strncmp(cmd, "hsm key list", cmdlen) != 0) return 0;
    ods_log_debug("[%s] hsm key list command", hsmkey_list_cmd_str);
    
    if (cmd[cmdlen] == '\0') {
        cmd = "";
    } else if (cmd[cmdlen] != ' ') {
        return 0;
    } else {
        cmd = &cmd[cmdlen+1];
    }
    
    if (strncmp(cmd, "--task", 7) == 0) {
        /* start the policy reader task */
        /* schedule task */
        task = hsmkey_list_task(engine->config);
        if (!task) {
            ods_log_crit("[%s] failed to create hsm key list task",
                         hsmkey_list_cmd_str);
        } else {
            status = schedule_task_from_thread(engine->taskq, task, 0);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to create hsm key list task",
                             hsmkey_list_cmd_str);

                (void)snprintf(buf, ODS_SE_MAXLINE, "Unable to schedule hsm "
                               "key list task.\n");
                ods_writen(sockfd, buf, strlen(buf));
            } else {
                (void)snprintf(buf, ODS_SE_MAXLINE, "Scheduled hsm key "
                               "list task.\n");
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
    } else {
        perform_hsmkey_list(sockfd,engine->config);
        (void)snprintf(buf, ODS_SE_MAXLINE, "hsm key list complete.\n");
        ods_writen(sockfd, buf, strlen(buf));
    }
    
    return 1;
}
