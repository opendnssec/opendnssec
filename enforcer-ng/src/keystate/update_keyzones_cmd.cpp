#include <ctime>
#include <iostream>
#include <cassert>

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "keystate/update_keyzones_cmd.h"
#include "keystate/update_keyzones_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
}

static const char *module_str = "update_keyzones_cmd";

/**
 * Print help for the 'key list' command
 *
 */
void help_update_keyzones_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    snprintf(buf, ODS_SE_MAXLINE,
             "update zonelist update zonelist by importing zonelist.xml\n"
             "  --task        schedule command to run once as a separate task.\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

int handled_update_keyzones_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    const char *scmd = "update zonelist";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled
    
    ods_log_debug("[%s] %s command", module_str, scmd);

    if (strncmp(cmd, "--task", 7) == 0) {
        /* schedule task */
        task = update_keyzones_task(engine->config,scmd);
        if (!task) {
            ods_log_crit("[%s] failed to create %s task",
                         module_str,scmd);
        } else {
            status = schedule_task_from_thread(engine->taskq, task, 0);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to create %s task",
                             module_str,scmd);

                (void)snprintf(buf, ODS_SE_MAXLINE,
                               "Unable to schedule %s task.\n",scmd);
                ods_writen(sockfd, buf, strlen(buf));
            } else {
                (void)snprintf(buf, ODS_SE_MAXLINE,"Scheduled %s task.\n",scmd);
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
    } else {
        /* perform task immediately */
        time_t tstart = time(NULL);
        perform_update_keyzones(sockfd,engine->config);
        (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                       scmd,time(NULL)-tstart);
        ods_writen(sockfd, buf, strlen(buf));
    }
    
    return 1;
}
