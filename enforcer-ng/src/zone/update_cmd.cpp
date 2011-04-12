#include <ctime>
#include <iostream>
#include <cassert>


// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "zone/update_cmd.h"
#include "zone/update_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "daemon/engine.h"
}

#include "policy/kasp.pb.h"

static const char *update_cmd_str = "update_cmd";

void help_update_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
                    "update          update zone list by importing zonelist.xml\n"
                    );
                 /* "update <zone>   update zone with information "
                                    "imported from the zonelist.xml file.\n" */
    ods_writen(sockfd, buf, strlen(buf));
}

int handled_update_cmd(int sockfd, engine_type* engine, const char *cmd, 
                       ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    
    if (n < 6 || strncmp(cmd, "update", 6) != 0) return 0;
    ods_log_debug("[%s] update command", update_cmd_str);
    if (cmd[6] == '\0') {
        cmd = "";
    } else if (cmd[6] != ' ') {
        return 0;
    } else {
        cmd = &cmd[7];
    }

    if (strncmp(cmd, "--task", 7) == 0) {
    
        /* start the update task */
        /* schedule task */
        task = update_task(engine->config);
        if (!task) {
            ods_log_crit("[%s] failed to create update task",
                         update_cmd_str);
        } else {
            status = schedule_task_from_thread(engine->taskq, task, 0);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to create update task",
                             update_cmd_str);
                
                (void)snprintf(buf, ODS_SE_MAXLINE, "Unable to schedule update "
                               "task.\n");
                ods_writen(sockfd, buf, strlen(buf));
            } else  {
                (void)snprintf(buf, ODS_SE_MAXLINE, "Scheduled update task.\n");
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
    } else {
        /* Do the update directly, giving the update process the chance to 
         * report back any problems directly via sockfd.
         */
        perform_update(sockfd, engine->config);
    }
    return 1;
}
