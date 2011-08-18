#include <ctime>
#include <iostream>
#include <cassert>

#include "hsmkey/hsmkey.pb.h"

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "hsmkey/update_hsmkeys_cmd.h"
#include "hsmkey/update_hsmkeys_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
}

static const char *module_str = "update_hsmkeys_cmd";

/**
 * Print help for the 'update_hsmkeys' command
 *
 */
void help_update_hsmkeys_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "update hsmkeys  import the keys found in all configured HSMs\n"
        "                into the database.\n"
        "  --task        schedule command to run once as a separate task.\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

int handled_update_hsmkeys_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    const char *scmd = "update hsmkeys";
    ssize_t ncmd = strlen(scmd);
    
    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled
    
    ods_log_debug("[%s] %s command", module_str, scmd);
    
    if (strncmp(cmd, "--task", 7) == 0) {
        /* schedule task */
        task = update_hsmkeys_task(engine->config,scmd);
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
        /* perform task immediately */
        time_t tstart = time(NULL);
        perform_update_hsmkeys(sockfd,engine->config);
        (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                       scmd,time(NULL)-tstart);
        ods_writen(sockfd, buf, strlen(buf));
    }
    
    return 1;
}
