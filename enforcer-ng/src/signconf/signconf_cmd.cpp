#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/kasp.pb.h"

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "signconf/signconf_cmd.h"
#include "signconf/signconf_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
}

static const char *module_str = "signconf_cmd";

/**
 * Print help for the 'signconf' command
 *
 */
void help_signconf_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "signconf        write signer configuration files for zones that have "
                        "been updated.\n"
        "  --task        schedule command as a separate task that runs every minute.\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

int handled_signconf_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    const char *scmd = "signconf";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);
    
    if (strncmp(cmd, "--task", 7) == 0) {
        /* schedule task */
        task = signconf_task(engine->config);
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
            } else  {
                (void)snprintf(buf, ODS_SE_MAXLINE, 
                               "Scheduled %s task.\n",scmd);
                ods_writen(sockfd, buf, strlen(buf));
            }
        }
    } else {
        /* perform task immediately */
        time_t tstart = time(NULL);
        perform_signconf(sockfd, engine->config);
        (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                       scmd,time(NULL)-tstart);
        ods_writen(sockfd, buf, strlen(buf));
    }
    return 1;
}
