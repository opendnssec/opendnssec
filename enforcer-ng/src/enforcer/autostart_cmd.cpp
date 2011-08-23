#include <ctime>
#include <iostream>
#include <cassert>

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "enforcer/autostart_cmd.h"

#include "enforcer/enforce_task.h"
#include "policy/policy_resalt_task.h"

#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
}

static const char *module_str = "autostart_cmd";

/**
 * Print help for the 'autostart' command
 *
 */
void help_autostart_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "autostart       start enforcer tasks that always need to be running.\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

static void 
schedule_task(int sockfd, engine_type* engine, 
                        task_type *task, const char * what)

{
    /* schedule task */
    if (!task) {
        ods_log_crit("[%s] failed to create %s task",
                     module_str,what);
    } else {
        char buf[ODS_SE_MAXLINE];
        ods_status status = schedule_task_from_thread(engine->taskq, task, 0);
        if (status != ODS_STATUS_OK) {
            ods_log_crit("[%s] failed to create %s task", module_str, what);
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "Unable to schedule %s task.\n",what);
            ods_writen(sockfd, buf, strlen(buf));
        } else {
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "Scheduled %s task.\n",what);
            ods_writen(sockfd, buf, strlen(buf));
            engine_wakeup_workers(engine);
        }
    }
    
}


/**
 * Handle the 'autostart' command.
 *
 */
int handled_autostart_cmd(int sockfd, engine_type* engine,
                      const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const char *scmd = "autostart";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled
    
    ods_log_debug("[%s] %s command", module_str, scmd);

    time_t tstart = time(NULL);
    
    schedule_task(sockfd,engine,
                  policy_resalt_task(engine->config,"resalt","policies"),
                  "resalt");

    schedule_task(sockfd,engine,
                  enforce_task(engine->config,"enforce","next zone"),
                  "enforce");

    (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                   scmd,time(NULL)-tstart);
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}
