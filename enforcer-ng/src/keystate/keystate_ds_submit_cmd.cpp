#include <ctime>
#include <iostream>
#include <cassert>

#include "keystate/keystate_ds_submit_cmd.h"
#include "keystate/keystate_ds_submit_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "keystate_ds_submit_cmd";

void
help_keystate_ds_submit_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "key ds-submit   list KSK keys that should be submitted to the parent.\n"
        "  --zone <zone> (aka -z) force submit of KSK key for zone <zone>.\n"
        "  --id <id>     (aka -k) force submit of KSK key with id <id>.\n"
        "  --auto        (aka -a) perform submit for all keys that have "
                        "the submit flag set.\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

int
handled_keystate_ds_submit_cmd(int sockfd, engine_type* engine,
                               const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
    task_type *task;
    ods_status status;
    const char *scmd = "key ds-submit";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled
    
    ods_log_debug("[%s] %s command", module_str, scmd);
    
    // Use buf as an intermediate buffer for the command.
    strncpy(buf,cmd,sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    
    // separate the arguments
    argc = ods_str_explode(&buf[0], NARGV, &argv[0]);
    if (argc > NARGV) {
        ods_log_warning("[%s] too many arguments for %s command",
                        module_str,scmd);
        (void)snprintf(buf, ODS_SE_MAXLINE,"too many arguments\n");
        ods_writen(sockfd, buf, strlen(buf));
        return 1; // errors, but handled
    }
    
    const char *zone = NULL;
    const char *id = NULL;
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
    (void)ods_find_arg_and_param(&argc,argv,"id","k",&id);
    bool bAutomatic = ods_find_arg(&argc,argv,"auto","a") != -1;
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str,scmd);
        (void)snprintf(buf, ODS_SE_MAXLINE,"unknown arguments\n");
        ods_writen(sockfd, buf, strlen(buf));
        return 1; // errors, but handled
    }
    
    /* perform task immediately */
    time_t tstart = time(NULL);
    perform_keystate_ds_submit(sockfd,engine->config,zone,id,bAutomatic?1:0);
    if (!zone && !id) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                       scmd,time(NULL)-tstart);
        ods_writen(sockfd, buf, strlen(buf));
    }

    return 1;
}
