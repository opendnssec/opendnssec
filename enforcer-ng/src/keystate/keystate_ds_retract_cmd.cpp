#include <ctime>
#include <iostream>
#include <cassert>

#include "keystate/keystate_ds_retract_cmd.h"
#include "keystate/keystate_ds_retract_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "keystate_ds_retract_cmd";

void
help_keystate_ds_retract_cmd(int sockfd)
{
    ods_printf(sockfd,
        "key ds-retract  list KSK keys that should be retracted from the parent.\n"
        "  --zone <zone> (aka -z) force retract of KSK key for zone <zone>.\n"
        "  --id <id>     (aka -k) force retract of KSK key with id <id>.\n"
        "  --auto        (aka -a) perform retract for all keys that have "
                        "the retract flag set.\n"
        );
}

int
handled_keystate_ds_retract_cmd(int sockfd, engine_type* engine,
								const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
    task_type *task;
    ods_status status;
    const char *scmd = "key ds-retract";

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
        ods_printf(sockfd,"too many arguments\n");
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
        ods_printf(sockfd,"unknown arguments\n");
        return 1; // errors, but handled
    }
    
    /* perform task immediately */
    time_t tstart = time(NULL);
    perform_keystate_ds_retract(sockfd,engine->config,zone,id,bAutomatic?1:0);
    if (!zone && !id) {
        ods_printf(sockfd,"%s completed in %ld seconds.\n",
				   scmd,time(NULL)-tstart);
    }

    return 1;
}
