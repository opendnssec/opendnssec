#include <ctime>
#include <iostream>
#include <cassert>

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "keystate/keystate_ds_seen_cmd.h"
#include "keystate/keystate_ds_seen_task.h"
#include "enforcer/enforce_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
}

static const char *module_str = "keystate_ds_seen_cmd";

void help_keystate_ds_seen_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "key ds-seen     list KSK keys that were submitted to the parent.\n"
        "  --zone <zone> (aka -z) set KSK key to seen for zone <zone>\n"
        "  --id <id>     (aka -k) with id <id>.\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

int handled_keystate_ds_seen_cmd(int sockfd, engine_type* engine,
                                   const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
    const char *scmd = "key ds-seen";
    
    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

    // Use buf as an intermediate buffer for the command.
    strncpy(buf,cmd,sizeof(buf));
    buf[sizeof(buf)-1] = '\0';

    // separate the arguments
    argc = ods_str_explode(buf,NARGV,argv);
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
    
    // Check for unknown parameters on the command line
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str,scmd);
        (void)snprintf(buf, ODS_SE_MAXLINE,"unknown arguments\n");
        ods_writen(sockfd, buf, strlen(buf));
        return 1; // errors, but handled
    }
    
    // Check for too many parameters on the command line
    if (argc > NARGV) {
        ods_log_warning("[%s] too many arguments for %s command",
                        module_str,scmd);
        (void)snprintf(buf, ODS_SE_MAXLINE,"too many arguments\n");
        ods_writen(sockfd, buf, strlen(buf));
        return 1; // errors, but handled
    }
    
    // Either no option or both need to be present.
    if (zone || id) {
        if (!zone) {
            ods_log_warning("[%s] expected option --zone <zone> for %s command",
                            module_str,scmd);
            (void)snprintf(buf, ODS_SE_MAXLINE,"expected --zone <zone> option\n");
            ods_writen(sockfd, buf, strlen(buf));
            return 1; // errors, but handled
        }
        if (!id) {
            ods_log_warning("[%s] expected option --id <id> for %s command",
                            module_str,scmd);
            (void)snprintf(buf, ODS_SE_MAXLINE,"expected --id <id> option\n");
            ods_writen(sockfd, buf, strlen(buf));
            return 1; // errors, but handled
        }
    }

    /* perform task immediately */
    time_t tstart = time(NULL);
    perform_keystate_ds_seen(sockfd,engine->config,zone,id);
    (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                   scmd,time(NULL)-tstart);
    ods_writen(sockfd, buf, strlen(buf));

    flush_enforce_task(engine);
    
    return 1;
}
