#include <ctime>
#include <iostream>
#include <cassert>

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "keystate/keystate_ds_seen_cmd.h"
#include "keystate/keystate_ds_seen_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
}

static const char *module_str = "keystate_ds_seen_cmd";

/**
 * Print help for the 'key list' command
 *
 */
void help_keystate_ds_seen_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "key ds-seen     show the ds-seen flag for all keys.\n"
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
    bool bHasZone = ods_find_arg_and_param(&argc,argv,"zone","z",&zone)!=-1 && zone;
    bool bHasId = ods_find_arg_and_param(&argc,argv,"id","k",&id)!=-1 && id;
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str,scmd);
        (void)snprintf(buf, ODS_SE_MAXLINE,"unknown arguments\n");
        ods_writen(sockfd, buf, strlen(buf));
        return 1; // errors, but handled
    }
            
    /* perform task directly */
    time_t tstart = time(NULL);
    perform_keystate_ds_seen(sockfd,engine->config,zone,id);
    (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                   scmd,time(NULL)-tstart);
    ods_writen(sockfd, buf, strlen(buf));
    
    return 1;
}
