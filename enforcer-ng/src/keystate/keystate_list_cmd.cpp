#include <ctime>
#include <iostream>
#include <cassert>

#include "keystate/keystate_list_cmd.h"
#include "keystate/keystate_list_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "keystate_list_cmd";

void help_keystate_list_cmd(int sockfd)
{
    ods_printf(sockfd,
        "key list        list all the keys used by a zone\n"
//        "  --verbose     (aka -v) also show the id for every key.\n"
        );
}

int handled_keystate_list_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
    const char *scmd = "key list";

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
        ods_printf(sockfd,"too many arguments\n");
        return 1; // errors, but handled
    }
    
    bool bVerbose = ods_find_arg(&argc,argv,"verbose","v") != -1;
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str,scmd);
        ods_printf(sockfd,"unknown arguments\n");
        return 1; // errors, but handled
    }
    
    time_t tstart = time(NULL);

    perform_keystate_list(sockfd,engine->config,bVerbose?1:0);
	
	ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    
    return 1;
}
