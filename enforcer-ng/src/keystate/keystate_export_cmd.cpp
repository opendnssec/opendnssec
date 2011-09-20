#include <ctime>
#include <iostream>
#include <cassert>

#include "keystate/keystate_export_cmd.h"
#include "keystate/keystate_export_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "keystate_export_cmd";

void help_keystate_export_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "key export      export trust anchors of a given zone\n"
        "  --zone <zone> (aka -z) export for the given zone.\n"
        "  [--dnskey]    export DNSKEY in BIND format (default).\n"
        "  [--ds]        export DS in BIND format.\n");
    ods_writen(sockfd, buf, strlen(buf));
}

int handled_keystate_export_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
    const char *scmd = "key export";

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
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
    bool bds = ods_find_arg(&argc,argv,"ds","ds") != -1;
    (void)ods_find_arg(&argc,argv,"dnskey","dns");
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str,scmd);
        (void)snprintf(buf, ODS_SE_MAXLINE,"unknown arguments\n");
        ods_writen(sockfd, buf, strlen(buf));
        return 1; // errors, but handled
    }
    if (!zone) {
        ods_log_warning("[%s] expected option --zone <zone> for %s command",
                        module_str,scmd);
        (void)snprintf(buf, ODS_SE_MAXLINE,"expected --zone <zone> option\n");
        ods_writen(sockfd, buf, strlen(buf));
        return 1; // errors, but handled
    }
    
    /* perform task immediately */
    perform_keystate_export(sockfd,engine->config,zone,bds?1:0);

    return 1;
}
