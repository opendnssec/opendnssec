#include <ctime>
#include <iostream>
#include <cassert>

#include "keystate/keystate_rollover_cmd.h"
#include "keystate/keystate_rollover_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
#include "enforcer/enforce_task.h"

#include "keystate/keystate.pb.h"

#include <algorithm>

static const char *module_str = "keystate_rollover_cmd";

void help_keystate_rollover_cmd(int sockfd)
{
    ods_printf(sockfd,
        "key rollover    rollover the key\n"
        "  --zone <zone> (aka -z) rollover key with id <id>.\n"
        "  [--keytype <keytype>]\n"
        "                (aka -t) type of the key KSK or ZSK (default all).\n"
        );
}

int handled_keystate_rollover_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
    const char *scmd = "key rollover";

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
    
    const char *zone = NULL;
    const char *keytype = NULL;
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
    (void)ods_find_arg_and_param(&argc,argv,"keytype","t",&keytype);
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str,scmd);
        ods_printf(sockfd,"unknown arguments\n");
        return 1; // errors, but handled
    }
    if (!zone) {
        ods_log_warning("[%s] expected option --zone <zone> for %s command",
                        module_str,scmd);
        ods_printf(sockfd,"expected --zone <zone> option\n");
        return 1; // errors, but handled
    }

    int nkeytype = 0;
    if (keytype) {
        std::string kt(keytype);
        int (*fp)(int) = toupper;
        std::transform(kt.begin(),kt.end(),kt.begin(),fp);
        if (kt == "KSK") {
            nkeytype = (int)::ods::keystate::KSK;
        } else {
            if (kt == "ZSK") {
                nkeytype = (int)::ods::keystate::ZSK;
            } else {
                if (kt == "CSK") {
                    nkeytype = (int)::ods::keystate::CSK;
                } else {
                    ods_log_warning("[%s] given keytype \"%s\" invalid",
                                    module_str,keytype);
                    ods_printf(sockfd,"given keytype \"%s\" invalid\n",keytype);
                    return 1; // errors, but handled
                }
            }
        }
    }
    
    time_t tstart = time(NULL);

    perform_keystate_rollover(sockfd,engine->config,zone,nkeytype);

    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);

    flush_enforce_task(engine);

    return 1;
}
