#include <ctime>
#include <iostream>
#include <cassert>

#include "keystate/keystate_ds_gone_cmd.h"
#include "keystate/keystate_ds_gone_task.h"
#include "enforcer/enforce_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "keystate_ds_gone_cmd";

/**
 * Print help for the 'key list' command
 *
 */
void help_keystate_ds_gone_cmd(int sockfd)
{
	ods_printf(sockfd,
		"key ds-gone     list KSK keys that were retracted from the parent.\n"
        "  --zone <zone> (aka -z) set KSK key to unsubmitted for zone <zone>\n"
        "  --id <id>     (aka -k) with id <id>.\n"
        "  --keytag <keytag>\n"
        "                (aka -x) with keytag <keytag>.\n"
        );
}

int handled_keystate_ds_gone_cmd(int sockfd, engine_type* engine,
								 const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
    const char *scmd = "key ds-gone";
    
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
    const char *id = NULL;
    const char *keytag = NULL;
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
    (void)ods_find_arg_and_param(&argc,argv,"id","k",&id);
    (void)ods_find_arg_and_param(&argc,argv,"keytag","x",&keytag);

    // Check for unknown parameters on the command line
    if (argc) {
        ods_log_warning("[%s] unknown arguments for %s command",
                        module_str,scmd);
        ods_printf(sockfd,"unknown arguments\n");
        return 1; // errors, but handled
    }

    // Check for too many parameters on the command line
    if (argc > NARGV) {
        ods_log_warning("[%s] too many arguments for %s command",
                        module_str,scmd);
        ods_printf(sockfd,"too many arguments\n");
        return 1; // errors, but handled
    }

    // Either no option or combi of zone & id or zone & keytag needs to be 
    // present. But not both id and keytag
    uint16_t nkeytag = 0;
    if (zone || id || keytag) {
        if (!zone) {
            ods_log_warning("[%s] expected option --zone <zone> for %s command",
                            module_str,scmd);
            ods_printf(sockfd,"expected --zone <zone> option\n");
            return 1; // errors, but handled
        }
        if (!id && !keytag) {
            ods_log_warning("[%s] expected option --id <id> or "
                            "--keytag <keytag> for %s command",
                            module_str,scmd);
            ods_printf(sockfd,"expected --id <id> or "
                           "--keytag <keytag> option\n");
            return 1; // errors, but handled
        } else {
            if (id && keytag) {
                ods_log_warning("[%s] both --id <id> and --keytag <keytag> given, "
                                "please only specify one for %s command",
                                module_str,scmd);
                ods_printf(sockfd,
                               "both --id <id> and --keytag <keytag> given, "
                               "please only specify one\n");
                return 1; // errors, but handled
            }
        }
        if (keytag) {
            int kt = atoi(keytag);
            if (kt<=0 || kt>=65536) {
                ods_log_warning("[%s] value \"%s\" for --keytag is invalid",
                                module_str,keytag);
                ods_printf(sockfd,
                               "value \"%s\" for --keytag is invalid\n",
                               keytag);
                return 1; // errors, but handled
            }
            nkeytag = (uint16_t )kt;
        }
    }
    
    time_t tstart = time(NULL);

    perform_keystate_ds_gone(sockfd,engine->config,zone,id,nkeytag);
    
	ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);

    flush_enforce_task(engine);
    return 1;
}
