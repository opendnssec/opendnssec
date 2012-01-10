#include <ctime>
#include <iostream>
#include <cassert>

#include "keystate/zone_add_cmd.h"
#include "keystate/zone_add_task.h"
#include "enforcer/enforce_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "shared/log.h"
#include "daemon/engine.h"

static const char *module_str = "zone_add_cmd";

void
help_zone_add_cmd(int sockfd)
{
    ods_printf(sockfd,
			   "zone add        add a new zone to the enforcer\n"
			   "  --zone <zone>	(aka -z) name of the zone\n"
			   "  --policy <policy>\n"
			   "                (aka -p) name of the policy\n"
			   "  --signconf <path>\n"
			   "                (aka -s) signer configuration path\n"
        );
}

bool get_arguments(int sockfd, const char *cmd,
				   std::string &out_zone,
				   std::string &out_policy,
				   std::string &out_signconf)
{
	char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
    
    // Use buf as an intermediate buffer for the command.
    strncpy(buf,cmd,sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    
    // separate the arguments
    argc = ods_str_explode(buf,NARGV,argv);
    if (argc > NARGV) {
        ods_log_error_and_printf(sockfd,module_str,"too many arguments");
        return false;
    }
    
    const char *zone = NULL;
    const char *policy = NULL;
	const char *signconf = NULL;
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
    (void)ods_find_arg_and_param(&argc,argv,"policy","p",&policy);
    (void)ods_find_arg_and_param(&argc,argv,"signconf","s",&signconf);
    if (argc) {
		ods_log_error_and_printf(sockfd,module_str,"unknown arguments");
        return false;
    }
    if (!zone) {
		ods_log_error_and_printf(sockfd,module_str,
								 "expected option --zone <zone>");
        return false;
    }
	out_zone = zone;
    if (!policy) {
		ods_log_error_and_printf(sockfd,module_str,
								 "expected option --policy <policy>");
        return false;
    }
	out_policy = policy;
    if (!signconf) {
		ods_log_error_and_printf(sockfd,module_str,
								 "expected option --signconf <path>");
        return false;
    }
	out_signconf = signconf;

	return true;
}

int
handled_zone_add_cmd(int sockfd, engine_type* engine, const char *cmd,
					 ssize_t n)
{
    const char *scmd = "zone add";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

	std::string zone,policy,signconf;
    if (!get_arguments(sockfd, cmd, zone,policy, signconf))
		return 1;
	
    time_t tstart = time(NULL);
	
    perform_zone_add(sockfd,engine->config,
					 zone.c_str(),
					 policy.c_str(),
					 signconf.c_str());
	
    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);

    flush_enforce_task(engine);
    return 1;
}
