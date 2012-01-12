#include <ctime>
#include <iostream>
#include <cassert>

#include "keystate/zone_del_cmd.h"
#include "keystate/zone_del_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "zone_del_cmd";

void help_zone_del_cmd(int sockfd)
{
    ods_printf(sockfd,
			   "zone del        delete zones\n"
			   "  --zone <zone> (aka -z) the zone to delete\n"
			   "  --force       (aka -f) additional flag to "
								"indicate you really mean it\n"
			   );
	
}

bool get_arguments(int sockfd, const char *cmd,
				   std::string &out_zone)
{
	char buf[ODS_SE_MAXLINE];
    const char *argv[16];
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
    (void)ods_find_arg_and_param(&argc,argv,"zone","z",&zone);
    bool bforce = ods_find_arg(&argc,argv,"force","f")!=-1;
	
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
    if (!bforce) {
		ods_log_error_and_printf(sockfd,module_str,
								 "expected option --force");
        return false;
    }
	return true;
}

int handled_zone_del_cmd(int sockfd, engine_type* engine, const char *cmd, 
						  ssize_t n)
{
    const char *scmd =  "zone del";
    
    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled
    
    ods_log_debug("[%s] %s command", module_str, scmd);

	std::string zone;
	if (!get_arguments(sockfd,cmd,zone))
		return 1;

    time_t tstart = time(NULL);

    perform_zone_del(sockfd,engine->config, zone.c_str());

    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    return 1;
}
