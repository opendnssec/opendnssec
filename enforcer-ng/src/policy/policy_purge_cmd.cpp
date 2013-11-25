/*
 * policy_purge_cmd.cpp
 *
 *  Created on: 2013��10��18��
 *      Author: zhangjm
 */
#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/policy_purge_cmd.h"
#include "policy/policy_purge_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "policy_purge_cmd";

void
help_policy_purge_cmd(int sockfd){
	 ods_printf(sockfd,"policy purge     Delete any policies with no zones \n");
}

/* Delete any policies with no zones  */
int
handled_policy_purge_cmd(int sockfd, engine_type* engine, const char *cmd,
                          ssize_t n){
	   const char *scmd =  "policy purge";

	    cmd = ods_check_command(cmd,n,scmd);
	    if (!cmd)
	        return 0; // not handled

	    ods_log_debug("[%s] %s command", module_str, scmd);

	    time_t tstart = time(NULL);

	    perform_policy_purge(sockfd, engine->config);

	    ods_printf(sockfd, "%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
	    return 1;
}
