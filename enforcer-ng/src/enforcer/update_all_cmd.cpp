/*
 * update_all_cmd.cpp
 *
 *  Created on: 2013Äê10ÔÂ11ÈÕ
 *      Author: zhangjm
 */

#include <ctime>
#include <iostream>
#include <cassert>

#include "enforcer/update_all_cmd.h"
#include "enforcer/setup_cmd.h"
#include "enforcer/autostart_cmd.h"
#include "enforcer/update_conf_task.h"

#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"


#include "policy/update_kasp_task.h"
#include "policy/kasp.pb.h"

#include "keystate/update_keyzones_task.h"
#include "keystate/keystate.pb.h"

#include "hsmkey/update_hsmkeys_task.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "hsmkey/hsmkey.pb.h"




static const char *module_str = "update_all_cmd";

void help_update_all_cmd(int sockfd){
	ods_printf(sockfd,
	        "	update all     perform:\n"
	        "                  update kasp - to import kasp.xml\n"
	        "                  update zonelist - to import zonelist.xml\n"
		    "                  update conf - to import conf.xml\n"
	);
}

static void
flush_all_tasks(int sockfd, engine_type* engine)
{
    ods_log_debug("[%s] flushing all tasks...", module_str);
    ods_printf(sockfd,"flushing all tasks...\n");

    ods_log_assert(engine);
    ods_log_assert(engine->taskq);
    lock_basic_lock(&engine->taskq->schedule_lock);
    /* [LOCK] schedule */
    schedule_flush(engine->taskq, TASK_NONE);
    /* [UNLOCK] schedule */
    lock_basic_unlock(&engine->taskq->schedule_lock);
    engine_wakeup_workers(engine);
}

int handled_update_all_cmd(int sockfd, engine_type* engine, const char *cmd,
					  ssize_t n){
		const char *scmd = "update all";
	    cmd = ods_check_command(cmd,n,scmd);
	    if (!cmd)
	        return 0; // not handled

	    ods_log_debug("[%s] %s command", module_str, scmd);

		// check that we are using a compatible protobuf version.
		GOOGLE_PROTOBUF_VERIFY_VERSION;

	    time_t tstart = time(NULL);


		autostart(engine);
		perform_update_conf(engine,cmd,n);
		perform_update_kasp(sockfd, engine->config);
		perform_update_keyzones(sockfd, engine->config);

		perform_update_hsmkeys(sockfd, engine->config, 0 /* automatic */);
		perform_hsmkey_gen(sockfd, engine->config, 0 /* automatic */,
						   engine->config->automatic_keygen_duration);

	    flush_all_tasks(sockfd, engine);

	    ods_printf(sockfd, "%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
	    return 1;
}


