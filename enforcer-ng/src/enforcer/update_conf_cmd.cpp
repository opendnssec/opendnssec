/*
 * update_conf_cmd.cpp
 *
 *  Created on: 2013Äê10ÔÂ8ÈÕ
 *      Author: zhangjm
 */

#include "enforcer/update_conf_cmd.h"

#include "hsmkey/update_hsmkeys_task.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "hsmkey/hsmkey.pb.h"
#include "shared/str.h"
#include "shared/file.h"

static const char *module_str = "update_conf_cmd";

void
help_update_conf_cmd(int sockfd)
{
    ods_printf(sockfd,
	   "update conf     import respostories from conf.xml into the enforcer.\n");
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

int
handled_update_conf_cmd(int sockfd, engine_type* engine, const char *cmd,
		ssize_t n)
{
    const char *scmd = "update conf";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);
    time_t tstart = time(NULL);

    perform_update_conf(engine,cmd,n);


    kill(engine->pid, SIGHUP);
    ods_printf(sockfd, "Notifying enforcer of new respositories! \n");


    ods_printf(sockfd,"%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
    return 1;
}


