/*
 * Copyright (c) 2014 NLNet Labs
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "config.h"

#include "shared/file.h"
#include "shared/duration.h"
#include "shared/str.h"
#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "daemon/clientpipe.h"

#include "daemon/time_leap_cmd.h"

#define MAX_ARGS 16

static const char *module_str = "time_leap_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"time leap              Simulate progression of time by leaping to the time of\n"
		"                       the earliest scheduled task.\n"
		"    --time <time>      -t for short, leap to this exact time.\n"
		"    --attach           -a for short. Perform 1 task and stay "
			"attached, use only when workerthreads=0.\n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"*WARNING* time leap is a debugging/testing tool, it should "
		"NEVER be used in production! Without arguments the daemon "
		"inspects the first task in the schedule and sets its internal "
		"time to the time of the task. This allows for a quick replay "
		"of a test scenario. With the --time or -t switch the daemon "
		"sets its time to the argument given as: \"YYYY-MM-DD-HH:MM:SS\"."
		"\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, time_leap_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
	int bShouldLeap = 0;
	char* strtime = NULL;
	char ctimebuf[32]; /* at least 26 according to docs */
	char buf[ODS_SE_MAXLINE];
	time_t now = time_now();
	task_type* task = NULL;
	const char *time = NULL;
	time_t time_leap = 0;
	struct tm tm;
	const int NARGV = MAX_ARGS;
	const char *argv[MAX_ARGS];
	int argc, attach;
	(void)n;

	ods_log_debug("[%s] %s command", module_str, time_leap_funcblock()->cmdname);

	strncpy(buf, cmd, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	argc = ods_str_explode(buf, NARGV, argv);
	if (argc > NARGV) {
		ods_log_error_and_printf(sockfd, module_str, "too many arguments");
		return -1;
	}
	(void)ods_find_arg_and_param(&argc, argv, "time", "t", &time);
	if (time) {
		if (strptime(time, "%Y-%m-%d-%H:%M:%S", &tm)) {
			time_leap = mktime_from_utc(&tm);
			client_printf(sockfd,
				"Using %s parameter value as time to leap to\n", time);
		} else {
			client_printf(sockfd, 
				"Time leap: Error - could not convert '%s' to a time. "
				"Format is YYYY-MM-DD-HH:MM:SS \n", time);
			return -1;
		}
	}
	attach = ods_find_arg(&argc,argv,"attach","a") != -1;

	ods_log_assert(engine);
	if (!engine->taskq || !engine->taskq->tasks) {
		client_printf(sockfd, "There are no tasks scheduled.\n");
		return 1;
	}

	lock_basic_lock(&engine->taskq->schedule_lock);
	/* [LOCK] schedule */

	/* how many tasks */
	now = time_now();
	strtime = ctime_r(&now,ctimebuf);
	client_printf(sockfd, 
		"There are %i tasks scheduled.\nIt is now       %s",
		(int) engine->taskq->tasks->count,
		strtime?strtime:"(null)\n");

	/* Get first task in schedule, this one also features the earliest wake-up
	   time of all tasks in the schedule. */
	task = schedule_get_first_task(engine->taskq);

	if (task) {
		if (!task->flush || attach) {
			/*Use the parameter vaule, or if not given use the time of the first task*/
			if (!time_leap)
				time_leap = task->when;

			set_time_now(time_leap);
			strtime = ctime_r(&time_leap,ctimebuf);
			if (strtime)
				strtime[strlen(strtime)-1] = '\0'; /* strip trailing \n */

			client_printf(sockfd,  "Leaping to time %s\n", 
				strtime?strtime:"(null)");
			ods_log_info("Time leap: Leaping to time %s\n",
				 strtime?strtime:"(null)");

			bShouldLeap = 1;
		} else {
			client_printf(sockfd, 
				"Already flushing tasks, unable to time leap\n");
		}
	} else {
		client_printf(sockfd, "Task queue is empty, unable to time leap\n");
	}

	/* [UNLOCK] schedule */
	lock_basic_unlock(&engine->taskq->schedule_lock);

	if (bShouldLeap) {
		/* Wake up all workers and let them reevaluate wether their
		 tasks need to be executed */
		client_printf(sockfd, "Waking up workers\n");
		engine_wakeup_workers(engine);
		if (attach) {
			task = schedule_pop_task(engine->taskq);
			if (task) {
				task = task_perform(task);
				ods_log_debug("[timeleap] finished working");
				if (task)
					(void) lock_and_schedule_task(engine->taskq, task, 1);
			}
		}
	}
	return !bShouldLeap;
}


static struct cmd_func_block funcblock = {
	"time leap", &usage, &help, &handles, &run
};

struct cmd_func_block*
time_leap_funcblock(void)
{
	return &funcblock;
}
