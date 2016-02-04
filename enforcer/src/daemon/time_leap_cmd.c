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

#include "file.h"
#include "duration.h"
#include "log.h"
#include "str.h"
#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "clientpipe.h"
#include "hsmkey/hsm_key_factory.h"

#include "daemon/time_leap_cmd.h"

#define MAX_ARGS 5

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
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	struct tm strtime_struct;
	char strtime[64]; /* at least 26 according to docs plus a long integer */
	char buf[ODS_SE_MAXLINE];
	time_t now = time_now();
	const char *time = NULL;
	time_t time_leap = 0;
	struct tm tm;
	const int NARGV = MAX_ARGS;
	const char *argv[MAX_ARGS];
	int argc, attach, cont;
	task_type* task = NULL, *newtask;
	(void)n; (void)dbconn;

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
			tm.tm_isdst = -1;
			time_leap = mktime(&tm);
			client_printf(sockfd,
				"Using %s parameter value as time to leap to\n", time);
		} else {
			client_printf_err(sockfd, 
				"Time leap: Error - could not convert '%s' to a time. "
				"Format is YYYY-MM-DD-HH:MM:SS \n", time);
			return -1;
		}
	}
	attach = ods_find_arg(&argc,argv,"attach","a") != -1;

	if (argc > 2){
		ods_log_error_and_printf(sockfd, module_str, "unknown arguments");
		return -1;
	}

	ods_log_assert(engine);
	if (!engine->taskq || !engine->taskq->tasks) {
		client_printf(sockfd, "There are no tasks scheduled.\n");
		return 1;
	}

	/* how many tasks */
	now = time_now();
	strftime(strtime, sizeof(strtime), "%c", localtime_r(&now, &strtime_struct));
	client_printf(sockfd, 
		"There are %i tasks scheduled.\nIt is now       %s (%ld seconds since epoch)\n",
		(int) schedule_taskcount(engine->taskq), strtime, (long)now);
	cont = 1;
	while (cont) {
		if (! time)
			time_leap = schedule_time_first(engine->taskq);
		if (time_leap < 0) break;

		set_time_now(time_leap);
		strftime(strtime, sizeof(strtime), "%c", localtime_r(&time_leap, &strtime_struct));

		client_printf(sockfd,  "Leaping to time %s (%ld seconds since epoch)\n", 
			(strtime[0]?strtime:"(null)"), (long)time_leap);
		ods_log_info("Time leap: Leaping to time %s\n", strtime);
		/* Wake up all workers and let them reevaluate wether their
		 tasks need to be executed */
		client_printf(sockfd, "Waking up workers\n");
		engine_wakeup_workers(engine);
		if (!attach)
			break;
		if (!(task = schedule_pop_first_task(engine->taskq)))
			break;
		client_printf(sockfd, "[timeleap] attaching to job %s\n", task_what2str(task->what));
		if (strcmp(task_what2str(task->what),  "enforce") == 0)
			cont = 0;
		task->dbconn = dbconn;
		newtask = task_perform(task);
		ods_log_debug("[timeleap] finished working");
		if (newtask) {
			newtask->dbconn = NULL;
			(void) schedule_task(engine->taskq, newtask); /* TODO unchecked error code */
		}
		hsm_key_factory_generate_all(engine, dbconn, 0);
	}
	return 0;
}


static struct cmd_func_block funcblock = {
	"time leap", &usage, &help, &handles, &run
};

struct cmd_func_block*
time_leap_funcblock(void)
{
	return &funcblock;
}
