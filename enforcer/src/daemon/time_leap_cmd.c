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

#include <getopt.h>
#include "config.h"

#include "file.h"
#include "duration.h"
#include "log.h"
#include "str.h"
#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
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
		"time leap\n"
		"	--time <time>				aka -t \n"
		"	--attach				aka -a\n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"*WARNING* time leap is a debugging/testing tool, it should NEVER be used\n" 
		"in production! Without arguments the daemon inspects the first task in the\n" 
		"schedule and sets its internal time to the time of the task. This allows for\n"
		"a quick replay of a test scenario. With the --time or -t switch the daemon\n"
		"sets its time to the argument given as: \"YYYY-MM-DD-HH:MM:SS\"."
		"\n"
		"\nOptions:\n"
		"time		leap to this exact time\n"
		"attach		Perform 1 task and stay attached, use only when workerthreads=0\n\n"
	);
}

static int
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
	db_connection_t* dbconn;
	struct tm strtime_struct;
	char strtime[64]; /* at least 26 according to docs plus a long integer */
	char buf[ODS_SE_MAXLINE];
	time_t now = time_now();
	const char *time = NULL;
	time_t time_leap = 0;
	struct tm tm;
	const int NARGV = MAX_ARGS;
	const char *argv[MAX_ARGS];
        int taskcount;
	int argc = 0, attach = 0;
	int long_index = 0, opt = 0;
	int processed_enforce;
	task_type* task = NULL;
        engine_type* engine = getglobalcontext(context);

	static struct option long_options[] = {
		{"time", required_argument, 0, 't'},
		{"attach", no_argument, 0, 'a'},
		{0, 0, 0, 0}
	};

	ods_log_debug("[%s] %s command", module_str, time_leap_funcblock.cmdname);

	strncpy(buf, cmd, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';

	argc = ods_str_explode(buf, NARGV, argv);
	if (argc == -1) {
		ods_log_error_and_printf(sockfd, module_str, "too many arguments");
		return -1;
	}

	optind = 0;
	while ((opt = getopt_long(argc, (char* const*)argv, "t:a", long_options, &long_index)) != -1) {
		switch (opt) {
			case 't':
				time = optarg;
				break;
			case 'a':
				attach = 1;
				break;
			default:
				client_printf_err(sockfd, "unknown arguments\n");
				ods_log_error("[%s] unknown arguments for %s command",
						module_str, time_leap_funcblock.cmdname);
				return -1;
		}
	}

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

	ods_log_assert(engine);
	if (!engine->taskq || !engine->taskq->tasks) {
		client_printf(sockfd, "There are no tasks scheduled.\n");
		return 1;
	}

	schedule_info(engine->taskq, &time_leap, NULL, &taskcount);
	now = time_now();
	strftime(strtime, sizeof(strtime), "%c", localtime_r(&now, &strtime_struct));
	client_printf(sockfd, 
		"There are %i tasks scheduled.\nIt is now       %s (%ld seconds since epoch)\n",
		taskcount, strtime, (long)now);

    if (!time) schedule_info(engine->taskq, &time_leap, NULL, NULL);
    if (time_leap == -1) {
        client_printf(sockfd, "No tasks in queue. Not able to leap.\n");
        return 0;
    }

    if (!attach) {
        set_time_now(time_leap);
		strftime(strtime, sizeof(strtime), "%c", localtime_r(&time_leap, &strtime_struct));
		client_printf(sockfd,  "Leaping to time %s (%ld seconds since epoch)\n",
			(strtime[0]?strtime:"(null)"), (long)time_leap);
		ods_log_info("Time leap: Leaping to time %s\n", strtime);
		/* Wake up all workers and let them reevaluate wether their
		 tasks need to be executed */
		client_printf(sockfd, "Waking up workers\n");
		engine_wakeup_workers(engine);
        return 0;
    }

    if (!(dbconn = get_database_connection(engine))) {
        client_printf_err(sockfd, "Failed to open DB connection.\n");
        client_exit(sockfd, 1);
        return -1;
    }
    /* Keep looping until an enforce task is found, then loop but don't advance time */
    processed_enforce = 0;
	while (1) {
        /*if time is set never advance time but only consume all task <= time*/
		if (!time) {
            schedule_info(engine->taskq, &time_leap, NULL, NULL);
            if (time_leap >= 0 && time_leap < time_now()) time_leap = time_now();
            if (processed_enforce && time_leap > time_now()) break;
        }
		if (time_leap == -1) {
			client_printf(sockfd, "No tasks in queue. Not able to leap.\n");
			break;
		}

		set_time_now(time_leap);
		strftime(strtime, sizeof(strtime), "%c", localtime_r(&time_leap, &strtime_struct));
		client_printf(sockfd,  "Leaping to time %s (%ld seconds since epoch)\n", 
			(strtime[0]?strtime:"(null)"), (long)time_leap);
		ods_log_info("Time leap: Leaping to time %s\n", strtime);
		if (!(task = schedule_pop_first_task(engine->taskq)))
			break;
		if (schedule_task_istype(task,  TASK_TYPE_ENFORCE))
			processed_enforce = 1;
		task_perform(engine->taskq, task, dbconn);
		ods_log_debug("[timeleap] finished working");
	}
    db_connection_free(dbconn);
	return 0;
}


struct cmd_func_block time_leap_funcblock = {
	"time leap", &usage, &help, NULL, &run
};
