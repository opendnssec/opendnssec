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

#include <pthread.h>
#include <time.h>

#include "file.h"
#include "log.h"
#include "str.h"
#include "duration.h"
#include "scheduler/schedule.h"
#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "clientpipe.h"
#include "clientpipe.h"

#include "daemon/queue_cmd.h"

static const char *module_str = "queue_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"queue\n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"queue shows all scheduled tasks with their time of earliest executions,\n"
		"as well as all tasks currently being processed."
		"\n\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, queue_funcblock()->cmdname)?1:0;
}

/**
 * Convert task to string.
 * buf must be at least ODS_SE_MAXLINE long.
 */
static void
task2str(task_t* task, char* buf, time_t now)
{
	char ctimebuf[32]; /* at least 26 according to docs */
	time_t time;
	char* strtime = NULL;
	char* strtask = NULL;

	assert(task);

	time = (task->due_date < now)?now:task->due_date;
	strtime = ctime_r(&time, ctimebuf);
	/* We need cut off the newline */
	if (strtime && strlen(strtime) > 0) {
		strtime[strlen(strtime)-1] = 0;
	}
	(void)snprintf(buf, ODS_SE_MAXLINE, "On %s I will [%s] %s\n",
		strtime?strtime:"(null)", task->type, task->owner);
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	struct tm strtime_struct;
	char strtime[64]; /* at least 26 according to docs plus a long integer */
	char buf[ODS_SE_MAXLINE];
	size_t i = 0, count;
	time_t now;
	time_t nextFireTime;
	ldns_rbnode_t* node = LDNS_RBTREE_NULL;
	task_t* task = NULL;
	(void)cmd; (void)n; (void)dbconn;
	int num_waiting;

	ods_log_debug("[%s] list tasks command", module_str);

	ods_log_assert(engine);
	if (!engine->taskq || !engine->taskq->tasks) {
		client_printf(sockfd, "There are no tasks scheduled.\n");
		return 0;
	}

	num_waiting = schedule_get_num_waiting(engine->taskq);
	if (num_waiting == engine->config->num_worker_threads) {
		client_printf(sockfd, "All worker threads idle.\n");
	}

	/* how many tasks */
	count = schedule_taskcount(engine->taskq);
	client_printf(sockfd, "There %s %i %s scheduled.\n",
		(count==1)?"is":"are", (int) count, (count==1)?"task":"tasks");
	now = time_now();
	strftime(strtime, sizeof(strtime), "%c", localtime_r(&now, &strtime_struct));
	client_printf(sockfd, "It is now %s (%ld seconds since epoch)\n", (strtime[0]?strtime:"(null)"), (long)now);
	nextFireTime = schedule_time_first(engine->taskq);
	if (nextFireTime > now) {
			strftime(strtime, sizeof(strtime), "%c", localtime_r(&nextFireTime, &strtime_struct));
			client_printf(sockfd, "Next task scheduled %s (%ld seconds since epoch)\n", strtime, (long)nextFireTime);
	} else if (nextFireTime >= 0) {
			client_printf(sockfd, "Next task scheduled immediately\n");
	} /* else: no tasks scheduled at all. */
	
	/* list tasks */
	pthread_mutex_lock(&engine->taskq->schedule_lock);
		node = ldns_rbtree_first(engine->taskq->tasks);
		while (node && node != LDNS_RBTREE_NULL) {
			task = (task_t*) node->data;
			memset(buf, 0, ODS_SE_MAXLINE);
			task2str(task, buf, now);
			client_printf(sockfd, "%s", buf);
			node = ldns_rbtree_next(node);
		}
	pthread_mutex_unlock(&engine->taskq->schedule_lock);
	return 0;
}

static struct cmd_func_block funcblock = {
	"queue", &usage, &help, &handles, &run
};

struct cmd_func_block*
queue_funcblock(void)
{
	return &funcblock;
}

static void
usage_flush(int sockfd)
{
	client_printf(sockfd,
		"flush\n"
	);
}

static void
help_flush(int sockfd)
{
	client_printf(sockfd,
		"Execute all scheduled tasks immediately.\n\n");
}

static int
handles_flush(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, flush_funcblock()->cmdname)?1:0;
}

static int
run_flush(int sockfd, engine_type *engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	(void)cmd; (void)n;  (void)dbconn;
	ods_log_debug("[%s] flush tasks command", module_str);
	ods_log_assert(engine);
	ods_log_assert(engine->taskq);

	schedule_flush(engine->taskq);

	client_printf(sockfd, "All tasks scheduled immediately.\n");
	ods_log_verbose("[cmdhandler] all tasks scheduled immediately");
	return 0;
}

static struct cmd_func_block funcblock_flush = {
	"flush", &usage_flush, &help_flush, &handles_flush, &run_flush
};

struct cmd_func_block*
flush_funcblock(void)
{
	return &funcblock_flush;
}
