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
#include "shared/str.h"
#include "shared/duration.h"
#include "daemon/cmdhandler.h"
#include "daemon/engine.h"

#include "daemon/queue_cmd.h"

static const char *module_str = "queue_cmd";

static void
usage(int sockfd)
{
	ods_printf(sockfd,
		"queue                  Show the current task queue.\n"
	);
}

static void
help(int sockfd)
{
	ods_printf(sockfd,
		"queue shows all scheduled tasks with their time of earliest "
		"execution. As well as all tasks currently being processed."
		"\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, queue_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
	char* strtime = NULL;
	char ctimebuf[32]; /* at least 26 according to docs */
	char buf[ODS_SE_MAXLINE];
	size_t i = 0;
	time_t now = 0;
	ldns_rbnode_t* node = LDNS_RBTREE_NULL;
	task_type* task = NULL;
	(void)cmd; (void)n;

	ods_log_debug("[%s] list tasks command", module_str);

	ods_log_assert(engine);
	if (!engine->taskq || !engine->taskq->tasks) {
		(void)snprintf(buf, ODS_SE_MAXLINE, "There are no tasks scheduled.\n");
		ods_writen(sockfd, buf, strlen(buf));
		return 0;
	}
	
	lock_basic_lock(&engine->taskq->schedule_lock);
	/* [LOCK] schedule */

	/* current work */
	for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
		task = engine->workers[i]->task;
		if (task) {
			(void)snprintf(buf, ODS_SE_MAXLINE, "Working with [%s] %s\n",
				task_what2str(task->what), task_who2str(task->who));
			ods_writen(sockfd, buf, strlen(buf));
		}
	}

	/* how many tasks */
	now = time_now();
	strtime = ctime_r(&now,ctimebuf);
	(void)snprintf(buf, ODS_SE_MAXLINE, 
				   "There are %i tasks scheduled.\nIt is now %s",
				   (int) engine->taskq->tasks->count,
				   strtime?strtime:"(null)\n");
	ods_writen(sockfd, buf, strlen(buf));
	
	/* list tasks */
	node = ldns_rbtree_first(engine->taskq->tasks);
	while (node && node != LDNS_RBTREE_NULL) {
		task = (task_type*) node->data;
		for (i=0; i < ODS_SE_MAXLINE; i++) {
			buf[i] = 0;
		}
		(void)task2str(task, (char*) &buf[0]);
		ods_writen(sockfd, buf, strlen(buf));
		node = ldns_rbtree_next(node);
	}
	/* [UNLOCK] schedule */
	lock_basic_unlock(&engine->taskq->schedule_lock);
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
	ods_printf(sockfd,
		"flush                  Execute all scheduled tasks immediately.\n"
	);
}

static int
handles_flush(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, flush_funcblock()->cmdname)?1:0;
}

static int
run_flush(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
	(void)cmd; (void)n;
	ods_log_debug("[%s] flush tasks command", module_str);
	ods_log_assert(engine);
	ods_log_assert(engine->taskq);

	lock_basic_lock(&engine->taskq->schedule_lock);
	/* [LOCK] schedule */
		schedule_flush(engine->taskq, TASK_NONE);
	/* [UNLOCK] schedule */
	lock_basic_unlock(&engine->taskq->schedule_lock);

	engine_wakeup_workers(engine);

	ods_printf(sockfd, "All tasks scheduled immediately.\n");
	ods_log_verbose("[cmdhandler] all tasks scheduled immediately");
	return 0;
}

static struct cmd_func_block funcblock_flush = {
	"flush", &usage_flush, NULL, &handles_flush, &run_flush
};

struct cmd_func_block*
flush_funcblock(void)
{
	return &funcblock_flush;
}
