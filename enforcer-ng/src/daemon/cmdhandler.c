/*
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

/**
 * Command handler.
 *
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <ldns/ldns.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <unistd.h>
/* According to earlier standards: select() sys/time.h sys/types.h unistd.h */
#include <sys/time.h>
#include <sys/types.h>

#include "daemon/engine.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/locks.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/duration.h"
#include "shared/str.h"

/* commands to handle */
#include "policy/policy_resalt_cmd.h"
#include "policy/policy_list_cmd.h"
#include "daemon/help_cmd.h"
#include "enforcer/setup_cmd.h"
#include "enforcer/update_repositorylist_cmd.h"
#include "enforcer/update_all_cmd.h"
#include "policy/update_kasp_cmd.h"
#include "policy/policy_import_cmd.h"
#include "policy/policy_export_cmd.h"
#include "policy/policy_purge_cmd.h"
#include "keystate/update_keyzones_cmd.h"
#include "keystate/zone_list_cmd.h"
#include "keystate/zone_del_cmd.h"
#include "keystate/zone_add_cmd.h"
#include "keystate/zonelist_cmd.h"

#include "daemon/cmdhandler.h"

#define SE_CMDH_CMDLEN 7

#ifndef SUN_LEN
#define SUN_LEN(su) (sizeof(*(su))-sizeof((su)->sun_path)+strlen((su)->sun_path))
#endif

static int count = 0;
static char* module_str = "cmdhandler";

/**
 * Handle the 'queue' command.
 *
 */
int handled_queue_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    char* strtime = NULL;
    char ctimebuf[32]; /* at least 26 according to docs */
    char buf[ODS_SE_MAXLINE];
    size_t i = 0;
    time_t now = 0;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    task_type* task = NULL;

    if (n != 5 || strncmp(cmd, "queue", n) != 0) return 0;
    ods_log_debug("[%s] list tasks command", module_str);

    ods_log_assert(engine);
    if (!engine->taskq || !engine->taskq->tasks) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "There are no tasks scheduled.\n");
        ods_writen(sockfd, buf, strlen(buf));
        return 1;
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
                   "\nThere are %i tasks scheduled.\nIt is now %s",
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
    return 1;
}


/**
 * Handle the 'time leap' command.
 *
 */
int handled_time_leap_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    int bShouldLeap = 0;
    char* strtime = NULL;
    char ctimebuf[32]; /* at least 26 according to docs */
    char buf[ODS_SE_MAXLINE];
    time_t now = time_now();
    task_type* task = NULL;
    const char *scmd = "time leap";
    ssize_t ncmd = strlen(scmd);
    const char *time = NULL;
	time_t time_leap = 0;
	struct tm tm;	
    const char *argv[16];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;	
    
    if (n < ncmd || strncmp(cmd, scmd, ncmd) != 0) return 0;
    ods_log_debug("[%s] %s command", module_str, scmd);

    strncpy(buf,cmd,sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    argc = ods_str_explode(buf,NARGV,argv);
    if (argc > NARGV) {
        ods_log_error_and_printf(sockfd,module_str,"too many arguments");
        return false;
    }   
    (void)ods_find_arg_and_param(&argc,argv,"time","t",&time);
    if (time) {
        if (strptime(time, "%Y-%m-%d-%H:%M:%S", &tm)) {	
            time_leap = mktime_from_utc(&tm);
		    (void)snprintf(buf, ODS_SE_MAXLINE,"Using %s parameter value as time to leap to\n", 
		                 time);	
		   	ods_writen(sockfd, buf, strlen(buf));
		}	
		else {
	        (void)snprintf(buf, ODS_SE_MAXLINE,
	                       "Time leap: Error - could not convert '%s' to a time. "
						   "Format is YYYY-MM-DD-HH:MM:SS \n", time);
	        ods_writen(sockfd, buf, strlen(buf));	
			return 1;				
		}		
	}
    
    ods_log_assert(engine);
    if (!engine->taskq || !engine->taskq->tasks) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "There are no tasks scheduled.\n");
        ods_writen(sockfd, buf, strlen(buf));
        return 1;
    }
    
    lock_basic_lock(&engine->taskq->schedule_lock);
    /* [LOCK] schedule */
    
    /* how many tasks */
    now = time_now();
    strtime = ctime_r(&now,ctimebuf);
    (void)snprintf(buf, ODS_SE_MAXLINE, 
                   "There are %i tasks scheduled.\nIt is now       %s",
                   (int) engine->taskq->tasks->count,
                   strtime?strtime:"(null)\n");
    ods_writen(sockfd, buf, strlen(buf));
    
    /* Get first task in schedule, this one also features the earliest wake-up 
       time of all tasks in the schedule. */
    task = schedule_get_first_task(engine->taskq);

    if (task) {
        if (!task->flush) {
			/*Use the parameter vaule, or if not given use the time of the first task*/
			if (!time_leap) 
				time_leap = task->when;
					
	        set_time_now(time_leap);
		    strtime = ctime_r(&time_leap,ctimebuf);		
            if (strtime)
                strtime[strlen(strtime)-1] = '\0'; /* strip trailing \n */

            (void)snprintf(buf, ODS_SE_MAXLINE, "Leaping to time %s\n",
                           strtime?strtime:"(null)");
		    ods_log_info("Time leap: Leaping to time %s\n", 
		                 strtime?strtime:"(null)");
            ods_writen(sockfd, buf, strlen(buf));
            
            bShouldLeap = 1;
        } else {
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "Already flushing tasks, unable to time leap\n");
            ods_writen(sockfd, buf, strlen(buf));
        }
    } else {
        (void)snprintf(buf, ODS_SE_MAXLINE,
                       "Task queue is empty, unable to time leap\n");
        ods_writen(sockfd, buf, strlen(buf));
    }

    /* [UNLOCK] schedule */
    lock_basic_unlock(&engine->taskq->schedule_lock);

    if (bShouldLeap) {
        /* Wake up all workers and let them reevaluate wether their
         tasks need to be executed */
        (void)snprintf(buf, ODS_SE_MAXLINE, "Waking up workers\n");
        ods_writen(sockfd, buf, strlen(buf));
        engine_wakeup_workers(engine);
    }
    return 1;
}


/**
 * Handle the 'flush' command.
 *
 */
int handled_flush_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    if (n != 5 || strncmp(cmd, "flush", n) != 0) return 0;
    ods_log_debug("[%s] flush tasks command", module_str);
    ods_log_assert(engine);
    ods_log_assert(engine->taskq);
    
    lock_basic_lock(&engine->taskq->schedule_lock);
    /* [LOCK] schedule */
    schedule_flush(engine->taskq, TASK_NONE);
    /* [UNLOCK] schedule */
    lock_basic_unlock(&engine->taskq->schedule_lock);
    
    engine_wakeup_workers(engine);
    
    (void)snprintf(buf, ODS_SE_MAXLINE, "All tasks scheduled immediately.\n");
    ods_writen(sockfd, buf, strlen(buf));
    ods_log_verbose("[%s] all tasks scheduled immediately", module_str);
    return 1;
}


/**
 * Handle the 'running' command.
 *
 */
int handled_running_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    (void) engine;
    if (n != 7 || strncmp(cmd, "running", n) != 0) return 0;
    ods_log_debug("[%s] running command", module_str);
    (void)snprintf(buf, ODS_SE_MAXLINE, "Engine running.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}

/**
 * Handle the 'reload' command.
 *
 */
int handled_reload_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    if (n != 6 || strncmp(cmd, "reload", n) != 0) return 0;
    ods_log_debug("[%s] reload command", module_str);

    ods_log_assert(engine);

    engine->need_to_reload = 1;

    lock_basic_lock(&engine->signal_lock);
    /* [LOCK] signal */
    lock_basic_alarm(&engine->signal_cond);
    /* [UNLOCK] signal */
    lock_basic_unlock(&engine->signal_lock);

    (void)snprintf(buf, ODS_SE_MAXLINE, "Reloading engine.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}

/**
 * Handle the 'stop' command.
 *
 */
int handled_stop_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    if (n != 4 || strncmp(cmd, "stop", n) != 0) return 0;
    ods_log_debug("[%s] stop command", module_str);
    
    ods_log_assert(engine);
    
    engine->need_to_exit = 1;
    
    lock_basic_lock(&engine->signal_lock);
    /* [LOCK] signal */
    lock_basic_alarm(&engine->signal_cond);
    /* [UNLOCK] signal */
    lock_basic_unlock(&engine->signal_lock);
    
    (void)snprintf(buf, ODS_SE_MAXLINE, ODS_SE_STOP_RESPONSE);
    ods_writen(sockfd, buf, strlen(buf));
    return 2;
}


/**
 * Handle the 'start' command.
 *
 */
int handled_start_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    if (n != 5 || strncmp(cmd, "start", n) != 0) return 0;
    ods_log_debug("[%s] start command", module_str);
    
    ods_log_assert(engine);
    
    (void)snprintf(buf, ODS_SE_MAXLINE-2, ODS_EN_START_RESPONSE);
    (void)snprintf(buf+strlen(buf), 2, "\n "); /*last char is stripped*/
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'verbosity' command.
 *
 */
int handled_verbosity_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    if (n < 9 || strncmp(cmd, "verbosity", 9) != 0) return 0;
    ods_log_debug("[%s] verbosity command", module_str);
    if (cmd[9] == '\0') {
        char buf[ODS_SE_MAXLINE];
        (void)snprintf(buf, ODS_SE_MAXLINE, "Error: verbosity command missing "
                                            "an argument (verbosity level).\n");
        ods_writen(sockfd, buf, strlen(buf));
    } else if (cmd[9] != ' ') {
        return 0; /* no match */
    } else {
        int val = atoi(&cmd[10]);
        char buf[ODS_SE_MAXLINE];
        ods_log_assert(engine);
        ods_log_assert(engine->config);
        ods_log_init(engine->config->log_filename,
                     engine->config->use_syslog, val);
        (void)snprintf(buf, ODS_SE_MAXLINE, "Verbosity level set to %i.\n", val);
        ods_writen(sockfd, buf, strlen(buf));
    }
    return 1;
}

typedef struct cmd_func_block* (*fbgetfunctype)(void);

static fbgetfunctype*
cmd_funcs_avail(void)
{
    static struct cmd_func_block* (*fb[])(void) = {
        &resalt_funcblock,
        &setup_funcblock,
        &help_funcblock,
        &update_repositorylist_funcblock,
        &update_all_funcblock,
        &update_kasp_funcblock,
        &update_keyzones_funcblock,
        &policy_list_funcblock,
        &policy_import_funcblock,
        &policy_export_funcblock,
        &policy_purge_funcblock,
        &zone_list_funcblock,
        &zone_add_funcblock,
        &zone_del_funcblock,
        &zonelist_export_funcblock,
        &zonelist_import_funcblock,
        NULL
    };
    return fb;
}

void
cmdhandler_get_usage(int sockfd)
{
    fbgetfunctype* fb = cmd_funcs_avail();
    int cmd_iter = 0;
    while (fb[cmd_iter]) {
        (*fb[cmd_iter])()->usage(sockfd);
        cmd_iter++;
    }
}

struct cmd_func_block*
get_funcblock(const char *cmd, ssize_t n)
{
    fbgetfunctype* fb = cmd_funcs_avail();
    int cmd_iter = 0;
    while (fb[cmd_iter]) {
        if (fb[cmd_iter]()->handles(cmd, n))
            return fb[cmd_iter]();
        cmd_iter++;
    }
    return NULL;
}

/**
 * Handle unknown command.
 *
 */
static int
handled_unknown_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    (void) n;
    (void) engine;

    ods_log_debug("[%s] unknown command", module_str);
    (void)snprintf(buf, ODS_SE_MAXLINE, "Unknown command %s.\n",
                   cmd?cmd:"(null)");
    ods_writen(sockfd, buf, strlen(buf));

    /* Anouncement */
    (void) snprintf(buf, ODS_SE_MAXLINE,"Commands:\n");
    ods_writen(sockfd, buf, strlen(buf));
    
    (void) snprintf(buf, ODS_SE_MAXLINE, "PLACEHOLDER, print help\n");
    cmdhandler_get_usage(sockfd);
    
    /* Generic commands */
    (void) snprintf(buf, ODS_SE_MAXLINE,
               "queue                  Show the current task queue.\n"
#ifdef ENFORCER_TIMESHIFT
               "time leap              Simulate progression of time by leaping to the time of\n"
               "                       the earliest scheduled task.\n"
#endif
               "flush                  Execute all scheduled tasks immediately.\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
    (void) snprintf(buf, ODS_SE_MAXLINE,
               "running                Returns acknowledgment that the engine is running.\n"
               "reload                 Reload the engine.\n"
               "stop                   Stop the engine and terminate the process.\n"
               "verbosity <nr>         Set verbosity.\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}

/**
 * Perform command
 */
static int
cmdhandler_perform_command(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    handled_xxxx_cmd_type internal_handled_cmds[] = {
        handled_queue_cmd,
#ifdef ENFORCER_TIMESHIFT
        handled_time_leap_cmd,
#endif
        handled_flush_cmd,
        handled_running_cmd,
        handled_reload_cmd,
        handled_start_cmd,
        handled_stop_cmd,
        handled_verbosity_cmd,
        handled_unknown_cmd /* unknown command allways matches, so last entry */
    };
    time_t tstart = time(NULL);
    struct cmd_func_block* fb;
    unsigned int cmdidx;
    int ret;

    ods_log_verbose("received command %s[%i]", cmd, n);

    if ((fb = get_funcblock(cmd, n))) {
        ret = fb->run(sockfd, engine, cmd, n);
        if (ret == -1) {
            ods_printf(sockfd, "Error parsing arguments\nUsage:\n\n", 
                fb->cmdname, time(NULL) - tstart);
            fb->usage(sockfd);
        } else if (ret == 0) {
            ods_printf(sockfd, "%s completed in %ld seconds.\n", 
                fb->cmdname, time(NULL) - tstart);
        }
        return ret;
    }

    /* enumerate the list of internal commands and break from the loop
     * when one of the handled_xxx_cmd entries inidicates the command
     * was handled by returning 1 or 2 if enforcer is stopped
     */
    for (cmdidx=0;
         cmdidx<sizeof(internal_handled_cmds)/sizeof(handled_xxxx_cmd_type);
         ++cmdidx)
    {
        if ((ret = internal_handled_cmds[cmdidx](sockfd,engine,cmd,n))) break;
    }

    ods_log_debug("[%s] done handling command %s[%i]", module_str, cmd, n);
    return ret;
}

/**
 * Handle a client command.
 *
 */
static void
cmdhandler_handle_client_conversation(cmdhandler_type* cmdc)
{
    ssize_t n;
    int sockfd;
    char buf[ODS_SE_MAXLINE];
    int done = 0;

    ods_log_assert(cmdc);
    if (!cmdc) return;
    sockfd = cmdc->client_fd;

	while (!done) {
		done = 1;
		n = read(sockfd, buf, ODS_SE_MAXLINE);
		if (n <= 0) {
			if (n == 0 || errno == ECONNRESET) {
				ods_log_error("[%s] done handling client: %s", module_str,
					strerror(errno));
			} else if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
				done = 0;
			else
				ods_log_error("[%s] read error: %s", module_str, strerror(errno));
		} else {
			buf[--n] = '\0';
			if (n > 0)
				cmdhandler_perform_command(sockfd, cmdc->engine, buf, n);
		}
	}
}


/**
 * Accept client.
 *
 */
static void*
cmdhandler_accept_client(void* arg)
{
    cmdhandler_type* cmdc = (cmdhandler_type*) arg;

    ods_thread_blocksigs();
    ods_thread_detach(cmdc->thread_id);

    ods_log_debug("[%s] accept client %i", module_str, cmdc->client_fd);
    cmdhandler_handle_client_conversation(cmdc);
    if (cmdc->client_fd) {
        close(cmdc->client_fd);
    }
    free(cmdc);
    count--;
    return NULL;
}


/**
 * Create command handler.
 *
 */
cmdhandler_type*
cmdhandler_create(allocator_type* allocator, const char* filename)
{
    cmdhandler_type* cmdh = NULL;
    struct sockaddr_un servaddr;
    int listenfd = 0;
    int flags = 0;
    int ret = 0;

    if (!allocator) {
        ods_log_error("[%s] unable to create: no allocator");
        return NULL;
    }
    ods_log_assert(allocator);

    if (!filename) {
        ods_log_error("[%s] unable to create: no socket filename");
        return NULL;
    }
    ods_log_assert(filename);
    ods_log_debug("[%s] create socket %s", module_str, filename);

    /* new socket */
    listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenfd <= 0) {
        ods_log_error("[%s] unable to create, socket() failed: %s", module_str,
            strerror(errno));
        return NULL;
    }
    /* set it to non-blocking */
    flags = fcntl(listenfd, F_GETFL, 0);
    if (flags < 0) {
        ods_log_error("[%s] unable to create, fcntl(F_GETFL) failed: %s",
            module_str, strerror(errno));
        close(listenfd);
        return NULL;
    }
    flags |= O_NONBLOCK;
    if (fcntl(listenfd, F_SETFL, flags) < 0) {
        ods_log_error("[%s] unable to create, fcntl(F_SETFL) failed: %s",
            module_str, strerror(errno));
        close(listenfd);
        return NULL;
    }

    /* no surprises */
    if (filename) {
        unlink(filename);
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strncpy(servaddr.sun_path, filename, sizeof(servaddr.sun_path) - 1);

    /* bind and listen... */
    ret = bind(listenfd, (const struct sockaddr*) &servaddr,
        SUN_LEN(&servaddr));
    if (ret != 0) {
        ods_log_error("[%s] unable to create, bind() failed: %s", module_str,
            strerror(errno));
        close(listenfd);
        return NULL;
    }
    ret = listen(listenfd, ODS_SE_MAX_HANDLERS);
    if (ret != 0) {
        ods_log_error("[%s] unable to create, listen() failed: %s", module_str,
            strerror(errno));
        close(listenfd);
        return NULL;
    }

    /* all ok */
    cmdh = (cmdhandler_type*) allocator_alloc(allocator,
        sizeof(cmdhandler_type));
    if (!cmdh) {
        close(listenfd);
        return NULL;
    }
    cmdh->allocator = allocator;
    cmdh->listen_fd = listenfd;
    cmdh->listen_addr = servaddr;
    cmdh->need_to_exit = 0;
    return cmdh;
}


/**
 * Start command handler.
 *
 */
void
cmdhandler_start(cmdhandler_type* cmdhandler)
{
    struct sockaddr_un cliaddr;
    socklen_t clilen;
    cmdhandler_type* cmdc = NULL;
    fd_set rset;
    int connfd = 0;
    int ret = 0;

    ods_log_assert(cmdhandler);
    ods_log_assert(cmdhandler->engine);
    ods_log_debug("[%s] start", module_str);

    ods_thread_detach(cmdhandler->thread_id);
    FD_ZERO(&rset);
    while (cmdhandler->need_to_exit == 0) {
        clilen = sizeof(cliaddr);
        FD_SET(cmdhandler->listen_fd, &rset);
        ret = select(cmdhandler->listen_fd+1, &rset, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                ods_log_warning("[%s] select() error: %s", module_str,
                   strerror(errno));
            }
            continue;
        }
        if (FD_ISSET(cmdhandler->listen_fd, &rset)) {
            connfd = accept(cmdhandler->listen_fd,
                (struct sockaddr *) &cliaddr, &clilen);
            if (connfd < 0) {
                if (errno != EINTR && errno != EWOULDBLOCK) {
                    ods_log_warning("[%s] accept error: %s", module_str,
                        strerror(errno));
                }
                continue;
            }
            /* client accepted, create new thread */
            cmdc = (cmdhandler_type*) malloc(sizeof(cmdhandler_type));
            if (!cmdc) {
                ods_log_crit("[%s] unable to create thread for client: "
                    "malloc failed", module_str);
                cmdhandler->need_to_exit = 1;
            }
            cmdc->listen_fd = cmdhandler->listen_fd;
            cmdc->client_fd = connfd;
            cmdc->listen_addr = cmdhandler->listen_addr;
            cmdc->engine = cmdhandler->engine;
            cmdc->need_to_exit = cmdhandler->need_to_exit;
            ods_thread_create(&cmdc->thread_id, &cmdhandler_accept_client,
                (void*) cmdc);
            count++;
            ods_log_debug("[%s] %i clients in progress...", module_str, count);
        }
    }

    ods_log_debug("[%s] done", module_str);
    cmdhandler->engine->cmdhandler_done = 1;
    return;
}

/**
 * Cleanup command handler.
 *
 */
void
cmdhandler_cleanup(cmdhandler_type* cmdhandler)
{
    if (cmdhandler)
        allocator_deallocate(cmdhandler->allocator, (void*) cmdhandler);
    return;
}
