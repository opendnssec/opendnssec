/*
 * $Id$
 *
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

#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/locks.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/duration.h"

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

#define SE_CMDH_CMDLEN 7

#ifndef SUN_LEN
#define SUN_LEN(su)  (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

#define NUM_CMDQUEUE 32

static int count = 0;
static char* cmdh_str = "cmdhandler";


/**
 * Handle the 'queue' command.
 *
 */
int handled_queue_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    char* strtime = NULL;
    char buf[ODS_SE_MAXLINE];
    size_t i = 0;
    time_t now = 0;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    task_type* task = NULL;

    if (n != 5 || strncmp(cmd, "queue", n) != 0) return 0;
    ods_log_debug("[%s] list tasks command", cmdh_str);

    ods_log_assert(engine);
    if (!engine->taskq || !engine->taskq->tasks) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "I have no tasks scheduled.\n");
        ods_writen(sockfd, buf, strlen(buf));
        return 1;
    }
    
    lock_basic_lock(&engine->taskq->schedule_lock);
    /* [LOCK] schedule */
    /* how many tasks */
    now = time_now();
    strtime = ctime(&now);
    (void)snprintf(buf, ODS_SE_MAXLINE, "I have %i tasks scheduled.\nIt is "
                   "now %s", (int) engine->taskq->tasks->count,
                   strtime?strtime:"(null)");
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
 * Handle the 'flush' command.
 *
 */
int handled_flush_cmd(int sockfd, engine_type* engine, const char *cmd, 
                      ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    if (n != 5 || strncmp(cmd, "flush", n) != 0) return 0;
    ods_log_debug("[%s] flush tasks command", cmdh_str);
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
    ods_log_verbose("[%s] all tasks scheduled immediately", cmdh_str);
    return 1;
}

/**
 * Handle the 'running' command.
 *
 */
int handled_running_cmd(int sockfd, engine_type* engine, const char *cmd,
                        ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    if (n != 7 || strncmp(cmd, "running", n) != 0) return 0;
    ods_log_debug("[%s] running command", cmdh_str);
    (void)snprintf(buf, ODS_SE_MAXLINE, "Engine running.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'start' command.
 *
 */
int handled_start_cmd(int sockfd, engine_type* engine, const char *cmd, 
                      ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    task_type *task;
    ods_status status;
    if (n != 5 || strncmp(cmd, "start", n) != 0) return 0;
    ods_log_debug("[%s] start command", cmdh_str);
    (void)snprintf(buf, ODS_SE_MAXLINE, "Scheduling autostart tasks.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'reload' command.
 *
 */
int handled_reload_cmd(int sockfd, engine_type* engine, const char *cmd,
                       ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    if (n != 6 || strncmp(cmd, "reload", n) != 0) return 0;
    ods_log_debug("[%s] reload command", cmdh_str);
    
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
int handled_stop_cmd(int sockfd, engine_type* engine, const char *cmd, 
                     ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    if (n != 4 || strncmp(cmd, "stop", n) != 0) return 0;
    ods_log_debug("[%s] shutdown command", cmdh_str);
    
    ods_log_assert(engine);
    
    engine->need_to_exit = 1;
    
    lock_basic_lock(&engine->signal_lock);
    /* [LOCK] signal */
    lock_basic_alarm(&engine->signal_cond);
    /* [UNLOCK] signal */
    lock_basic_unlock(&engine->signal_lock);
    
    (void)snprintf(buf, ODS_SE_MAXLINE, ODS_SE_STOP_RESPONSE);
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'verbosity' command.
 *
 */
int handled_verbosity_cmd(int sockfd, engine_type* engine, const char *cmd, 
                          ssize_t n)
{
    if (n < 9 || strncmp(cmd, "verbosity", 9) != 0) return 0;
    ods_log_debug("[%s] verbosity command", cmdh_str);
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


/**
 * Handle the 'help' command.
 *
 */
int handled_help_cmd(int sockfd, engine_type* engine,const char *cmd,
                     ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    help_xxxx_cmd_type *help;

    /* help command ? */
    if (n != 4 || strncmp(cmd, "help", n) != 0) return 0;
    
    ods_log_debug("[%s] help command", cmdh_str);

    
    /* Anouncement */
    (void) snprintf(buf, ODS_SE_MAXLINE,"Commands:\n");
    ods_writen(sockfd, buf, strlen(buf));
    
    /* Call all help functions to emit help texts to the socket. */ 
    for (help=engine->help; help && *help; ++help) {
        (*help)(sockfd);
    }
    
    /* Generic commands */
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "queue           show the current task queue.\n"
        "flush           execute all scheduled tasks immediately.\n"
        "running         returns acknowledgment that the engine is running.\n"
        "start           start the engine.\n"
        "reload          reload the engine.\n"
        "stop            stop the engine.\n"
        "verbosity <nr>  set verbosity.\n"
        "help            show overview of available commands.\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle unknown command.
 *
 */
int handled_unknown_cmd(int sockfd, engine_type* engine, const char *cmd, 
                        ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    ods_log_debug("[%s] unknown command", cmdh_str);
    (void)snprintf(buf, ODS_SE_MAXLINE, "Unknown command %s.\n",
                   cmd?cmd:"(null)");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


static void
cmdhandler_perform_command(int sockfd, engine_type* engine, const char *cmd, 
                           ssize_t n)
{
    handled_xxxx_cmd_type *handled_cmd = NULL;
    handled_xxxx_cmd_type internal_handled_cmds[] = {
        handled_queue_cmd,
        handled_flush_cmd,
        handled_running_cmd,
        handled_start_cmd,
        handled_reload_cmd,
        handled_stop_cmd,
        handled_verbosity_cmd,
        handled_help_cmd,
        handled_unknown_cmd /* unknown command allways matches, so last entry */
    };
    int cmdidx;

    ods_log_verbose("received command %s[%i]", cmd, n);
    
    /* enumerate the list of external commands and break from the 
     * loop when one of the handled_xxx_cmd entries inidicates the 
     * command was handled by returning 1
     */
    for (handled_cmd=engine->commands; handled_cmd && *handled_cmd;
         ++handled_cmd) 
    {
        if ((*handled_cmd)(sockfd,engine,cmd,n)) break;
    }
    
    /* if the command was not handled, try the internal list of commands */
    if (handled_cmd==NULL || *handled_cmd==NULL) {
        /* enumerate the list of internal commands and break from the loop
         * when one of the handled_xxx_cmd entries inidicates the command 
         * was handled by returning 1
         */
        for (cmdidx=0; 
             cmdidx<sizeof(internal_handled_cmds)/sizeof(handled_xxxx_cmd_type);
             ++cmdidx)
        {
            if (internal_handled_cmds[cmdidx](sockfd,engine,cmd,n)) break;
        }
    }
    
    ods_log_debug("[%s] done handling command %s[%i]", cmdh_str, cmd, n);
}

/* Process the commands that were placed in the command processor 
 * queue in sequence.
 *
 */
static task_type *
cmdhandler_queue_processor_task_perform(task_type *task)
{
    cmdhandler_type *cmdh = (cmdhandler_type *)task->context;
    
    /*FIXME: actually process the command.... */
    
	task->backoff = 60;
    task->when = time_now() + task->backoff;
    return task;
}

static task_type *
cmdhandler_queue_processor_task(void *context)
{
    task_id enforce_task_id = task_register_how("cmdhandler_queue_processor_task_perform", cmdhandler_queue_processor_task_perform);
	return task_create(enforce_task_id,time_now(),"cmdhandler", context, cmdhandler_queue_processor_task_perform);
}

/**
 * Handle a client command.
 *
 */
static void
cmdhandler_handle_client_conversation(cmdhandler_type* cmdc)
{
    ssize_t n = 0;
    int sockfd = 0;
    char buf[ODS_SE_MAXLINE];

    ods_log_assert(cmdc);
    if (!cmdc)
        return;
    sockfd = cmdc->client_fd;

again:
    while ((n = read(sockfd, buf, ODS_SE_MAXLINE)) > 0) {
        buf[n-1] = '\0';
        n--;
        if (n <= 0) {
            return;
        }
        
        cmdhandler_perform_command(sockfd,cmdc->engine,buf,n);
        
        (void)snprintf(buf, SE_CMDH_CMDLEN, "\ncmd> ");
        ods_writen(sockfd, buf, strlen(buf));
    }

    if (n < 0 && (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) ) {
        goto again;
    } else if (n < 0 && errno == ECONNRESET) {
        ods_log_debug("[%s] done handling client: %s", cmdh_str,
            strerror(errno));
    } else if (n < 0 ) {
        ods_log_error("[%s] read error: %s", cmdh_str, strerror(errno));
    }
    return;
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

    ods_log_debug("[%s] accept client %i", cmdh_str, cmdc->client_fd);
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
    ods_log_debug("[%s] create socket %s", cmdh_str, filename);

    /* new socket */
    listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenfd <= 0) {
        ods_log_error("[%s] unable to create, socket() failed: %s", cmdh_str,
            strerror(errno));
        return NULL;
    }
    /* set it to non-blocking */
    flags = fcntl(listenfd, F_GETFL, 0);
    if (flags < 0) {
        ods_log_error("[%s] unable to create, fcntl(F_GETFL) failed: %s",
            cmdh_str, strerror(errno));
        close(listenfd);
        return NULL;
    }
    flags |= O_NONBLOCK;
    if (fcntl(listenfd, F_SETFL, flags) < 0) {
        ods_log_error("[%s] unable to create, fcntl(F_SETFL) failed: %s",
            cmdh_str, strerror(errno));
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
        ods_log_error("[%s] unable to create, bind() failed: %s", cmdh_str,
            strerror(errno));
        close(listenfd);
        return NULL;
    }
    ret = listen(listenfd, ODS_SE_MAX_HANDLERS);
    if (ret != 0) {
        ods_log_error("[%s] unable to create, listen() failed: %s", cmdh_str,
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
    lock_basic_init(&cmdh->cmdqueue_lock);
    cmdh->cmdqueue = (const char **)
        allocator_alloc(allocator, NUM_CMDQUEUE * sizeof(const char *));
    cmdh->ncmdqueue = 0;
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
    engine_type* engine = NULL;
    fd_set rset;
    int connfd = 0;
    int ret = 0;

    ods_log_assert(cmdhandler);
    ods_log_assert(cmdhandler->engine);
    ods_log_debug("[%s] start", cmdh_str);

    engine = cmdhandler->engine;
    ods_thread_detach(cmdhandler->thread_id);
    FD_ZERO(&rset);
    while (cmdhandler->need_to_exit == 0) {
        clilen = sizeof(cliaddr);
        FD_SET(cmdhandler->listen_fd, &rset);
        ret = select(ODS_SE_MAX_HANDLERS+1, &rset, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                ods_log_warning("[%s] select() error: %s", cmdh_str,
                   strerror(errno));
            }
            continue;
        }
        if (FD_ISSET(cmdhandler->listen_fd, &rset)) {
            connfd = accept(cmdhandler->listen_fd,
                (struct sockaddr *) &cliaddr, &clilen);
            if (connfd < 0) {
                if (errno != EINTR && errno != EWOULDBLOCK) {
                    ods_log_warning("[%s] accept error: %s", cmdh_str,
                        strerror(errno));
                }
                continue;
            }
            /* client accepted, create new thread */
            cmdc = (cmdhandler_type*) malloc(sizeof(cmdhandler_type));
            if (!cmdc) {
                ods_log_crit("[%s] unable to create thread for client: "
                    "malloc failed", cmdh_str);
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
            ods_log_debug("[%s] %i clients in progress...", cmdh_str, count);
        }
    }

    ods_log_debug("[%s] done", cmdh_str);
    engine = cmdhandler->engine;
    engine->cmdhandler_done = 1;
    return;
}

int
cmdhandler_command_push_back(cmdhandler_type* cmdhandler, const char *cmd)
{
    allocator_type* allocator;
    if (!cmdhandler)
        return 0;

    allocator = cmdhandler->allocator;
    
    lock_basic_lock(&cmdhandler->cmdqueue_lock);
    /* [LOCK] cmdqueue */

    if (cmdhandler->ncmdqueue >= NUM_CMDQUEUE) {
        /* [UNLOCK] cmdqueue */
        lock_basic_unlock(&cmdhandler->cmdqueue_lock);
        return 0;
    }

    cmdhandler->cmdqueue[cmdhandler->ncmdqueue] = allocator_strdup(allocator,
                                                                   cmd);
    if (!cmdhandler->cmdqueue[cmdhandler->ncmdqueue]) {
        /* [UNLOCK] cmdqueue */
        lock_basic_unlock(&cmdhandler->cmdqueue_lock);
       return 0;
    }
    
    /* if this is the first inserted command then start a task to 
     * service the queue
     */
    if (!cmdhandler->ncmdqueue) {
        task_type * task = cmdhandler_queue_processor_task((void*)cmdhandler);
        if (!task) {
            ods_log_crit("[%s] failed to create command processor task",
                         cmdh_str);
        } else {
            ods_status status = schedule_task_from_thread(
                                        cmdhandler->engine->taskq, task, 0);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] failed to schedule command processor task",
                             cmdh_str);
                task_cleanup(task);
            }
        }
    }
    
    ++cmdhandler->ncmdqueue;
    /* [UNLOCK] cmdqueue */
    lock_basic_unlock(&cmdhandler->cmdqueue_lock);

    return 1;
}

const char *
cmdhandler_command_peek_front(cmdhandler_type *cmdhandler)
{
    int i;
    const char *cmd;
    if (!cmdhandler)
        return NULL;
    
    lock_basic_lock(&cmdhandler->cmdqueue_lock);
    /* [LOCK] cmdqueue */
    
    if (!cmdhandler->ncmdqueue) {
        /* [UNLOCK] cmdqueue */
        lock_basic_unlock(&cmdhandler->cmdqueue_lock);
        return NULL;
    }
    
    cmd = cmdhandler->cmdqueue[0];
    
    /* [UNLOCK] cmdqueue */
    lock_basic_unlock(&cmdhandler->cmdqueue_lock);
    return cmd;
}

const char *
cmdhandler_command_pop_front(cmdhandler_type *cmdhandler)
{
    int i;
    const char *cmd;
    if (!cmdhandler)
        return NULL;

    lock_basic_lock(&cmdhandler->cmdqueue_lock);
    /* [LOCK] cmdqueue */
    
    if (!cmdhandler->ncmdqueue) {
        /* [UNLOCK] cmdqueue */
        lock_basic_unlock(&cmdhandler->cmdqueue_lock);
        return NULL;
    }

    cmd = cmdhandler->cmdqueue[0];
    for (i=1; i<cmdhandler->ncmdqueue; ++i)
        cmdhandler->cmdqueue[i-1] = cmdhandler->cmdqueue[i];
    --cmdhandler->ncmdqueue;

    /* [UNLOCK] cmdqueue */
    lock_basic_unlock(&cmdhandler->cmdqueue_lock);
    return cmd;
}

void
cmdhandler_command_release(cmdhandler_type* cmdhandler, const char *cmd)
{
    if (cmdhandler)
        allocator_deallocate(cmdhandler->allocator, (void *) cmd);
}

/**
 * Cleanup command handler.
 *
 */
void
cmdhandler_cleanup(cmdhandler_type* cmdhandler)
{
    int i;
    allocator_type* allocator;
    if (!cmdhandler) {
        return;
    }
    lock_basic_destroy(&cmdhandler->cmdqueue_lock);
    allocator = cmdhandler->allocator;
    for (i=0; i<cmdhandler->ncmdqueue; ++i) {
        allocator_deallocate(allocator, (void*) cmdhandler->cmdqueue[i]);   
    }
    allocator_deallocate(allocator, (void*) cmdhandler->cmdqueue);
    allocator_deallocate(allocator, (void*) cmdhandler);
    return;
}

