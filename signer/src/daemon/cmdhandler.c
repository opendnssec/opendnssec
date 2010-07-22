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
#include "scheduler/locks.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <errno.h>
#include <fcntl.h> /* fcntl() */
#include <ldns/ldns.h> /* ldns_rbtree_*() */
#include <stdio.h> /* snprintf() */
#include <stdlib.h> /* atoi() */
#include <string.h> /* strncpy(), strerror(), strlen(), strncmp() */
#include <strings.h> /* bzero() */
#include <sys/select.h> /* select(), FD_ZERO(), FD_SET(), FD_ISSET() */
#include <sys/socket.h> /* socket(), listen(), bind(), accept() */
#include <unistd.h> /* fcntl(), close(), unlink(), read() */

/* According to earlier standards: select() sys/time.h sys/types.h unistd.h */
#include <sys/time.h>
#include <sys/types.h>

#define SE_CMDH_CMDLEN 7

#ifndef SUN_LEN
#define SUN_LEN(su)  (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

static int count = 0;


/**
 * Handle the 'help' command.
 *
 */
static void
cmdhandler_handle_cmd_help(int sockfd)
{
    char buf[ODS_SE_MAXLINE];

    (void) snprintf(buf, ODS_SE_MAXLINE,
        "Commands:\n"
        "zones           show the currently known zones\n"
        "sign <zone>     schedule zone for immediate (re-)signing\n"
        "sign --all      schedule all zones for immediate (re-)signing.\n"
        "clear <zone>    delete the internal storage of this zone.\n"
        "                All signatures will be regenerated on the next re-sign.\n"
        "queue           show the current task queue.\n"
    );
    se_writen(sockfd, buf, strlen(buf));

    (void) snprintf(buf, ODS_SE_MAXLINE,
        "flush           execute all scheduled tasks immediately.\n"
        "update <zone>   update this zone signer configurations.\n"
        "update [--all]  update zone list and all signer configurations.\n"
        "start           start the engine.\n"
        "reload          reload the engine.\n"
        "stop            stop the engine.\n"
        "verbosity <nr>  set verbosity.\n"
    );
    se_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle the 'zones' command.
 *
 */
static void
cmdhandler_handle_cmd_zones(int sockfd, cmdhandler_type* cmdc)
{
    char buf[ODS_SE_MAXLINE];
    size_t i;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;

    se_log_assert(cmdc);
    se_log_assert(cmdc->engine);
    se_log_assert(cmdc->engine->zonelist);

    /* lock zonelist */
    zonelist_lock(cmdc->engine->zonelist);

    /* how many zones */
    (void)snprintf(buf, ODS_SE_MAXLINE, "I have %i zones configured\n",
        cmdc->engine->zonelist->zones->count);
    se_writen(sockfd, buf, strlen(buf));

    /* list zones */
    node = ldns_rbtree_first(cmdc->engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->key;
        for (i=0; i < ODS_SE_MAXLINE; i++) {
            buf[i] = 0;
        }
        (void)snprintf(buf, ODS_SE_MAXLINE, "- %s\n", zone->name);
        se_writen(sockfd, buf, strlen(buf));
        node = ldns_rbtree_next(node);
    }

    /* unlock zonelist */
    zonelist_unlock(cmdc->engine->zonelist);
    return;
}


/**
 * Handle the 'update' command.
 *
 */
static void
cmdhandler_handle_cmd_update(int sockfd, cmdhandler_type* cmdc, const char* tbd)
{
    char buf[ODS_SE_MAXLINE];
    size_t i = 0;
    int ret = 0;

    se_log_assert(tbd);
    se_log_assert(cmdc);
    se_log_assert(cmdc->engine);
    se_log_assert(cmdc->engine->tasklist);

    if (se_strcmp(tbd, "--all") == 0) {
        ret = engine_update_zonelist(cmdc->engine, buf);
        se_writen(sockfd, buf, strlen(buf));
        tbd = NULL;
    }
    engine_update_zones(cmdc->engine, tbd, buf);
    se_writen(sockfd, buf, strlen(buf));

    /* wake up sleeping workers */
    for (i=0; i < (size_t) cmdc->engine->config->num_worker_threads; i++) {
        worker_wakeup(cmdc->engine->workers[i]);
    }
    return;
}


/**
 * Handle the 'sign' command.
 *
 */
static void
cmdhandler_handle_cmd_sign(int sockfd, cmdhandler_type* cmdc, const char* tbd)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    task_type* task = NULL;
    time_t now = time_now();
    int found = 0, scheduled = 0;
    char buf[ODS_SE_MAXLINE];
    size_t i = 0;

    se_log_assert(tbd);
    se_log_assert(cmdc);
    se_log_assert(cmdc->engine);
    se_log_assert(cmdc->engine->tasklist);

    /* lock tasklist */
    lock_basic_lock(&cmdc->engine->tasklist->tasklist_lock);

    node = ldns_rbtree_first(cmdc->engine->tasklist->tasks);
    while (node && node != LDNS_RBTREE_NULL) {
        task = (task_type*) node->key;

        if (se_strcmp(tbd, "--all") == 0) {
            /* just flush it */
            task->flush = 1;
            task->what = TASK_READ;
        } else if (se_strcmp(tbd, task->who) == 0) {
            task = tasklist_delete_task(cmdc->engine->tasklist, task);
            task->when = now;
            /* NOTE: isn't this counter-intuitive? should we read unsigned
             * zone on a different command?
             */
            task->what = TASK_READ;
            task = tasklist_schedule_task(cmdc->engine->tasklist, task, 0);
            if (task) {
                scheduled = 1;
            }
            found = 1;
            break;
        }
        node = ldns_rbtree_next(node);
    }

    /* unlock tasklist */
    lock_basic_unlock(&cmdc->engine->tasklist->tasklist_lock);

    if (se_strcmp(tbd, "--all") == 0) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "All zones scheduled for "
            "immediate re-sign.\n");
        se_writen(sockfd, buf, strlen(buf));

        /* wake up sleeping workers */
        for (i=0; i < (size_t) cmdc->engine->config->num_worker_threads; i++) {
            worker_wakeup(cmdc->engine->workers[i]);
        }
    } else if (found && scheduled) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s scheduled for "
            "immediate re-sign.\n", tbd);
        se_writen(sockfd, buf, strlen(buf));

        /* wake up sleeping workers */
        for (i=0; i < (size_t) cmdc->engine->config->num_worker_threads; i++) {
            worker_wakeup(cmdc->engine->workers[i]);
        }
    } else if (found && !scheduled) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s not scheduled, "
            "already being signed right now!\n", tbd);
        se_writen(sockfd, buf, strlen(buf));
    } else {
        (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s not being signed yet, "
            "updating sign configuration\n", tbd);
        se_writen(sockfd, buf, strlen(buf));
        cmdhandler_handle_cmd_update(sockfd, cmdc, tbd);
    }
    return;
}


/**
 * Handle the 'clear' command.
 *
 */
static void
cmdhandler_handle_cmd_clear(int sockfd, cmdhandler_type* cmdc, const char* tbd)
{
    char buf[ODS_SE_MAXLINE];
    char* tmpname = NULL;

    se_log_assert(tbd);
    se_log_assert(cmdc);
    se_log_assert(cmdc->engine);
    se_log_assert(cmdc->engine->tasklist);

    /* lock tasklist */
    lock_basic_lock(&cmdc->engine->tasklist->tasklist_lock);

    tmpname = se_build_path(tbd, ".unsorted", 0);
    unlink(tmpname);
    se_free((void*)tmpname);

    tmpname = se_build_path(tbd, ".denial", 0);
    unlink(tmpname);
    se_free((void*)tmpname);

    tmpname = se_build_path(tbd, ".rrsigs", 0);
    unlink(tmpname);
    se_free((void*)tmpname);

    /* unlock tasklist */
    lock_basic_unlock(&cmdc->engine->tasklist->tasklist_lock);


    (void)snprintf(buf, ODS_SE_MAXLINE, "Internal information about "
        "%s cleared", tbd);
    se_writen(sockfd, buf, strlen(buf));

    return;
}


/**
 * Handle the 'queue' command.
 *
 */
static void
cmdhandler_handle_cmd_queue(int sockfd, cmdhandler_type* cmdc)
{
    char* taskstr = NULL;
    char* strtime = NULL;
    char buf[ODS_SE_MAXLINE];
    size_t i = 0;
    time_t now = 0;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    task_type* task = NULL;

    se_log_assert(cmdc);
    se_log_assert(cmdc->engine);
    se_log_assert(cmdc->engine->tasklist);

    /* lock tasklist */
    lock_basic_lock(&cmdc->engine->tasklist->tasklist_lock);

    /* how many tasks scheduled */
    now = time_now();
    strtime = ctime(&now);
    (void)snprintf(buf, ODS_SE_MAXLINE, "I have %i tasks scheduled\nIt is "
        "now %s", cmdc->engine->tasklist->tasks->count, strtime);
    se_writen(sockfd, buf, strlen(buf));

    /* list tasks */
    node = ldns_rbtree_first(cmdc->engine->tasklist->tasks);
    while (node && node != LDNS_RBTREE_NULL) {
        task = (task_type*) node->key;
        for (i=0; i < ODS_SE_MAXLINE; i++) {
            buf[i] = 0;
        }
        taskstr = task2str(task, (char*) &buf[0]);
        se_writen(sockfd, buf, strlen(buf));
        node = ldns_rbtree_next(node);
    }

    /* unlock tasklist */
    lock_basic_unlock(&cmdc->engine->tasklist->tasklist_lock);
    return;
}


/**
 * Handle the 'flush' command.
 *
 */
static void
cmdhandler_handle_cmd_flush(int sockfd, cmdhandler_type* cmdc)
{
    char buf[ODS_SE_MAXLINE];
    size_t i = 0;

    se_log_assert(cmdc);
    se_log_assert(cmdc->engine);
    se_log_assert(cmdc->engine->tasklist);

    lock_basic_lock(&cmdc->engine->tasklist->tasklist_lock);
    tasklist_flush(cmdc->engine->tasklist);
    lock_basic_unlock(&cmdc->engine->tasklist->tasklist_lock);

    /* wake up sleeping workers */
    for (i=0; i < (size_t) cmdc->engine->config->num_worker_threads; i++) {
        worker_wakeup(cmdc->engine->workers[i]);
    }
    (void)snprintf(buf, ODS_SE_MAXLINE, "All tasks scheduled immediately.\n");
    se_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle the 'reload' command.
 *
 */
static void
cmdhandler_handle_cmd_reload(int sockfd, cmdhandler_type* cmdc)
{
    char buf[ODS_SE_MAXLINE];

    se_log_assert(cmdc);
    se_log_assert(cmdc->engine);

    lock_basic_lock(&cmdc->engine->signal_lock);
    cmdc->engine->need_to_reload = 1;
    lock_basic_alarm(&cmdc->engine->signal_cond);
    lock_basic_unlock(&cmdc->engine->signal_lock);

    (void)snprintf(buf, ODS_SE_MAXLINE, "Reloading engine.\n");
    se_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle the 'stop' command.
 *
 */
static void
cmdhandler_handle_cmd_stop(int sockfd, cmdhandler_type* cmdc)
{
    char buf[ODS_SE_MAXLINE];

    se_log_assert(cmdc);
    se_log_assert(cmdc->engine);

    lock_basic_lock(&cmdc->engine->signal_lock);
    cmdc->engine->need_to_exit = 1;
    lock_basic_alarm(&cmdc->engine->signal_cond);
    lock_basic_unlock(&cmdc->engine->signal_lock);

    (void)snprintf(buf, ODS_SE_MAXLINE, ODS_SE_STOP_RESPONSE);
    se_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle the 'start' command.
 *
 */
static void
cmdhandler_handle_cmd_start(int sockfd)
{
    char buf[ODS_SE_MAXLINE];

    (void)snprintf(buf, ODS_SE_MAXLINE, "Engine already running.\n");
    se_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle the 'verbosity' command.
 *
 */
static void
cmdhandler_handle_cmd_verbosity(int sockfd, cmdhandler_type* cmdc, int val)
{
    char buf[ODS_SE_MAXLINE];

    se_log_assert(cmdc);
    se_log_assert(cmdc->engine);
    se_log_assert(cmdc->engine->config);

    lock_basic_lock(&cmdc->engine->signal_lock);
    se_log_init(cmdc->engine->config->log_filename,
        cmdc->engine->config->use_syslog, val);
    lock_basic_unlock(&cmdc->engine->signal_lock);

    (void)snprintf(buf, ODS_SE_MAXLINE, "Verbosity level set to %i.\n", val);
    se_writen(sockfd, buf, strlen(buf));
}


/**
 * Handle erroneous command.
 *
 */
static void
cmdhandler_handle_cmd_error(int sockfd, const char* str)
{
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, "Error: %s.\n", str);
    se_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle unknown command.
 *
 */
static void
cmdhandler_handle_cmd_unknown(int sockfd, const char* str)
{
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, "Unknown command %s.\n", str);
    se_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle not implemented.
 *
static void
cmdhandler_handle_cmd_notimpl(int sockfd, const char* str)
{
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, "Command %s not implemented.\n", str);
    se_writen(sockfd, buf, strlen(buf));
    return;
}
 */


/**
 * Handle client command.
 *
 */
static void
cmdhandler_handle_cmd(cmdhandler_type* cmdc)
{
    ssize_t n = 0;
    int sockfd = 0;
    char buf[ODS_SE_MAXLINE];

    se_log_assert(cmdc);

    sockfd = cmdc->client_fd;

again:
    while ((n = read(sockfd, buf, ODS_SE_MAXLINE)) > 0) {
        buf[n-1] = '\0';
        n--;
        if (n <= 0) {
            return;
        }
        se_log_verbose("received command %s[%i]", buf, n);

        if (n == 4 && strncmp(buf, "help", n) == 0) {
            se_log_debug("help command");
            cmdhandler_handle_cmd_help(sockfd);
        } else if (n == 5 && strncmp(buf, "zones", n) == 0) {
            se_log_debug("list zones command");
            cmdhandler_handle_cmd_zones(sockfd, cmdc);
        } else if (n >= 4 && strncmp(buf, "sign", 4) == 0) {
            se_log_debug("sign zone command");
            if (buf[4] == '\0') {
                /* NOTE: wouldn't it be nice that we default to --all? */
                cmdhandler_handle_cmd_error(sockfd, "sign command needs "
                    "an argument (either '--all' or a zone name)");
            } else if (buf[4] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_sign(sockfd, cmdc, &buf[5]);
            }
        } else if (n >= 5 && strncmp(buf, "clear", 5) == 0) {
            se_log_debug("clear zone command");
            if (buf[5] == '\0') {
                cmdhandler_handle_cmd_error(sockfd, "clear command needs "
                    "a zone name");
            } else if (buf[5] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_clear(sockfd, cmdc, &buf[6]);
            }
        } else if (n == 5 && strncmp(buf, "queue", n) == 0) {
            se_log_debug("list tasks command");
            cmdhandler_handle_cmd_queue(sockfd, cmdc);
        } else if (n == 5 && strncmp(buf, "flush", n) == 0) {
            se_log_debug("flush tasks command");
            cmdhandler_handle_cmd_flush(sockfd, cmdc);
        } else if (n >= 6 && strncmp(buf, "update", 6) == 0) {
            se_log_debug("update command");
            if (buf[6] == '\0') {
                cmdhandler_handle_cmd_update(sockfd, cmdc, "--all");
            } else if (buf[6] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_update(sockfd, cmdc, &buf[7]);
            }
        } else if (n == 4 && strncmp(buf, "stop", n) == 0) {
            se_log_debug("shutdown command");
            cmdhandler_handle_cmd_stop(sockfd, cmdc);
            return;
        } else if (n == 5 && strncmp(buf, "start", n) == 0) {
            se_log_debug("start command");
            cmdhandler_handle_cmd_start(sockfd);
        } else if (n == 6 && strncmp(buf, "reload", n) == 0) {
            se_log_debug("reload command");
            cmdhandler_handle_cmd_reload(sockfd, cmdc);
        } else if (n >= 9 && strncmp(buf, "verbosity", 9) == 0) {
            se_log_debug("verbosity command");
            if (buf[9] == '\0') {
                cmdhandler_handle_cmd_error(sockfd, "verbosity command "
                    "an argument (verbosity level)");
            } else if (buf[9] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_verbosity(sockfd, cmdc, atoi(&buf[10]));
            }
        } else {
            se_log_debug("unknown command");
            cmdhandler_handle_cmd_unknown(sockfd, buf);
        }

        se_log_debug("done handling command %s[%i]", buf, n);
        (void)snprintf(buf, SE_CMDH_CMDLEN, "\ncmd> ");
        se_writen(sockfd, buf, strlen(buf));
    }

    if (n < 0 && errno == EINTR) {
        goto again;
    } else if (n < 0 && errno == ECONNRESET) {
        se_log_debug("done handling client: %s", strerror(errno));
    } else if (n < 0 ) {
        se_log_error("command handler read error: %s", strerror(errno));
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

    se_thread_blocksigs();
    se_thread_detach(cmdc->thread_id);

    se_log_debug("command handler accept client %i", cmdc->client_fd);
    cmdhandler_handle_cmd(cmdc);
    cmdhandler_cleanup(cmdc);
    count--;
    return NULL;
}


/**
 * Create command handler.
 *
 */
cmdhandler_type*
cmdhandler_create(const char* filename)
{
    cmdhandler_type* cmdh = NULL;
    struct sockaddr_un servaddr;
    int listenfd = 0;
    int flags = 0;
    int ret = 0;

    se_log_assert(filename);
    se_log_debug("create command handler to socket %s", filename);

    /* new socket */
    listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenfd <= 0) {
        se_log_error("unable to create command handler, socket() failed: %s",
            strerror(errno));
        return NULL;
    }
    /* set it to non-blocking */
    flags = fcntl(listenfd, F_GETFL, 0);
    if (flags < 0) {
        se_log_error("unable to create command handler, fcntl(F_GETFL) "
            "failed: %s", strerror(errno));
        close(listenfd);
        return NULL;
    }
    flags |= O_NONBLOCK;
    if (fcntl(listenfd, F_SETFL, flags) < 0) {
        se_log_error("unable to create command handler, fcntl(F_SETFL) "
            "failed: %s", strerror(errno));
        close(listenfd);
        return NULL;
    }

    /* no suprises */
    unlink(filename);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strncpy(servaddr.sun_path, filename, sizeof(servaddr.sun_path) - 1);

    /* bind and listen... */
    ret = bind(listenfd, (const struct sockaddr*) &servaddr,
        SUN_LEN(&servaddr));
    if (ret != 0) {
        se_log_error("unable to create command handler, bind() failed: %s",
            strerror(errno));
        close(listenfd);
        return NULL;
    }
    ret = listen(listenfd, ODS_SE_MAX_HANDLERS);
    if (ret != 0) {
        se_log_error("unable to create command handler, listen() failed: %s",
            strerror(errno));
        close(listenfd);
        return NULL;
    }

    /* all ok */
    cmdh = (cmdhandler_type*) se_malloc(sizeof(cmdhandler_type));
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
    engine_type* engine = NULL;
    fd_set rset;
    int connfd = 0;
    int ret = 0;

    se_log_assert(cmdhandler);
    se_log_assert(cmdhandler->engine);
    se_log_debug("command handler start");

    engine = cmdhandler->engine;
    se_thread_detach(cmdhandler->thread_id);
    FD_ZERO(&rset);
    while (cmdhandler->need_to_exit == 0) {
        clilen = sizeof(cliaddr);
        FD_SET(cmdhandler->listen_fd, &rset);
        ret = select(ODS_SE_MAX_HANDLERS+1, &rset, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                se_log_warning("cmdhandler select() error: %s",
                   strerror(errno));
            }
            continue;
        }
        if (FD_ISSET(cmdhandler->listen_fd, &rset)) {
            connfd = accept(cmdhandler->listen_fd,
                (struct sockaddr *) &cliaddr, &clilen);
            if (connfd < 0) {
                if (errno != EINTR && errno != EWOULDBLOCK) {
                    se_log_warning("command handler accept error: %s",
                        strerror(errno));
                }
                continue;
            }
            /* client accepted, create new thread */
            cmdc = (cmdhandler_type*) se_malloc(sizeof(cmdhandler_type));
            cmdc->listen_fd = cmdhandler->listen_fd;
            cmdc->client_fd = connfd;
            cmdc->listen_addr = cmdhandler->listen_addr;
            cmdc->engine = cmdhandler->engine;
            cmdc->need_to_exit = cmdhandler->need_to_exit;
            se_thread_create(&cmdc->thread_id, &cmdhandler_accept_client,
                (void*) cmdc);
            count++;
            se_log_debug("command handler %i clients in progress...", count);
        }
    }

    se_log_debug("command handler done");
    engine = cmdhandler->engine;
    cmdhandler_cleanup(cmdhandler);
    engine->cmdhandler_done = 1;
    return;
}


/**
 * Clean up command handler.
 *
 */
void
cmdhandler_cleanup(cmdhandler_type* cmdhandler)
{
    if (cmdhandler) {
        se_free((void*)cmdhandler);
    } else {
        se_log_warning("clean up empty command handler");
    }
    return;
}
