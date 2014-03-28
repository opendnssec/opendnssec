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

#include <sys/un.h>
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
#include "daemon/time_leap_cmd.h"
#include "daemon/queue_cmd.h"
#include "daemon/verbosity_cmd.h"
#include "daemon/ctrl_cmd.h"
#include "enforcer/setup_cmd.h"
#include "enforcer/update_repositorylist_cmd.h"
#include "enforcer/update_all_cmd.h"
#include "enforcer/enforce_cmd.h"
#include "policy/update_kasp_cmd.h"
#include "policy/policy_import_cmd.h"
#include "policy/policy_export_cmd.h"
#include "policy/policy_purge_cmd.h"
#include "keystate/update_keyzones_cmd.h"
#include "keystate/zone_list_cmd.h"
#include "keystate/zone_del_cmd.h"
#include "keystate/zone_add_cmd.h"
#include "keystate/zonelist_cmd.h"
#include "keystate/keystate_ds_submit_cmd.h"
#include "keystate/keystate_ds_seen_cmd.h"
#include "keystate/keystate_ds_retract_cmd.h"
#include "keystate/keystate_ds_gone_cmd.h"
#include "keystate/keystate_export_cmd.h"
#include "keystate/keystate_list_cmd.h"
#include "keystate/rollover_list_cmd.h"
#include "keystate/keystate_rollover_cmd.h"
#include "hsmkey/hsmkey_gen_cmd.h"
#include "hsmkey/update_hsmkeys_cmd.h"
#include "signconf/signconf_cmd.h"
#include "hsmkey/backup_hsmkeys_cmd.h"

#include "daemon/cmdhandler.h"

#define SE_CMDH_CMDLEN 7

#ifndef SUN_LEN
#define SUN_LEN(su) (sizeof(*(su))-sizeof((su)->sun_path)+strlen((su)->sun_path))
#endif

static int count = 0;
static char* module_str = "cmdhandler";

typedef struct cmd_func_block* (*fbgetfunctype)(void);

static fbgetfunctype*
cmd_funcs_avail(void)
{
    static struct cmd_func_block* (*fb[])(void) = {
        /* Thoughts has gone into the ordering of this list, it affects 
         * the output of the help command */
        &setup_funcblock,
        &update_kasp_funcblock,
        &update_keyzones_funcblock,
        &update_repositorylist_funcblock,
        &update_all_funcblock,

        &policy_list_funcblock,
        &policy_export_funcblock,
        &policy_import_funcblock,
        &policy_purge_funcblock,
        &resalt_funcblock,

        &zone_list_funcblock,
        &zone_add_funcblock,
        &zone_del_funcblock,

        &zonelist_export_funcblock,
        &zonelist_import_funcblock,

        &key_list_funcblock,
        &key_import_funcblock,
        &key_export_funcblock,
        &key_ds_submit_funcblock,
        &key_ds_seen_funcblock,
        &key_ds_retract_funcblock,
        &key_ds_gone_funcblock,
        &key_gen_funcblock,

        &key_rollover_funcblock,
        &rollover_list_funcblock,
        
        &backup_funcblock,

        &enforce_funcblock,
        &signconf_funcblock,

        &queue_funcblock,
#ifdef ENFORCER_TIMESHIFT
        &time_leap_funcblock,
#endif
        &flush_funcblock,
        &ctrl_funcblock,
        &verbosity_funcblock,
        &help_funcblock,
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
 * Perform command
 */
static int
cmdhandler_perform_command(int sockfd, engine_type* engine,
    const char *cmd, ssize_t n)
{
    time_t tstart = time(NULL);
    struct cmd_func_block* fb;
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
        ods_log_debug("[%s] done handling command %s[%i]", module_str, cmd, n);
        return ret;
    }
    ods_printf(sockfd, "Unknown command %s.\n", cmd?cmd:"(null)");
    ods_printf(sockfd, "Commands:\n");
    cmdhandler_get_usage(sockfd);
    return 1;
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
    count--; /* !not thread safe! */
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
    cmdh = (cmdhandler_type*)malloc(sizeof (cmdhandler_type));
    if (!cmdh) {
        close(listenfd);
        return NULL;
    }
    cmdh->listen_fd = listenfd;
    cmdh->listen_addr = servaddr;
    cmdh->need_to_exit = 0;
    return cmdh;
}

/**
 * Cleanup command handler.
 *
 */
void
cmdhandler_cleanup(cmdhandler_type* cmdhandler)
{
    free(cmdhandler);
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
 * Self pipe trick (see Unix Network Programming).
 *
 */
static int
self_pipe_trick()
{
    int sockfd, ret;
    struct sockaddr_un servaddr;
    const char* servsock_filename = OPENDNSSEC_ENFORCER_SOCKETFILE;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd <= 0) {
        ods_log_error("[engine] cannot connect to command handler: "
            "socket() failed: %s\n", strerror(errno));
        return 1;
    } else {
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sun_family = AF_UNIX;
        strncpy(servaddr.sun_path, servsock_filename,
            sizeof(servaddr.sun_path) - 1);

        ret = connect(sockfd, (const struct sockaddr*) &servaddr,
            sizeof(servaddr));
        if (ret != 0) {
            ods_log_error("[engine] cannot connect to command handler: "
                "connect() failed: %s\n", strerror(errno));
            close(sockfd);
            return 1;
        } else {
            /* self-pipe trick */
            ods_writen(sockfd, "", 1);
            close(sockfd);
        }
    }
    return 0;
}
/**
 * Stop command handler.
 *
 */
void
cmdhandler_stop(struct engine_struct* engine)
{
    ods_log_assert(engine);
    if (!engine->cmdhandler) {
        return;
    }
    ods_log_debug("[engine] stop command handler");
    engine->cmdhandler->need_to_exit = 1;
    if (self_pipe_trick() == 0) {
        while (!engine->cmdhandler_done) {
            ods_log_debug("[engine] waiting for command handler to exit...");
            sleep(1);
        }
    } else {
        ods_log_error("[engine] command handler self pipe trick failed, "
            "unclean shutdown");
    }
    return;
}
