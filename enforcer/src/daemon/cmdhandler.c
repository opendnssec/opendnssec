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
#include <pthread.h>
#include <syslog.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <unistd.h>
/* According to earlier standards: select() sys/time.h sys/types.h unistd.h */
#include <sys/time.h>
#include <sys/types.h>

#include "daemon/engine.h"
#include "clientpipe.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "file.h"
#include "log.h"
#include "status.h"
#include "duration.h"
#include "str.h"
#include "db/db_connection.h"

/* commands to handle */
#include "policy/policy_resalt_cmd.h"
#include "policy/policy_list_cmd.h"
#include "daemon/help_cmd.h"
#include "daemon/time_leap_cmd.h"
#include "daemon/queue_cmd.h"
#include "daemon/verbosity_cmd.h"
#include "daemon/ctrl_cmd.h"
#include "enforcer/update_repositorylist_cmd.h"
#include "enforcer/repositorylist_cmd.h"
#include "enforcer/update_all_cmd.h"
#include "enforcer/update_conf_cmd.h"
#include "enforcer/enforce_cmd.h"
#include "policy/policy_import_cmd.h"
#include "policy/policy_export_cmd.h"
#include "policy/policy_purge_cmd.h"
#include "keystate/zone_list_cmd.h"
#include "keystate/zone_del_cmd.h"
#include "keystate/zone_add_cmd.h"
#include "keystate/keystate_ds_submit_cmd.h"
#include "keystate/keystate_ds_seen_cmd.h"
#include "keystate/keystate_ds_retract_cmd.h"
#include "keystate/keystate_ds_gone_cmd.h"
#include "keystate/keystate_export_cmd.h"
#include "keystate/keystate_list_cmd.h"
#include "keystate/key_purge_cmd.h"
#include "keystate/rollover_list_cmd.h"
#include "keystate/keystate_rollover_cmd.h"
#include "keystate/zonelist_import_cmd.h"
#include "keystate/zonelist_export_cmd.h"
#include "signconf/signconf_cmd.h"
#include "hsmkey/backup_hsmkeys_cmd.h"
#include "hsmkey/key_generate_cmd.h"

#include "daemon/cmdhandler.h"

#define SE_CMDH_CMDLEN 7
#define MAX_CLIENT_CONN 8

#ifndef SUN_LEN
#define SUN_LEN(su) (sizeof(*(su))-sizeof((su)->sun_path)+strlen((su)->sun_path))
#endif

static char const * module_str = "cmdhandler";

typedef struct cmd_func_block* (*fbgetfunctype)(void);

static fbgetfunctype*
cmd_funcs_avail(void)
{
    static struct cmd_func_block* (*fb[])(void) = {
        /* Thoughts has gone into the ordering of this list, it affects 
         * the output of the help command */
        &update_conf_funcblock,
        &update_repositorylist_funcblock,
	&repositorylist_funcblock,
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
        &key_export_funcblock,
        &key_ds_submit_funcblock,
        &key_ds_seen_funcblock,
        &key_ds_retract_funcblock,
        &key_ds_gone_funcblock,
        &key_generate_funcblock,
	&key_purge_funcblock,

        &key_rollover_funcblock,
        &rollover_list_funcblock,
        
        &backup_funcblock,

        &enforce_funcblock,
        &signconf_funcblock,


        &queue_funcblock,
        &time_leap_funcblock,
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
 * 
 * \param sockfd, pipe to client
 * \param engine, central enigine object
 * \param cmd, command to evaluate
 * \param n, length of command.
 * \return exit code for client, 0 for no errors, -1 for syntax errors
 */
static int
cmdhandler_perform_command(cmdhandler_type* cmdc, const char *cmd,
    ssize_t n)
{
    time_t tstart = time(NULL);
    struct cmd_func_block* fb;
    int ret;
    int sockfd = cmdc->client_fd;

    ods_log_verbose("received command %s[%ld]", cmd, (long)n);
    if (n == 0) return 0;

    /* Find function claiming responsibility */
    if ((fb = get_funcblock(cmd, n))) {
        ods_log_debug("[%s] %s command", module_str, fb->cmdname);
        ret = fb->run(sockfd, cmdc->engine, cmd, n, cmdc->dbconn);
        if (ret == -1) {
            /* Syntax error, print usage for cmd */
            client_printf_err(sockfd, "Error parsing arguments\n",
                fb->cmdname, time(NULL) - tstart);
            client_printf(sockfd, "Usage:\n\n");
            fb->usage(sockfd);
        } else if (ret == 0) { /* success */
            client_printf_err(sockfd, "%s completed in %ld seconds.\n",
                fb->cmdname, time(NULL) - tstart);
        }
        ods_log_debug("[%s] done handling command %s[%ld]", module_str, cmd, (long)n);
        return ret;
    }
    /* Unhandled command, print general error */
    client_printf_err(sockfd, "Unknown command %s.\n", cmd?cmd:"(null)");
    client_printf(sockfd, "Commands:\n");
    cmdhandler_get_usage(sockfd);
    return 1;
}

/**
 * Consume a message from the buffer
 * 
 * Read all complete messages in the buffer or until exit code is set.
 * Messages larger than ODS_SE_MAXLINE can be handled but will be 
 * truncated. On exit pos will indicate new position in buffer. when 
 * returning true an exit code is set.
 * 
 * \param buf, buffer containing user input. Must not be NULL.
 * \param[in|out] pos, count of meaningful octets in buf. Must not be 
 *      NULL or exceed buflen.
 * \param buflen, capacity of buf. Must not exceed ODS_SE_MAXLINE.
 * \param[out] exitcode, exit code for client, only meaningful on 
 *      return 1. Must not be NULL.
 * \param sockfd, pipe to client.
 * \param engine, central enigine object
 * \return 0: waiting for more data. 1: exit code is set.
 */
static int
extract_msg(char* buf, int *pos, int buflen, int *exitcode, 
cmdhandler_type* cmdc)
{
    char data[ODS_SE_MAXLINE+1], opc;
    int datalen;
    
    assert(exitcode);
    assert(buf);
    assert(pos);
    assert(*pos <= buflen);
    assert(ODS_SE_MAXLINE >= buflen);
    
    while (1) {
        if (*pos < 3) return 0;
        opc = buf[0];
        datalen = (buf[1]<<8) | (buf[2]&0xFF);
        if (datalen+3 <= *pos) {
            /* a complete message */
            memset(data, 0, ODS_SE_MAXLINE+1);
            memcpy(data, buf+3, datalen);
            *pos -= datalen+3;
            memmove(buf, buf+datalen+3, *pos);
            ods_str_trim(data, 0);

            if (opc == CLIENT_OPC_STDIN) {
                *exitcode = cmdhandler_perform_command(cmdc, data, strlen(data));
                return 1;
            }
        } else if (datalen+3 > buflen) {
            /* Message is not going to fit! Discard the data already recvd */
            ods_log_error("[%s] Message received to big, truncating.", module_str);
            datalen -= *pos - 3;
            buf[1] = datalen >> 8;
            buf[2] = datalen & 0xFF;
            *pos = 3;
            return 0;
        } else {
            /* waiting for more data */
            return 0;
        }
    }
}

/**
 * Handle a client command.
 * \param cmdc, command handler data, must not be NULL
 */
static void
cmdhandler_handle_client_conversation(cmdhandler_type* cmdc)
{
    /* read blocking */
    char buf[ODS_SE_MAXLINE+4]; /* enough space for hdr and \0 */
    int bufpos = 0, r;
    int exitcode = 0;

    assert(cmdc);

    while (1) {
        int n = read(cmdc->client_fd, buf+bufpos, ODS_SE_MAXLINE-bufpos+3);
        /* client closed pipe */
        if (n == 0) return;
        if (n == -1) { /* an error */
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return;
        }
        bufpos += n;
        r = extract_msg(buf, &bufpos, ODS_SE_MAXLINE, &exitcode, cmdc);
        if (r == -1) {
            ods_log_error("[%s] Error receiving message from client.", module_str);
            break;
        } else if (r == 1) {
            if (!client_exit(cmdc->client_fd, exitcode)) {
                ods_log_error("[%s] Error sending message to client.", module_str);
            }
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
    int err;
    sigset_t sigset;
    cmdhandler_type* cmdc = (cmdhandler_type*) arg;

    sigfillset(&sigset);
    if((err=pthread_sigmask(SIG_SETMASK, &sigset, NULL)))
        ods_fatal_exit("[%s] pthread_sigmask: %s", module_str, strerror(err));

    ods_log_debug("[%s] accept client %i", module_str, cmdc->client_fd);

    cmdc->dbconn = get_database_connection(cmdc->engine->dbcfg_list);
    if (!cmdc->dbconn) {
        client_printf_err(cmdc->client_fd, "Failed to open DB connection.\n");
        client_exit(cmdc->client_fd, 1);
        return NULL;
    }
    
    cmdhandler_handle_client_conversation(cmdc);
    if (cmdc->client_fd) {
        close(cmdc->client_fd);
    }
    db_connection_free(cmdc->dbconn);
    cmdc->stopped = 1;
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
        ods_log_error("[%s] unable to create: no socket filename", module_str);
        return NULL;
    }
    ods_log_assert(filename);
    ods_log_debug("[%s] create socket %s", module_str, filename);

    /* new socket */
    listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenfd < 0) {
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
    close(cmdhandler->listen_fd);
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
    int flags, connfd = 0, ret = 0;
    ssize_t thread_index = 0, i;
    cmdhandler_type cmdcs[MAX_CLIENT_CONN];

    ods_log_assert(cmdhandler);
    ods_log_assert(cmdhandler->engine);
    ods_log_debug("[%s] start", module_str);


    FD_ZERO(&rset);
    while (cmdhandler->need_to_exit == 0) {
        clilen = sizeof(cliaddr);
        FD_SET(cmdhandler->listen_fd, &rset);
        ret = select(cmdhandler->listen_fd+1, &rset, NULL, NULL, NULL);
        /* Don't handle new connections when need to exit, this
         * removes the delay of the self_pipe_trick*/

        /* Opportunistic join threads LIFO. */
        for (i = thread_index-1; i>0; i--) {
            if (!cmdcs[i].stopped) break;
            if (pthread_join(cmdcs[i].thread_id, NULL)) {
                break;
            }
            thread_index--;
        }

        if (cmdhandler->need_to_exit) break;
        if (ret < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                ods_log_warning("[%s] select() error: %s", module_str,
                   strerror(errno));
            }
            continue;
        }
        if (FD_ISSET(cmdhandler->listen_fd, &rset) &&
            thread_index < MAX_CLIENT_CONN)
        {
            connfd = accept(cmdhandler->listen_fd,
                (struct sockaddr *) &cliaddr, &clilen);
            if (connfd < 0) {
                if (errno != EINTR && errno != EWOULDBLOCK) {
                    ods_log_warning("[%s] accept error: %s", module_str,
                        strerror(errno));
                }
                continue;
            }
            /* Explicitely set to blocking, on BSD they would inherit
             * O_NONBLOCK from parent */
            flags = fcntl(connfd, F_GETFL, 0);
            if (flags < 0) {
                ods_log_error("[%s] unable to create, fcntl(F_GETFL) failed: %s",
                    module_str, strerror(errno));
                close(connfd);
                continue;
            }
            if (fcntl(connfd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
                ods_log_error("[%s] unable to create, fcntl(F_SETFL) failed: %s",
                    module_str, strerror(errno));
                close(connfd);
                continue;
            }
            /* client accepted, create new thread */
            cmdc = &cmdcs[thread_index];
            cmdc->stopped = 0;
            cmdc->listen_fd = cmdhandler->listen_fd;
            cmdc->client_fd = connfd;
            cmdc->listen_addr = cmdhandler->listen_addr;
            cmdc->engine = cmdhandler->engine;
            cmdc->need_to_exit = cmdhandler->need_to_exit;
            if (!pthread_create(&(cmdcs[thread_index].thread_id), NULL, &cmdhandler_accept_client,
                (void*) cmdc))
            {
                thread_index++;
            }
            ods_log_debug("[%s] %lu clients in progress...", module_str, thread_index);
        }
    }

    /* join threads LIFO. */
    for (i = thread_index-1; i>0; i--) {
        if (pthread_join(cmdcs[i].thread_id, NULL)) {
            break;
        }
    }

    ods_log_debug("[%s] done", module_str);
    cmdhandler->engine->cmdhandler_done = 1;
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
    if (sockfd < 0) {
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
            client_printf(sockfd, "");
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
    (void) pthread_join(engine->cmdhandler->thread_id, NULL);
}
