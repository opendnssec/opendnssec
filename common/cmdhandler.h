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

#ifndef DAEMON_CMDHANDLER_H
#define DAEMON_CMDHANDLER_H

#include "config.h"
#include <sys/un.h>

typedef struct cmdhandler_struct cmdhandler_type;

#include "janitor.h"

typedef struct cmdhandler_ctx_struct {
    int sockfd;
    void* globalcontext;
    void* localcontext;
    cmdhandler_type* cmdhandler;
} cmdhandler_ctx_type;

struct cmd_func_block {
    /* Name of command */
    const char* cmdname;
    /* print usage information */
    void (*usage)(int sockfd);
    /* print help, more elaborate than usage. Allowed to be
     * NULL to indicate no help is available */
    void (*help)(int sockfd);
    /* 1 if module claims responsibility for command
     * 0 otherwise */
    int (*handles)(const char *cmd);
    /** Run the handler
     * 
     * \param sockfd, pipe to client,
     * \param ctx, the client context
     * \param cmd, command and args for additional parsing null terminated
     * \param dbconn, connection to the database.
     * \return 0 command executed, all OK
     *      -1 Errors parsing commandline / missing params
     *       positive error code to return to user.
     */
    int (*run)(int sockfd, cmdhandler_ctx_type*, char *cmd);
};

struct cmdhandler_struct {
    struct sockaddr_un listen_addr;
    janitor_thread_t thread_id;
    int listen_fd;
    int need_to_exit;
    int stopped;
    struct cmd_func_block** commands;
    void* globalcontext;
    void* (*createlocalcontext)(void*);
    void  (*destroylocalcontext)(void*);
};

/**
 * Create command handler.
 * \param[in] filename socket file name
 * \return cmdhandler_type* created command handler
 *
 */
cmdhandler_type* cmdhandler_create(const char* filename, struct cmd_func_block** functions, void* globalcontext, void*(*createlocalcontext)(void*globalcontext),void(*destroylocalcontext)(void*localcontext));

/**
 * Cleanup command handler.
 * \param[in] cmdhandler command handler
 *
 */
void cmdhandler_cleanup(cmdhandler_type* cmdhandler);

/**
 * Start command handler.
 * \param[in] cmdhandler_type* command handler
 *
 */
void cmdhandler_start(cmdhandler_type* cmdhandler);
void cmdhandler_stop(cmdhandler_type* cmdhandler);

/**
 * Print usage of all known commands to file descriptor
 * 
 * \param[in] sockfd, file descriptor to print to.
 * 
 */
void cmdhandler_get_usage(int sockfd, cmdhandler_type* cmdc);

/**
 * Retrieve function block responsible for cmd
 * 
 * Loops over all known commands, first command to claim to be 
 * responsible will have its function block returned. If not claimed
 * return NULL.
 * 
 * \param[in] cmd, command to look for
 * \param[in] n, length of cmd string.
 * \return function block or NULL
 */
struct cmd_func_block* get_funcblock(const char *cmd, cmdhandler_type* cmdc);

/**
 * Compare commandline with command, return arguments if found.
 *
 * \param[in] cmd, commandline to test
 * \param[in] scmd, command to look for
 * \return Pointer to arguments within cmd. NULL if scmd not found.
 */
const char *ods_check_command(const char *cmd, const char *scmd);

#endif /* DAEMON_CMDHANDLER_H */
