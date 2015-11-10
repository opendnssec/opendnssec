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

#include <sys/un.h>
#include "scheduler/schedule.h"
#include "db/db_connection.h"

/* Max number of not accepted connections before starting to drop. */
#define ODS_SE_MAX_HANDLERS 5

struct engine_struct;
struct client_conn;

typedef struct cmdhandler_struct cmdhandler_type;
struct cmdhandler_struct {
    struct engine_struct* engine;
    struct sockaddr_un listen_addr;
    pthread_t thread_id;
    int listen_fd;
    int client_fd;
    int need_to_exit;
    int stopped;
    db_connection_t* dbconn;
};

struct cmd_func_block {
    /* Name of command */
    const char* cmdname;
    /* print usage information */
    void (*usage)(int sockfd);
    /* print help, more elaborate than usage. Allowed to be
     * NULL to indicate no help is available */
    void (*help)(int sockfd);
    /* 1 if module claims responibility for command
     * 0 otherwise */
    int (*handles)(const char *cmd, ssize_t n);
    /** Run the handler
     * 
     * \param sockfd, pipe to client,
     * \param engine, daemon information must not be NULL.
     * \param cmd, command and args for additional parsing.
     * \param n, length of cmd.
     * \param dbconn, connection to the database.
     * \return 0 command executed, all OK
     *      -1 Errors parsing commandline / missing params
     *       positive error code to return to user.
     */
    int (*run)(int sockfd, struct engine_struct* engine,
        const char *cmd, ssize_t n, db_connection_t *dbconn);
};

/**
 * Create command handler.
 * \param[in] filename socket file name
 * \return cmdhandler_type* created command handler
 *
 */
cmdhandler_type* cmdhandler_create(const char* filename);

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
void cmdhandler_stop(struct engine_struct* engine);

/**
 * Print usage of all known commands to file descriptor
 * 
 * \param[in] sockfd, file descriptor to print to.
 * 
 */
void cmdhandler_get_usage(int sockfd);

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
struct cmd_func_block* get_funcblock(const char *cmd, ssize_t n);

#endif /* DAEMON_CMDHANDLER_H */
