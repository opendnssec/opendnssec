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
 * OpenDNSSEC enforcer engine client.
 *
 */

#include "config.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"

#include <errno.h>
#include <fcntl.h> /* fcntl() */
#include <stdio.h> /* fprintf() */
#include <string.h> /* strerror(), strncmp(), strlen(), strcpy(), strncat() */
#include <strings.h> /* bzero() */
#include <sys/select.h> /* select(), FD_ZERO(), FD_SET(), FD_ISSET(), FD_CLR() */
#include <sys/socket.h> /* socket(), connect(), shutdown() */
#include <sys/un.h>
#include <unistd.h> /* exit(), read(), write() */

/* According to earlier standards, we need sys/time.h, sys/types.h, unistd.h for select() */
#include <sys/types.h>
#include <sys/time.h>

/* cmd history */
#include <stdlib.h>
#include <readline/readline.h>
#include <readline/history.h>

static const char* cli_str = "client";

/**
 * Prints usage.
 *
 */
static void
usage(FILE* out)
{
    fprintf(out, "Usage: %s [<cmd>]\n", "ods-enforcer");
    fprintf(out, "Simple command line interface to control the enforcer "
                 "engine daemon.\nIf no cmd is given, the tool is going "
                 "to interactive mode.\nWhen the daemon is running "
                 "'ods-enforcer help' gives a full list of available commands.\n");
    fprintf(out, "\nBSD licensed, see LICENSE in source package for "
                 "details.\n");
    fprintf(out, "Version %s. Report bugs to <%s>.\n",
        PACKAGE_VERSION, PACKAGE_BUGREPORT);
}


/**
 * Interface.
 *
 * fp: stdin
 * sockfd: pipe to daemon
 * cmd: command line args, may be NULL;
 */
static int
interface_run(int sockfd, char* cmd)
{
    int written, n = 0, ret = 0, sockeof = 0;
    fd_set rset;
    char buf[ODS_SE_MAXLINE];

    ods_writen(sockfd, cmd, strlen(cmd)+1);
    FD_ZERO(&rset);
    while (!sockeof) {
        FD_SET(sockfd, &rset); /* pipe */
        ret = select(sockfd + 1, &rset, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                ods_log_warning("[%s] interface select error: %s",
                    cli_str, strerror(errno));
            }
            continue;
        }
        if (FD_ISSET(sockfd, &rset)) {
            /* socket is readable */
            memset(buf, 0, ODS_SE_MAXLINE);
            n = read(sockfd, buf, ODS_SE_MAXLINE);
            if (n == 0) {
                /* daemon closed connection */
                sockeof = 1;
                printf("\n");
            } else if (n < 0) {
                fprintf(stderr, "error reading pipe: %s\n", strerror(errno));
                rl_callback_handler_remove();
                return 1; /* indicates error */
            }
            /* now write what we have to stdout */
            for (written = 0, ret = 0; written < n; written += ret) {
                ret = (int) write(fileno(stdout), buf+written, n-written);
                if (ret < 0) {
                    if (errno == EINTR || errno == EWOULDBLOCK) {
                        ret = 0;
                        continue; /* try again... */
                    }
                    fprintf(stderr, "error writing to stdout: %s\n", 
                        strerror(errno));
                    return 1; /*  */
                }
            }
        }
    }
    return 0;
}


/**
 * Start interface
 *
 * char *cmd: command to exec, NULL for interactive mode
 */
static int
interface_start(char* cmd_arg)
{
    int sockfd, ret, flags, n;
    struct sockaddr_un servaddr;
    const char* servsock_filename = OPENDNSSEC_ENFORCER_SOCKETFILE;
    char* icmd = NULL; /* interactive commands*/
    char* cmd;
    int keep_running = 1;
    
    ods_log_init(NULL, 0, 0);

    while (keep_running) {
        /* read user input */
        if (!cmd_arg) {
            icmd = readline("cmd> ");
            if (!icmd) { /* eof */
                printf("\n");
                break;
            }
            ods_str_trim(icmd);
            n = strlen(icmd)+1;/* include terminator */
            if (icmd[0]!=0) add_history(icmd);
            
            if (n >= 5 && (strncmp(icmd, "exit", 4) == 0 ||
                strncmp(icmd, "quit", 4) == 0)) {
                break;
            }
            cmd = icmd;
        } else {
            cmd = cmd_arg;
            keep_running = 0;
        }
        /* Now we know what to say, open socket */
        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd <= 0) {
            fprintf(stderr, "Unable to connect to engine. "
                "socket() failed: %s (\"%s\")\n", strerror(errno), servsock_filename);
            return 1;
        }

        /* no suprises */
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sun_family = AF_UNIX;
        strncpy(servaddr.sun_path, servsock_filename, sizeof(servaddr.sun_path) - 1);
        ret = connect(sockfd, (const struct sockaddr*) &servaddr, sizeof(servaddr));
        if (ret != 0) {
            if (cmd && ods_strcmp(cmd, "start") == 0) {
                system(ODS_EN_ENGINE);
            } else if (cmd && ods_strcmp(cmd, "running") == 0) {
                fprintf(stderr, "Engine not running.\n");
            } else {
                fprintf(stderr, "Unable to connect to engine. "
                "connect() failed: %s (\"%s\")\n"
                "Is ods-enforcerd running?\n", strerror(errno), servsock_filename);
            }
            close(sockfd);
            continue;
        }
        /* set socket to non-blocking */
        flags = fcntl(sockfd, F_GETFL, 0);
        if (flags < 0) {
            ods_log_error("[%s] unable to start interface, fcntl(F_GETFL) "
                "failed: %s", cli_str, strerror(errno));
            close(sockfd);
            return 1;
        }
        flags |= O_NONBLOCK;
        if (fcntl(sockfd, F_SETFL, flags) < 0) {
            ods_log_error("[%s] unable to start interface, fcntl(F_SETFL) "
                "failed: %s", cli_str, strerror(errno));
            close(sockfd);
            return 1;
        }

        if (cmd_arg) {
            interface_run(sockfd, cmd);
            break;
        } else {
            ret = interface_run(sockfd, cmd);
            free(icmd);
            if (ret) break;  /* error case */
        }
        close(sockfd);
    }
    return 0;
}


/**
 * Main. start interface tool.
 *
 */
int
main(int argc, char* argv[])
{
    char* cmd = NULL;
    int ret = 0;
    allocator_type* clialloc = allocator_create(malloc, free);
    if (!clialloc) {
        fprintf(stderr,"error, malloc failed for client\n");
        exit(1);
    }
    
    /*  concat arguments an add 1 extra char for 
        adding '\n' char later on, but only when argc > 1 */
    if (argc > 1) {
        cmd = ods_str_join(clialloc, argc-1, &argv[1], ' ');
        if (!cmd) {
            fprintf(stderr, "memory allocation failed\n");
            exit(1);
        }
    }

    /* main stuff */
    if (cmd && (ods_strcmp(cmd, "-h") == 0 || ods_strcmp(cmd, "--help") == 0)) {
        usage(stdout);
        ret = 1;
    } else {
        ret = interface_start(cmd);
    }

    /* done */
    allocator_deallocate(clialloc, (void*) cmd);
    allocator_cleanup(clialloc);
    return ret;
}
