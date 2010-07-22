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
 * OpenDNSSEC signer engine client.
 *
 */

#include "config.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"

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

#define SE_CLI_CMDLEN 6

/**
 * Prints usage.
 *
 */
static void
usage(FILE* out)
{
    fprintf(out, "Usage: %s [<cmd>]\n", "ods-signer");
    fprintf(out, "Simple command line interface to control the signer "
                 "engine daemon.\nIf no cmd is given, the tool is going "
                 "to interactive mode.\n");
    fprintf(out, "\nBSD licensed, see LICENSE in source package for "
                 "details.\n");
    fprintf(out, "Version %s. Report bugs to <%s>.\n",
        PACKAGE_VERSION, PACKAGE_BUGREPORT);
}


/**
 * Return largest value.
 *
 */
static int
max(int a, int b)
{
    return a<b ? b : a;
}


/**
 * Interface.
 *
 */
static void
interface_run(FILE* fp, int sockfd, char* cmd)
{
    int maxfdp1 = 0;
    int stdineof = 0;
    int i = 0;
    int n = 0;
    int ret = 0;
    int cmd_written = 0;
    int cmd_response = 0;
    fd_set rset;
    char buf[ODS_SE_MAXLINE];

    stdineof = 0;
    FD_ZERO(&rset);
    for(;;) {
        /* prepare */
        if (stdineof == 0) {
            FD_SET(fileno(fp), &rset);
        }
        FD_SET(sockfd, &rset);
        maxfdp1 = max(fileno(fp), sockfd) + 1;

        if (!cmd || cmd_written) {
            /* interactive mode */
            ret = select(maxfdp1, &rset, NULL, NULL, NULL);
            if (ret < 0) {
                if (errno != EINTR && errno != EWOULDBLOCK) {
                    se_log_warning("interface select error: %s",
                        strerror(errno));
                }
                continue;
            }
        } else if (cmd) {
            /* passive mode */
            se_writen(sockfd, cmd, strlen(cmd));
            cmd_written = 1;
            stdineof = 1;
            continue;
        }

        if (cmd && cmd_written && cmd_response) {
            /* normal termination */
            return;
        }

        if (FD_ISSET(sockfd, &rset)) {
            /* clear buffer */
            for (i=0; i< ODS_SE_MAXLINE; i++) {
                buf[i] = 0;
            }

            /* socket is readable */
            if ((n = read(sockfd, buf, ODS_SE_MAXLINE)) == 0) {
                if (stdineof == 1) {
                    /* normal termination */
                    return;
                } else {
                    /* weird termination */
                    fprintf(stderr, "signer engine terminated "
                        "prematurely\n");
                    exit(1);
                }
            }

            if (cmd && strncmp(buf+n-SE_CLI_CMDLEN, "\ncmd> ", SE_CLI_CMDLEN) == 0) {
                /* we have the full response */
                if (n > SE_CLI_CMDLEN) {
                    ret = (int) write(fileno(stdout), buf, n-SE_CLI_CMDLEN);
                }
                cmd_response = 1;
                ret = 1;
            } else {
                /* we can expect more */
                ret = (int) write(fileno(stdout), buf, n);
            }

            /* error and shutdown handling */
            if (ret == 0) {
                fprintf(stderr, "no write\n");
            } else if (ret < 0) {
                fprintf(stderr, "write error: %s\n", strerror(errno));
            }
            if (se_strcmp(buf, ODS_SE_STOP_RESPONSE) == 0 || cmd_response) {
                fprintf(stderr, "\n");
                return;
            }
        }

        if (FD_ISSET(fileno(fp), &rset)) {
            /* input is readable */

            if (cmd && cmd_written) {
                /* passive mode */
                stdineof = 1;
                ret = shutdown(sockfd, SHUT_WR);
                if (ret != 0) {
                    fprintf(stderr, "shutdown failed: %s\n",
                        strerror(errno));
                    exit(1);
                }
                FD_CLR(fileno(fp), &rset);
                continue;
            }

            /* clear buffer */
            for (i=0; i< ODS_SE_MAXLINE; i++) {
                buf[i] = 0;
            }

            /* interactive mode */
            if ((n = read(fileno(fp), buf, ODS_SE_MAXLINE)) == 0) {
                stdineof = 1;
                ret = shutdown(sockfd, SHUT_WR);
                if (ret != 0) {
                    fprintf(stderr, "shutdown failed: %s\n",
                        strerror(errno));
                    exit(1);
                }
                FD_CLR(fileno(fp), &rset);
                continue;
            }
            if (strncmp(buf, "exit", 4) == 0 ||
                strncmp(buf, "quit", 4) == 0) {
                return;
            }
            se_str_trim(buf);
            n = strlen(buf);
            se_writen(sockfd, buf, n);
        }
    }
}


/**
 * Start interface
 *
 */
static void
interface_start(char* cmd)
{
    int sockfd, ret, flags;
    struct sockaddr_un servaddr;
    const char* servsock_filename = ODS_SE_SOCKFILE;

    /* new socket */
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd <= 0) {
        fprintf(stderr, "Unable to connect to engine. "
            "socket() failed: %s\n", strerror(errno));
        exit(1);
    }

    /* no suprises */
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strncpy(servaddr.sun_path, servsock_filename,
        sizeof(servaddr.sun_path) - 1);

    /* connect */
    ret = connect(sockfd, (const struct sockaddr*) &servaddr,
        sizeof(servaddr));
    if (ret != 0) {
        if (cmd && se_strcmp(cmd, "start\n") == 0) {
            ret = system(ODS_SE_ENGINE);
            return;
        }

        fprintf(stderr, "Unable to connect to engine: "
            "connect() failed: %s\n", strerror(errno));
        close(sockfd);
        exit(1);
    }

    /* set socket to non-blocking */
    flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        se_log_error("unable to start interface, fcntl(F_GETFL) "
            "failed: %s", strerror(errno));
        return;
    }
    flags |= O_NONBLOCK;
    if (fcntl(sockfd, F_SETFL, flags) < 0) {
        se_log_error("Unable to start interface, fcntl(F_SETFL) "
            "failed: %s", strerror(errno));
        return;
    }

    /* set stdin to non-blocking */
    flags = fcntl(fileno(stdin), F_GETFL, 0);
    if (flags < 0) {
        se_log_error("Unable to start interface, fcntl(F_GETFL) "
            "failed: %s", strerror(errno));
        return;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fileno(stdin), F_SETFL, flags) < 0) {
        se_log_error("Unable to start interface, fcntl(F_SETFL) "
            "failed: %s", strerror(errno));
        return;
    }

    /* some sort of interface */
    if (!cmd) {
        fprintf(stderr, "cmd> ");
    }

    /* run */
    se_log_init(NULL, 0, 0);
    interface_run(stdin, sockfd, cmd);
}


/**
 * Main. start interface tool.
 *
 */
int
main(int argc, char* argv[])
{
    int c;
    int options_size = 0;
    const char* options[sizeof(argv)];
    char* cmd = NULL;

    /* command line options */
    for (c = 0; c < argc; c++) {
        options[c] = argv[c];
        if (c > 0) {
            options_size += strlen(argv[c]) + 1;
        }
    }
    if (argc > 1) {
        cmd = (char*) se_calloc(options_size+2,sizeof(char));
        (void)strncpy(cmd, "", 0);
        for (c = 1; c < argc; c++) {
            (void)strncat(cmd, options[c], strlen(options[c]));
            (void)strncat(cmd, " ", 1);
        }
        cmd[options_size-1] = '\n';
    }

    /* main stuff */
    if (cmd && se_strcmp(cmd, "-h\n") == 0) {
        usage(stdout);
        return 0;
    } else if (cmd && se_strcmp(cmd, "--help\n") == 0) {
        usage(stdout);
        return 0;
    }

    interface_start(cmd);

    /* done */
    if (cmd) {
        se_free((void*)cmd);
    }
    return 0;
}
