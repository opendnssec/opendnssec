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
 * OpenDNSSEC enforcer engine client.
 *
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h> /* fcntl() */
#include <stdio.h> /* fprintf() */
#include <string.h> /* strerror(), strncmp(), strlen(), strcpy(), strncat() */
#include <strings.h> /* bzero() */
#include <sys/select.h> /* select(), FD_ZERO(), FD_SET(), FD_ISSET(), FD_CLR() */
#include <sys/socket.h> /* socket(), connect(), shutdown() */
#include <sys/un.h>
#include <unistd.h> /* exit(), read(), write() */
#include <getopt.h>
/* According to earlier standards, we need sys/time.h, sys/types.h, unistd.h for select() */
#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <assert.h>
#ifdef HAVE_READLINE
    /* cmd history */
    #include <readline/readline.h>
    #include <readline/history.h>
#endif

#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "daemon/clientpipe.h"

static const char* PROMPT = "cmd> ";
static const char* cli_str = "client";

/**
 * Prints usage.
 *
 */
static void
usage(FILE* out)
{
    fprintf(out, "Usage: %s [options] [cmd]\n", "ods-enforcer");
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
 * Consume messages in buffer
 * 
 * Read all complete messages in the buffer or until EXIT message 
 * is read. Messages larger than ODS_SE_MAXLINE can be handled but
 * will be truncated.
 * 
 * \param buf: buffer to read from.
 * \param pos: length of valid data in buffer, must never exeed buflen.
 * \param buflen: Capacity of buf, must not exeed ODS_SE_MAXLINE.
 * \param exitcode[out]: Return code from the daemon, only valid
 *                       when returned 1
 * \return: -1 An error occured
 *           1 daemon done handling command, exitcode is set,
 *           0 otherwise 
 */
/* return 0 or (1 and exit code set) or -1*/
static int
extract_msg(char* buf, int *pos, int buflen, int *exitcode, int sockfd)
{
    char data[ODS_SE_MAXLINE+1], opc;
    int datalen;
    
    assert(*pos <= buflen);
    assert(ODS_SE_MAXLINE >= buflen);
    
    while (1) {
        /* Do we have a complete header? */
        if (*pos < 3) return 0;
        opc = buf[0];
        datalen = (buf[1]<<8) | (buf[2]&0xFF);
        if (datalen+3 <= *pos) {
            /* a complete message */
            memset(data, 0, ODS_SE_MAXLINE+1);
            memcpy(data, buf+3, datalen);
            *pos -= datalen+3;
            memmove(buf, buf+datalen+3, *pos);
          
            if (opc == CLIENT_OPC_EXIT) {
                fflush(stdout);
                if (datalen != 1) return -1;
                *exitcode = (int)buf[3];
                return 1;
            }
            switch (opc) {
                case CLIENT_OPC_STDOUT:
                    fprintf(stdout, "%s", data);
                    break;
                case CLIENT_OPC_STDERR:
                    fprintf(stderr, "%s", data);
                    break;
                case CLIENT_OPC_PROMPT:
                    fprintf(stdout, "%s", data); 
                    fflush(stdout);
                    /* listen for input here */
                    if (!client_handleprompt(sockfd)) {
                        fprintf(stderr, "\n");
                        *exitcode = 300;
                        return 1;
                    }
            }
            continue;
        } else if (datalen+3 > buflen) {
            /* Message is not going to fit! Discard the data already 
             * received */
            fprintf(stderr, "Daemon message to big, truncating.\n");
            datalen -= *pos - 3;
            buf[1] = datalen >> 8;
            buf[2] = datalen & 0xFF;
            *pos = 3;
            return 0;
        }
        return 0; /* waiting for more data */
    }
}

/**
 * Start interface - Set up connection and handle communication
 *
 * \param cmd: command to exec, NULL for interactive mode.
 * \param ervsock_filename: name of pipe to connect to daemon.
 * \return exit code for client
 */
static int
interface_start(const char* cmd, const char* servsock_filename)
{
    struct sockaddr_un servaddr;
    fd_set rset;
    int sockfd, flags, exitcode = 0;
    int ret, n, r, error = 0, inbuf_pos = 0;
    char userbuf[ODS_SE_MAXLINE], inbuf[ODS_SE_MAXLINE];

    /* Create a socket */
    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Socket creation failed: %s\n", strerror(errno));
        return 200;
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strncpy(servaddr.sun_path, servsock_filename, sizeof(servaddr.sun_path) - 1);
    
    if (connect(sockfd, (const struct sockaddr*) &servaddr, sizeof(servaddr)) == -1) {
        if (cmd) {
            if (strncmp(cmd, "start", 5) == 0) {
                return system(ODS_EN_ENGINE);
            } else if (strcmp(cmd, "running\n") == 0) {
                fprintf(stdout, "Engine not running.\n");
                return 209;
            }
        }
        fprintf(stderr, 
            "Unable to connect to engine. connect() failed: "
            "%s (\"%s\")\n", strerror(errno), servsock_filename);
        return 201;
    }
    /* set socket to non-blocking */
    if ((flags = fcntl(sockfd, F_GETFL, 0)) == -1) {
        ods_log_error("[%s] unable to start interface, fcntl(F_GETFL) "
            "failed: %s", cli_str, strerror(errno));
        close(sockfd);
        return 202;
    } else if (fcntl(sockfd, F_SETFL, flags|O_NONBLOCK) == -1) {
        ods_log_error("[%s] unable to start interface, fcntl(F_SETFL) "
            "failed: %s", cli_str, strerror(errno));
        close(sockfd);
        return 203;
    }
    
    /* If we have a cmd send it to the daemon, otherwise display a
     * prompt */
    if (cmd) client_stdin(sockfd, cmd, strlen(cmd)+1);
    do {
        if (!cmd) {
#ifdef HAVE_READLINE
            char *icmd_ptr;
            if ((icmd_ptr = readline(PROMPT)) == NULL) { /* eof */
                printf("\n");
                break;
            }
            strcpy(userbuf, icmd_ptr);
            free(icmd_ptr);
            ods_str_trim(userbuf);
            if (strlen(userbuf) > 0) add_history(userbuf);
#else        
            fprintf(stdout, "%s", PROMPT);
            fflush(stdout);
            n = read(fileno(stdin), userbuf, ODS_SE_MAXLINE);
            if (n == 0) { /* eof */
                printf("\n");
                break;
            } else if (n == -1) {
                error = 205;
                break;
            }
            userbuf[n] = 0;
            ods_str_trim(userbuf);
#endif
            if (strlen(userbuf) == 0) continue;
            client_stdin(sockfd, userbuf, strlen(userbuf));
        }
        while (1) {
            /* Clean the readset and add the pipe to the daemon */
            FD_ZERO(&rset);
            FD_SET(sockfd, &rset);
        
            ret = select(sockfd+1, &rset, NULL, NULL, NULL);
            if (ret < 0) {
                /* *SHRUG* just some interrupt*/
                if (errno == EINTR) continue;
                /* anything else is an actual error */
                perror("select()");
                error = 204;
                break;
            }
            /* Handle data coming from the daemon */
            if (FD_ISSET(sockfd, &rset)) { /*daemon pipe is readable*/
                n = read(sockfd, inbuf+inbuf_pos, ODS_SE_MAXLINE-inbuf_pos);
                if (n == 0) { /* daemon closed pipe */
                    fprintf(stderr, "[Remote closed connection]\n");
                    error = 206;
                    break;
                } else if (n == -1) { /* an error */
                    if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                    perror("read()");
                    error = 207;
                    break;
                }
                inbuf_pos += n;
                r = extract_msg(inbuf, &inbuf_pos, ODS_SE_MAXLINE, &exitcode, sockfd);
                if (r == -1) {
                    fprintf(stderr, "Error handling message from daemon\n");
                    error = 208;
                    break;
                } else if (r == 1) {
                    if (cmd) 
                        error = exitcode;
                    else /* we are interactive so print response */
                        fprintf(stderr, "Daemon exit code: %d\n", exitcode);
                    break;
                }
            }
        }
    } while (error == 0 && !cmd);
    close(sockfd);
#ifdef HAVE_READLINE
    clear_history();
    rl_free_undo_list();
#endif
    return error;
}

/**
 * Main. start interface tool.
 */
int
main(int argc, char* argv[])
{
    char* cmd = NULL;
    int error, c, options_index = 0, i, argopc;
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        { 0, 0, 0, 0}
    };
    
    ods_log_init(NULL, 0, 0);
    
    /* Find out how many args are for the client. This may need
     * improvement in the future in case the client want to support
     * options with args. */
    argopc = argc;
    for (i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            argopc = i;
            break;
        }
    }

    /* parse the commandline */
    while ((c=getopt_long(argopc, argv, "h",
        long_options, &options_index)) != -1) {
        switch (c) {
            case 'h':
                usage(stdout);
                exit(0);
            default:
                /* unrecognized options 
                 * getopt will report an error */
                exit(100);
        }
    }
    argc -= optind;
    argv += optind;
    if (argc != 0) 
        cmd = ods_strcat_delim(argc, argv, ' ');
    error = interface_start(cmd, OPENDNSSEC_ENFORCER_SOCKETFILE);
    free(cmd);
    return error;
}
