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
#include <syslog.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <unistd.h>
/* According to earlier standards: select() sys/time.h sys/types.h unistd.h */
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "file.h"
#include "str.h"
#include "locks.h"
#include "log.h"
#include "status.h"
#include "util.h"
#include "clientpipe.h"
#include "cmdhandler.h"
#include "longgetopt.h"

static char const * module_str = "cmdhandler";

static struct cmd_func_block*
findcommand(const char *arg, int argc, char* argv[], int argi, struct cmd_func_block** commands, void* user)
{
    const char* cmdname;
    struct cmd_func_block* command = NULL;

    for(int i=0; commands[i]; i++) {
        cmdname = commands[i]->name;
        int match = 1;
        int ncmdwords = 0;
        if(commands[i]->handles) {
            match = commands[i]->handles(arg);
        } else if(commands[i]->names) {
            while(match && commands[i]->names[ncmdwords]) {
                if(strcmp(argv[argi+ncmdwords], commands[i]->names[ncmdwords])) {
                    match = 0;
                    break;
                } else if(argi+ncmdwords >= argc) {
                    match = 0;
                    break;
                } else
                    ++ncmdwords;
            }
        } else {
            while(match && *cmdname && argi+ncmdwords < argc) {
                char* nextcmdname = strchr(cmdname,' ');
                if(nextcmdname) {
                    if(strncmp(argv[argi+ncmdwords], cmdname, nextcmdname-cmdname) || argv[argi+ncmdwords][nextcmdname-cmdname]==' ') {
                        match = 0;
                        break;
                    } else if(argi+ncmdwords >= argc) {
                        match = 0;
                        break;
                    } else {
                        cmdname = strchr(cmdname,' ') + 1;
                        ++ncmdwords;
                    }
                } else {
                    if(strcmp(argv[argi+ncmdwords], cmdname)) {
                        match = 0;
                        break;
                    } else {
                        cmdname = "";
                        ++ncmdwords;
                    }
                }
            }
            if(match && *cmdname)
                match = 0;
        }
        if(match) {
            command = commands[i];
            argi += ncmdwords;
            break;
        }
    }
    return command;
}

static struct option genericoptions[] = {
    { NULL,        0, NULL, 0   }
};

static int
cmdhandler_perform_command(const char *arg, struct cmdhandler_ctx_struct* context)
{
    struct cmd_func_block** commands = context->cmdhandler->commands;
    void* user = NULL;
    char** errormessageptr = NULL;

    int status = 0;
    char* statusstr = NULL;
    int help = 0;;
    int version = 0;
    int opt;
    int longindex;
    int argc;
    char** argv;
    int argi;
    struct longgetopt optctx;
    struct cmd_func_block* command = NULL;

    int verbosity = 0;

    if (strlen(arg) == 0)
        return 0;
    strtoargs(arg, &argc, &argv);
    for(opt = longgetopt(argc, argv, "+vh", genericoptions, &longindex, &optctx); opt != -1;
        opt = longgetopt(argc, argv, NULL,  genericoptions, &longindex, &optctx)) {
        switch(opt) {
            case 'v':
                ++verbosity;
                break;
            case 1: // --verbosity
                verbosity = atoi(optctx.optarg);
                break;
            case 'h':
                help = 1;
                break;
            case 2: // --version
                version = 1;
                break;
        }
    }
    argi = optctx.optind;
    if(!help && !version) {
        if (argi >= argc) {
            asprintf(&statusstr, "unknown generic arguments");
        }
        if(!strcmp(argv[argi], "help")) {
            help = 1;
        } else if(!strcmp(argv[argi], "version")) {
            version = 1;
        }
    }
    if(help) {
        for(int i=0; commands[i]; i++)
            if(commands[i]->name && !strcmp("help",commands[i]->name)) {
                command = commands[i];
                break;
            }
    } else if(version) {
        for(int i=0; commands[i]; i++)
            if(commands[i]->name && !strcmp("version",commands[i]->name)) {
                command = commands[i];
                break;
            }
    } else {
        command = findcommand(arg, argc, argv, argi, commands, user);
    }
    if(command) {
        if(command->runargs) {
            status = command->runargs(context, argc-argi, &argv[argi]);
        } else {
            char *buf;
            if (!(buf = strdup(arg))) {
                asprintf(&statusstr, "memory error");
                return 1;
            }
            status = command->runarg(context, buf);
            if (status == -1) {
                /* Syntax error, print usage for cmd */
                if(!statusstr)
                    asprintf(&statusstr, "Error parsing arguments %s command line %s", command->name, arg);
            }
            free(buf);
        }
        if (status == -1) {
            /* Syntax error, print usage for cmd */
            client_printf_err(context->sockfd, "Error parsing arguments %s command line %s\n",
                command->name, arg);
            if (command->usage != NULL) {
                client_printf(context->sockfd, "Usage:\n\n");
                command->usage(context->sockfd);
            }
        }
    } else {
        client_printf_err(context->sockfd, "Unknown command %s\n", argv[argi]);
        /* Unhandled command, print general error */
        if(!strcmp(argv[argi], "help")) {
            if(argi+1<argc) {
                command = findcommand(arg, argc, argv, argi+1, commands, user);
                if(command) {
                    if(command->help) {
                        status = 0;
                        client_printf(context->sockfd, "Usage:\n");
                        command->usage(context->sockfd);
                        client_printf(context->sockfd, "\nHelp:\n");
                        command->help(context->sockfd);
                    } else if(command->usage) {
                        status = 0;
                        client_printf(context->sockfd, "Usage:\n");
                        command->usage(context->sockfd);
                    } else {
                        status = 1;
                        asprintf(&statusstr, "no help for command  %s.", arg);
                    }
                } else {
                    client_printf(context->sockfd, "Help: command '%s' unknown. Type 'help' without arguments to get a list of supported commands.\n", argv[argi+1]);                    
                }
            } else {
                status = 0;
                for(int i=0; commands[i]; i++) {
                    if(commands[i]->usage)
                        commands[i]->usage(context->sockfd);
                }
            }
        } else {
            status = 1;
            asprintf(&statusstr, "Unknown command %s.", arg);
            for(int i=0; commands[i]; i++) {
                if(commands[i]->usage)
                    commands[i]->usage(context->sockfd);
            }
        }
        goto exit;
    }

  exit:
    free(argv);
    if(errormessageptr) {
        *errormessageptr = statusstr;
    } else if(statusstr) {
        fprintf(stderr,"%s\n",statusstr);
        free(statusstr);
    }
    return status;
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
extract_msg(char* buf, int *pos, int buflen, int *exitcode, struct cmdhandler_ctx_struct* context)
{
    char data[ODS_SE_MAXLINE+1], opc;
    uint16_t datalen;
    
    assert(exitcode);
    assert(buf);
    assert(pos);
    assert(*pos <= buflen);
    assert(ODS_SE_MAXLINE >= buflen);
    
    while (1) {
        if (*pos < 3) return 0;
        opc = buf[0];

        /* Do a memcpy instead of a cast in order to not break memory alignment
         * requirements on some targets. */
        memcpy(&datalen, &buf[1], 2);
        datalen = ntohs(datalen);

        if (datalen+3 <= *pos) {
            /* a complete message */
            memset(data, 0, ODS_SE_MAXLINE+1);
            memcpy(data, buf+3, datalen);
            *pos -= datalen+3;
            memmove(buf, buf+datalen+3, *pos);
            ods_str_trim(data, 0);

            if (opc == CLIENT_OPC_STDIN) {
                *exitcode = cmdhandler_perform_command(data, context);
                return 1;
            }
        } else if (datalen+3 > buflen) {
            /* Message is not going to fit! Discard the data already recvd */
            ods_log_error("[%s] Message received to big, truncating.", module_str);
            datalen -= *pos - 3;

            /* Do a memcpy instead of a cast in order to not break memory
             * alignment requirements on some targets. */
            datalen = htons(datalen);
            memcpy(&buf[1], &datalen, 2);

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
cmdhandler_handle_client_conversation(struct cmdhandler_ctx_struct* context)
{
    char buf[ODS_SE_MAXLINE+4]; /* enough space for hdr and \0 */
    int bufpos, r, numread;
    int exitcode = 0;

    bufpos = 0;
    for (;;) {
        numread = read(context->sockfd, &buf[bufpos], ODS_SE_MAXLINE - bufpos + 3);
        if (numread == 0) {
            /* client closed pipe */
            break;
        } else if (numread < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            } else if (errno == ECONNRESET) {
                ods_log_debug("[%s] done handling client: %s", module_str, strerror(errno));
                break;
            } else {
                /* error occured */
                ods_log_error("[%s] read error: %s", module_str, strerror(errno));
                break;
            }
        } else {
            bufpos += numread;
            r = extract_msg(buf, &bufpos, ODS_SE_MAXLINE, &exitcode, context);
            if (r == -1) {
                ods_log_error("[%s] Error receiving message from client.", module_str);
                break;
            } else if (r == 1) {
                if (!client_exit(context->sockfd, exitcode)) {
                    ods_log_error("[%s] Error sending message to client.", module_str);
                }
            }
        }
    }
}

/**
 * Accept client.
 *
 */
static void
cmdhandler_accept_client(void* arg)
{
    int err;
    cmdhandler_ctx_type* context = (cmdhandler_ctx_type*) arg;

    ods_log_debug("[%s] accept client %i", module_str, context->sockfd);

    if (context->cmdhandler->createlocalcontext) {
        context->localcontext = context->cmdhandler->createlocalcontext(context->globalcontext);
        if (!context->localcontext) {
            client_printf_err(context->sockfd, "Failed to open DB connection.\n");
            client_exit(context->sockfd, 1);
            return;
        }
    }

    cmdhandler_handle_client_conversation(context);
    if (context->sockfd) {
        shutdown(context->sockfd, SHUT_RDWR);
        close(context->sockfd);
    }
    if (context->cmdhandler->destroylocalcontext) {
        context->cmdhandler->destroylocalcontext(context->localcontext);
    }
    free(context);
}

/**
 * Create command handler.
 *
 */
cmdhandler_type*
cmdhandler_create(const char* filename, struct cmd_func_block** commands, void* globalcontext, void*(*createlocalcontext)(void*globalcontext),void(*destroylocalcontext)(void*localcontext))
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
    /* new socket */
    ods_log_debug("[%s] create socket %s", module_str, filename);
    listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenfd < 0) {
        ods_log_error("[%s] unable to create cmdhandler: socket() failed: %s", module_str, strerror(errno));
        return NULL;
    }
    /* set it to non-blocking */
    flags = fcntl(listenfd, F_GETFL, 0);
    if (flags < 0) {
        ods_log_error("[%s] unable to create cmdhandler: fcntl(F_GETFL) failed: %s", module_str, strerror(errno));
        close(listenfd);
        return NULL;
    }
    flags |= O_NONBLOCK;
    if (fcntl(listenfd, F_SETFL, flags) < 0) {
        ods_log_error("[%s] unable to create cmdhandler: fcntl(F_SETFL) failed: %s", module_str, strerror(errno));
        close(listenfd);
        return NULL;
    }
    if (filename) {
        (void)unlink(filename);
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strncpy(servaddr.sun_path, filename, sizeof(servaddr.sun_path) - 1);
#ifdef HAVE_SOCKADDR_SUN_LEN
    servaddr.sun_len = strlen(servaddr.sun_path);
#endif
    /* bind and listen... */
    ret = bind(listenfd, (const struct sockaddr*) &servaddr, sizeof(struct sockaddr_un));
    if (ret != 0) {
        ods_log_error("[%s] unable to create cmdhandler: bind() failed: %s", module_str, strerror(errno));
        close(listenfd);
        return NULL;
    }
    ret = listen(listenfd, 5);
    if (ret != 0) {
        ods_log_error("[%s] unable to create cmdhandler: listen() failed: %s", module_str, strerror(errno));
        close(listenfd);
        return NULL;
    }
    CHECKALLOC(cmdh = (cmdhandler_type*) malloc(sizeof(cmdhandler_type)));
    cmdh->listen_fd = listenfd;
    cmdh->listen_addr = servaddr;
    cmdh->need_to_exit = 0;
    cmdh->stopped = 0;
    cmdh->commands = commands;
    cmdh->globalcontext = globalcontext;
    cmdh->createlocalcontext = createlocalcontext;
    cmdh->destroylocalcontext = destroylocalcontext;
    return cmdh;
}

/**
 * Cleanup command handler.
 *
 */
void
cmdhandler_cleanup(cmdhandler_type* cmdhandler)
{
    if (cmdhandler) {
        if (cmdhandler->listen_fd >= 0)
            close(cmdhandler->listen_fd);
        free(cmdhandler);
    }
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
    cmdhandler_ctx_type* cmdclient;
    janitor_thread_t cmdclientthread;
    fd_set rset;
    int flags, connfd = 0, ret = 0;
    ssize_t i;

    ods_log_assert(cmdhandler);
    ods_log_debug("[%s] start", module_str);

    FD_ZERO(&rset);
    while (cmdhandler->need_to_exit == 0) {
        clilen = sizeof(cliaddr);
        FD_SET(cmdhandler->listen_fd, &rset);
        ret = select(cmdhandler->listen_fd+1, &rset, NULL, NULL, NULL);
        /* Don't handle new connections when need to exit, this
         * removes the delay of the self_pipe_trick*/

        /* Opportunistic join threads LIFO. */
        janitor_thread_tryjoinall(cmdhandlerthreadclass);

        if (cmdhandler->need_to_exit) break;
        if (ret < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                ods_log_warning("[%s] select() error: %s", module_str,
                   strerror(errno));
            }
            continue;
        }
        if (FD_ISSET(cmdhandler->listen_fd, &rset)) {
            connfd = accept(cmdhandler->listen_fd, (struct sockaddr *) &cliaddr, &clilen);
            if (connfd < 0) {
                if (errno != EINTR && errno != EWOULDBLOCK) {
                    ods_log_warning("[%s] accept() error: %s", module_str, strerror(errno));
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
            cmdclient = malloc(sizeof(cmdhandler_ctx_type));
            cmdclient->cmdhandler = cmdhandler;
            cmdclient->sockfd = connfd;
            cmdclient->globalcontext = cmdhandler->globalcontext;
            cmdclient->localcontext = NULL;
            janitor_thread_create(&cmdclientthread, cmdhandlerthreadclass, &cmdhandler_accept_client, (void*) cmdclient);
        }
    }

    /* join threads */
    janitor_thread_joinall(cmdhandlerthreadclass);

    ods_log_debug("[%s] done", module_str);
    cmdhandler->stopped = 1;
}

/**
 * Self pipe trick (see Unix Network Programming).
 *
 */
static int
self_pipe_trick(cmdhandler_type* cmdhandler)
{
    int sockfd, ret;
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        ods_log_error("[engine] cannot connect to command handler: "
            "socket() failed: %s\n", strerror(errno));
        return 1;
    } else {
        ret = connect(sockfd, (const struct sockaddr*) &cmdhandler->listen_addr,
            sizeof(cmdhandler->listen_addr));
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
cmdhandler_stop(cmdhandler_type* cmdhandler)
{
    ods_log_debug("[engine] stop command handler");
    cmdhandler->need_to_exit = 1;
    if (self_pipe_trick(cmdhandler) == 0) {
        while (!cmdhandler->stopped) {
            ods_log_debug("[engine] waiting for command handler to exit...");
            sleep(1);
        }
    } else {
        ods_log_error("[engine] command handler self pipe trick failed, "
            "unclean shutdown");
    }
    janitor_thread_join(cmdhandler->thread_id);
}

const char* ods_check_command(const char *cmd, const char *scmd)
{
    size_t ncmd = strlen(scmd);
    if (strncmp(cmd, scmd, ncmd) != 0 )
        return NULL;
    else if (cmd[ncmd] == '\0')
        return &cmd[ncmd];
    else if (cmd[ncmd] != ' ')
        return NULL;
    else
        return &cmd[ncmd+1];
}
