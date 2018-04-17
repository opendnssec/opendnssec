/*
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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

/* 
 * daemon.c code needed to get a daemon up and running
 *
 * edit the DAEMONCONFIG and cmlParse function
 * in daemon_util.[c|h] to add options specific
 * to your app
 *
 * gcc -o daemon daemon_util.c daemon.c
 *
 * Most of this is based on stuff I have seen in NSD
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "daemon.h"
#include "daemon_util.h"
#include "privdrop.h"

#include "ksm/ksm.h"
#include "ksm/dbsmsg.h"
#include "ksm/dbsdef.h"
#include "ksm/kmemsg.h"
#include "ksm/kmedef.h"
#include "ksm/ksmmsg.h"
#include "ksm/ksmdef.h"
#include "ksm/message.h"
#include "ksm/string_util.h"

#ifndef MAXPATHLEN
# define MAXPATHLEN 4096
#endif

extern int server_init(DAEMONCONFIG *config);
extern void server_main(DAEMONCONFIG *config);

DAEMONCONFIG config;

void 
sig_handler (int sig)
{
    switch (sig) {
        case SIGCHLD:
            return;
        case SIGHUP:
            return;
        case SIGALRM:
            break;
        case SIGILL:
            break;
        case SIGUSR1:
            break;
        case SIGINT:
            config.term = 2;
            break;
        case SIGTERM:
            config.term = 1;
            break;
        default:      
            break;
    }
}

int daemon_our_pidfile = 0;

void
exit_function(void)
{
	/* Only unlink pidfile if its our pidfile */
	if (daemon_our_pidfile) {
		unlink(config.pidfile);
	}
}

int
main(int argc, char *argv[]){
    int fd;
    struct sigaction action;
    const char* program;		/* Temporary for program name */
   
    config.debug = false;
    config.once = false;

    config.pidfile = NULL;
    config.pidfile_set = 0;
    config.program = NULL;
    config.host = NULL;
    config.port = NULL;
    config.user = (unsigned char *)calloc(MAX_USER_LENGTH, sizeof(char));
    config.password = (unsigned char *)calloc(MAX_PASSWORD_LENGTH, sizeof(char));
    config.schema = (unsigned char *)calloc(MAX_SCHEMA_LENGTH, sizeof(char));
    config.DSSubmitCmd = (char *)calloc(MAXPATHLEN + 1024, sizeof(char));
    config.policy = NULL;

    if (config.user == NULL || config.password == NULL || config.schema == NULL) {
        log_msg(&config, LOG_ERR, "Malloc for config struct failed");
        exit(1);
    }
    config.term = 0;

    /* Lets set up the logging first */
    /* The program name is the last component of the program file name */
    if ((program = strrchr(argv[0], '/'))) {	/* EQUALS */
        ++program;			/* Point to character after last "/" */
	}
	else {
		program = argv[0];	/* No slash, so use string given */
	}
    config.program = program;
    config.log_user = DEFAULT_LOG_FACILITY;

    log_init(config.log_user, config.program);
		
    /* useful message */
    log_msg(&config, LOG_INFO, "%s starting...", PACKAGE_NAME);

#ifdef ENFORCER_TIMESHIFT
    if (getenv("ENFORCER_TIMESHIFT")) {
        log_msg(&config, LOG_INFO, "Timeshift mode detected, running once only!");
        fprintf(stderr, "WARNING: Timeshift mode detected, running once only!\n");
        config.once = true;
        config.debug = true;
    }
#endif /* ENFORCER_TIMESHIFT */

    /* Process command line */
    cmdlParse(&config, &argc, argv);
    if(config.debug) log_msg(&config, LOG_INFO, "%s DEBUG ON.", PACKAGE_NAME);

    /* If we dont debug then fork */
    if(!config.debug){
        /* Fork */
        switch ((config.pid = fork())) {
            case 0:
                break;
            case -1:
                log_msg(&config, LOG_ERR, "fork failed: %s", strerror(errno));
                unlink(config.pidfile);
                exit(1);
            default:
                fprintf(stdout, "OpenDNSSEC ods-enforcerd started (version %s), pid %d\n", PACKAGE_VERSION, (int) config.pid);
                log_msg(&config, LOG_INFO, "%s Parent exiting...", PACKAGE_NAME);
                exit(0);
        }

        /* Detach ourselves... */
        if (setsid() == -1) {
            log_msg(&config, LOG_ERR, "setsid() failed: %s", strerror(errno));
            exit(1);
        }

        if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
            (void)dup2(fd, STDIN_FILENO);
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            if (fd > 2)
                (void)close(fd);
        }
        log_msg(&config, LOG_INFO, "%s forked OK...", PACKAGE_NAME);
    } else {
        log_msg(&config, LOG_INFO, "%s in debug mode - not forking...", PACKAGE_NAME);
    }

    action.sa_handler = sig_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGILL, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGALRM, &action, NULL);
    sigaction(SIGCHLD, &action, NULL);
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);

    /* Get perms that we will be dropping to */
    if (getPermsForDrop(&config) != 0) {
        exit(1);
    }
    
    /* Run the server specific code. You need to provide this function somewhere
        this sets our pidfile */
    if (server_init(&config) != 0) {
        exit(1);
    }

    /* make the directory for the pidfile if required; do this before we drop
       privs */
    if (createPidDir(&config) != 0) {
        exit(1);
    }

    /* 
     * Drop permissions.
     * This function exits if something goes wrong
     */
    privdrop(config.username, config.groupname, NULL);

    config.uid = geteuid();
    config.gid = getegid();
	config.pid = getpid();

	atexit(exit_function);

    log_msg(&config, LOG_NOTICE, "%s started (version %s), pid %d", PACKAGE_NAME, PACKAGE_VERSION, 
            (int) config.pid);

    MsgInit();
    MsgRegister(KME_MIN_VALUE, KME_MAX_VALUE, m_messages, ksm_log_msg);
    MsgRegister(DBS_MIN_VALUE, DBS_MAX_VALUE, d_messages, ksm_log_msg);
    MsgRegister(KSM_MIN_VALUE, KSM_MAX_VALUE, s_messages, ksm_log_msg);

    /* Do something. You need to provide this function somewhere */
    server_main(&config);

    /* Free stuff here (exit from sigs pass through) */
    MsgRundown();
    if (config.host) free(config.host);
    if (config.port) free(config.port);
    if (config.pidfile && !config.pidfile_set) free(config.pidfile);
    free(config.user);
    free(config.password);
    free(config.schema);
    free(config.DSSubmitCmd);

    StrFree(config.username);
    StrFree(config.groupname);
#if 0
    StrFree(config.chrootdir);
#endif

    exit(0);

}

