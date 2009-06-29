/*
 * $Id$
 *
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

#ifndef ENFORCER_DAEMON_H
#define ENFORCER_DAEMON_H
/* 
 * daemon.h code needed to get a daemon up and running
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
#include <inttypes.h>

#ifdef HAVE_STDBOOL_H 
# include <stdbool.h> 
#else 
# ifndef HAVE__BOOL 
# ifdef __cplusplus 
typedef bool _Bool; 
# else 
# define _Bool signed char 
# endif /* __cplusplus */
# endif /* HAVE__BOOL */
# define bool _Bool 
# define false 0 
# define true 1 
# define __bool_true_false_are_defined 1 
#endif /* HAVE_STDBOOL_H */

#include <stdint.h>
#include <unistd.h>
#include <syslog.h>

/* Define some lengths of the char*s in the struct
   MySQL allows e.g. 81 characters for the username, 
   set these stupidly high though */
#define MAX_PROG_NAME_LENGTH 255
#define MAX_USER_LENGTH 255
#define MAX_HOST_LENGTH 255
#define MAX_PASSWORD_LENGTH 255
#define MAX_SCHEMA_LENGTH 255
#define MAX_PORT_LENGTH 16
#define MAX_PID_LENGTH 255
#define MAX_LOG_USER_LENGTH 32

#ifdef LOG_DAEMON
#define DEFAULT_LOG_FACILITY LOG_DAEMON
#define DEFAULT_LOG_FACILITY_STRING "LOG_DAEMON"
#else
#define DEFAULT_LOG_FACILITY LOG_USER
#define DEFAULT_LOG_FACILITY_STRING "LOG_USER"
#endif /* LOG_DAEMON */

/* struct to hold configuration */
typedef struct
{
    /* stuff that daemons always have */
    char *program;
    bool debug;
    pid_t pid;
    char *pidfile;
    uid_t uid;
    gid_t gid;
    char *username;
		/* flag to indicate that SIGTERM was recieved */
		int term;

    /* Add app specific stuff here */
    unsigned char* user;
    unsigned char* host;
    unsigned char* password;
    unsigned char* schema;
    unsigned char* port;
    uint16_t interval;
    int keycreate;
    int backupinterval;
    int keygeninterval;

    int log_user; /* log facility (or default of LOG_DAEMON) */

} DAEMONCONFIG;


#define AUTHOR_NAME "John Dickinson"
#define COPYRIGHT_STR "Copyright (C) 2008 2009 Nominet UK"

#endif /* ENFORCER_DAEMON_H */
