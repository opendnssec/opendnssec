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

#ifndef ENFORCER_DAEMON_UTIL_H
#define ENFORCER_DAEMON_UTIL_H
/* 
 * daemon_util.h code needed to get a daemon up and running
 *
 * edit the DAEMONCONFIG and cmlParse function
 * in daemon_util.[c|h] to add options specific
 * to your app
 *
 * gcc -o daemon daemon_util.c daemon.c
 *
 * Most of this is based on stuff I have seen in NSD
 */

#include "daemon.h"
#include <stdio.h>

void cmdlParse(DAEMONCONFIG*, int*, char**);
void log_init(int facility, const char *program_name);
void log_switch(int facility, const char *facility_name, const char *program_name, int verbose);
void log_msg(DAEMONCONFIG* config, int priority, const char *format, ...);
void ksm_log_msg(const char *format);
void log_xml_error(void *ignore, const char *format, ...);
void log_xml_warn(void *ignore, const char *format, ...);
int permsDrop(DAEMONCONFIG* config);
int writepid (DAEMONCONFIG *config);
int make_directory(DAEMONCONFIG *config, const char* path);
int ReadConfig(DAEMONCONFIG *config, int verbose);
int get_lite_lock(char *lock_filename, FILE* lock_fd);
int release_lite_lock(FILE* lock_fd);
int get_log_user(const char* username, int* usernumber);

#endif /* ENFORCER_DAEMON_UTIL_H */
