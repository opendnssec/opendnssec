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
*
* Copyright (c) 2008 2009, John Dickinson. All rights reserved.
*
* See LICENSE for the license.
*/
#include <stdlib.h>

void cmdlParse(DAEMONCONFIG*, int*, char**);
void log_msg(DAEMONCONFIG* config, int priority, const char *format, ...);
int permsDrop(DAEMONCONFIG* config);
int writepid (DAEMONCONFIG *config);
void sig_handler (int sig);