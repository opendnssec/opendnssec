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

#include <sys/types.h>
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

#include <ksm/ksm.h>
#include "communicator.h"

int
main(int argc, char *argv[]){
  int fd;
  struct sigaction action;
	DAEMONCONFIG config;
	
  /* useful message */
	log_msg(&config, LOG_INFO, "%s starting...", PACKAGE_NAME);
	
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
  
  /* 
  * Drop permissions.
  * You may want to move this in to the server init code
  * if you need to do other stuff such as bind to low ports first
  */
  if (permsDrop(&config) != 0) {
    unlink(config.pidfile);
    exit(1);
  }
    
  config.pid = getpid();
  if (writepid(&config) == -1) {
    log_msg(&config, LOG_ERR, "cannot write the pidfile %s: %s",
      config.pidfile, strerror(errno));
  }
  
  /* Run the server. You need to provide this function somewhere */
  if (server_init(&config) != 0) {
    unlink(config.pidfile);
    exit(1);
  }
  
  log_msg(&config, LOG_NOTICE, "%s started (version %s), pid %d", PACKAGE_NAME, PACKAGE_VERSION, 
    (int) config.pid);
  
  /* Do something. You need to provide this function somewhere */
  server_main(&config);
  
  /* NOTREACH */
  exit(0);
  
}
