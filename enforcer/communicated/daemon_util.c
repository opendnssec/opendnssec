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
 * daemon_util.c code needed to get a daemon up and running
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <ctype.h>
#include <signal.h>

#include "daemon.h"
#include "daemon_util.h"

int
permsDrop(DAEMONCONFIG* config)
{
  if (setgid(config->gid) != 0 || setuid(config->uid) !=0) {
          log_msg(config, LOG_ERR, "unable to drop user privileges: %s", strerror(errno));
          return -1;
  }
  return 0;
}

void
log_msg(DAEMONCONFIG *config, int priority, const char *format, ...)
{
  /* TODO: if the variable arg list is bad then random errors can occur */ 
	va_list args;
	/* for testing */
	priority = LOG_ERR;
	va_start(args, format);
  vsyslog(priority, format, args);
  va_end(args);
}


static void
usage(void)
{
	fprintf(stderr, "Usage: ods_enf [OPTION]...\n");
	fprintf(stderr, "OpenDNSSEC Enforcer Daemon.\n\n");
	fprintf(stderr, "Supported options:\n");
	fprintf(stderr, "  -d          Debug.\n");
  fprintf(stderr, "  -u          Change effective uid to the specified user.\n");
  fprintf(stderr, "  -P pidfile  Specify the PID file to write.\n");
  
	fprintf(stderr, "  -h          Host.\n");
	fprintf(stderr, "  -n          User.\n");
	fprintf(stderr, "  -p          Password.\n");
	fprintf(stderr, "  -s          Database/Schema.\n");

	fprintf(stderr, "  -v          Print version.\n");
	fprintf(stderr, "  -?          This help.\n");
}

static void
version(void)
{
	fprintf(stderr, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
	fprintf(stderr, "Written by %s.\n\n", AUTHOR_NAME);
	fprintf(stderr, "%s.  This is free software.\n", COPYRIGHT_STR);
	fprintf(stderr, "There is NO warranty; not even for MERCHANTABILITY or FITNESS\n"
			"FOR A PARTICULAR PURPOSE.\n");
	exit(0);
}

int
write_data(DAEMONCONFIG *config, FILE *file, const void *data, size_t size)
{
        size_t result;

        if (size == 0)
                return 1;
        
        result = fwrite(data, 1, size, file);

        if (result == 0) {
                log_msg(config, LOG_ERR, "write failed: %s", strerror(errno));
                return 0;
        } else if (result < size) {
                log_msg(config, LOG_ERR, "short write (disk full?)");
                return 0;
        } else {
                return 1;
        }
}

int
writepid (DAEMONCONFIG *config)
{
  FILE * fd;
  char pidbuf[32];

  snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long) config->pid);

  if ((fd = fopen(config->pidfile, "w")) ==  NULL ) {
    return -1;
  }

  if (!write_data(config, fd, pidbuf, strlen(pidbuf))) {
    fclose(fd);
    return -1;
  }
  fclose(fd);

  if (chown(config->pidfile, config->uid, config->gid) == -1) {
    log_msg(config, LOG_ERR, "cannot chown %u.%u %s: %s",
      (unsigned) config->uid, (unsigned) config->gid,
      config->pidfile, strerror(errno));
    return -1;
  }

  return 0;
}



void
cmdlParse(DAEMONCONFIG* config, int *argc, char **argv)
{
	int c;
	/*
	 * Set some defaults for missing
	 * command line options
	 */
	config->debug = false;
	config->user = "kasp";
	config->password = "kasp";
	config->host = "localhost";
	config->schema = "kasp";
	config->keycreate = 1;

	/*
	 * Not really a command line option
	 * but set an interval for now
	 */
	config->interval = 300;
	config->backup_interval = 10;

	/*
	 * Read the command line
	 */
	while ((c = getopt(*argc, argv, "dv?h:u:s:p:P:n:")) != -1) {
		switch (c) {
			case 'd':
				config->debug = true;
				break;
			case 'n':
				config->user = optarg;
				break;
			case 's':
				config->schema = optarg;
				break;
			case 'p':
				config->password = optarg;
				break;
			case 'h':
				config->host = optarg;
				break;
			case 'P':
        config->pidfile = optarg;
        break;
      case 'u':
        config->username = optarg;
        /* Parse the username into uid and gid */
        config->gid = getgid();
        config->uid = getuid();
        if (*config->username) {
          struct passwd *pwd;
          if (isdigit(*config->username)) {
            char *t;
            config->uid = strtol(config->username, &t, 10);
            if (*t != 0) {
              if (*t != '.' || !isdigit(*++t)) {
                log_msg(config, LOG_ERR, "-u user or -u uid or -u uid.gid. exiting...");
                exit(1);
              }
              config->gid = strtol(t, &t, 10);
              } else {
              /* Lookup the group id in /etc/passwd */
              if ((pwd = getpwuid(config->uid)) == NULL) {
                log_msg(config, LOG_ERR, "user id %u does not exist. exiting...", (unsigned) config->uid);
                exit(1);
              } else {
                config->gid = pwd->pw_gid;
              }
              endpwent();
            }
          } else {
            /* Lookup the user id in /etc/passwd */
            if ((pwd = getpwnam(config->username)) == NULL) {
              log_msg(config, LOG_ERR, "user '%s' does not exist. exiting...", config->username);
              exit(1);
            } else {
              config->uid = pwd->pw_uid;
              config->gid = pwd->pw_gid;
            }
            endpwent();
          }
        }   
        break;
			case '?':
				usage();
				exit(0);
			case 'v':
				version();
				exit(0);
			default:
				usage();
				exit(0);
		}
	}
}

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
          break;
    case SIGTERM:
    default:      
          break;
  }
}
