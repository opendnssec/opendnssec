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
*
* Copyright (c) 2008 2009, John Dickinson. All rights reserved.
*
* See LICENSE for the license.
*/
#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>
#include <syslog.h>

/* struct to hold configuration */
typedef struct
{
  /* stuff that daemons always have */
	bool debug;
  pid_t pid;
  const char *pidfile;
  uid_t uid;
  gid_t gid;
  const char *username;
  
  /* Add app specific stuff here */
  char* user;
	char* host;
	char* password;
	char* schema;
  uint16_t interval;
	int keycreate;
	int backup_interval;
  int keygeninterval;
	
} DAEMONCONFIG;

#define PACKAGE_NAME "OpenDNSSEC Key Generation"
#define PACKAGE_VERSION "0.0.1"
#define AUTHOR_NAME "John Dickinson"
#define COPYRIGHT_STR "Copyright (C) 2008 2009 John Dickinson"