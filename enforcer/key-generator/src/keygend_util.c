/* 
* keygend_util.c utilities needed by keygend
*
* Copyright (c) 2008 2009, John Dickinson. All rights reserved.
*
* See LICENSE for the license.
*/
#include <stdlib.h>
#include <errno.h>

#include "daemon.h"
#include "daemon_util.h"

/*
* Go to sleep
*/

void
keygensleep(DAEMONCONFIG* config)
{
  struct timeval tv;

  tv.tv_sec = config->keygeninterval;
  tv.tv_usec = 0;
  log_msg(config, LOG_INFO, "Sleeping for %i seconds.",config->keygeninterval);
  select(0, NULL, NULL, NULL, &tv);
}

