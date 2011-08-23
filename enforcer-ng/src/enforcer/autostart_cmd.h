#ifndef _ENFORCER_AUTOSTART_CMD_H_
#define _ENFORCER_AUTOSTART_CMD_H_

#include "daemon/engine.h"

void help_autostart_cmd(int sockfd);

int handled_autostart_cmd(int sockfd, engine_type* engine,
                      const char *cmd, ssize_t n);

#endif
