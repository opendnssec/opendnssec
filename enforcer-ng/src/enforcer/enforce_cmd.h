#ifndef _ENFORCER_ENFORCE_CMD_H_
#define _ENFORCER_ENFORCE_CMD_H_

#include "daemon/engine.h"

void help_enforce_zones_cmd(int sockfd);

int handled_enforce_zones_cmd(int sockfd, engine_type* engine, const char *cmd,
                              ssize_t n);

#endif
