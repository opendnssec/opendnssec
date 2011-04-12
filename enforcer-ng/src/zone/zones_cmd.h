#ifndef _ZONE_ZONES_CMD_H_
#define _ZONE_ZONES_CMD_H_

#include "daemon/engine.h"

void help_zones_cmd(int sockfd);

int handled_zones_cmd(int sockfd, engine_type* engine, const char *buf, ssize_t n);

#endif
