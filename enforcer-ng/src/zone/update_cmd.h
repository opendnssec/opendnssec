#ifndef _ZONE_UPDATE_ZONELIST_CMD_H_
#define _ZONE_UPDATE_ZONELIST_CMD_H_

#include "daemon/engine.h"

void help_update_zonelist_cmd(int sockfd);

int handled_update_zonelist_cmd(int sockfd, engine_type* engine, const char *cmd, 
                       ssize_t n);

#endif
