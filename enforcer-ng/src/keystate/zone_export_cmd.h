#ifndef _ZONE_EXPORT_CMD_H_
#define _ZONE_EXPORT_CMD_H_

#include "daemon/engine.h"

void help_zone_export_cmd(int sockfd);

int handled_zone_export_cmd(int sockfd, engine_type* engine,
                            const char *cmd, ssize_t n);

#endif
