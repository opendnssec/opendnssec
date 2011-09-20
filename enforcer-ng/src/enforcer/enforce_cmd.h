#ifndef _ENFORCER_ENFORCE_CMD_H_
#define _ENFORCER_ENFORCE_CMD_H_

#include "daemon/engine.h"

#ifdef __cplusplus
extern "C" {
#endif

void help_enforce_zones_cmd(int sockfd);

int handled_enforce_zones_cmd(int sockfd, engine_type* engine,
                              const char *cmd, ssize_t n);

#ifdef __cplusplus
}
#endif

#endif
