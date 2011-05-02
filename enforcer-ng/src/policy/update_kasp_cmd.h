#ifndef _POLICY_UPDATE_KASP_CMD_H_
#define _POLICY_UPDATE_KASP_CMD_H_

#include "daemon/engine.h"

void help_update_kasp_cmd(int sockfd);

int handled_update_kasp_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n);

#endif
