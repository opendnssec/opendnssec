#ifndef _POLICY_POLICIES_CMD_H_
#define _POLICY_POLICIES_CMD_H_

#include "daemon/engine.h"

void help_policies_cmd(int sockfd);

int handled_policies_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n);

#endif
