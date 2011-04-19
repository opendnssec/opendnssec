#ifndef _HSMKEY_KEYPREGEN_CMD_H_
#define _HSMKEY_KEYPREGEN_CMD_H_

#include "daemon/engine.h"

void help_keypregen_cmd(int sockfd);

int handled_keypregen_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n);

#endif
