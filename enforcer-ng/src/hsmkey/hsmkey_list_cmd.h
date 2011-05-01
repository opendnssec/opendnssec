#ifndef _HSMKEY_LIST_CMD_H_
#define _HSMKEY_LIST_CMD_H_

#include "daemon/engine.h"

void help_hsmkey_list_cmd(int sockfd);

int handled_hsmkey_list_cmd(int sockfd, engine_type* engine, const char *cmd, 
                            ssize_t n);

#endif
