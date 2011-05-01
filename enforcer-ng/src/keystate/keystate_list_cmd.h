#ifndef _KEYSTATE_LIST_CMD_H_
#define _KEYSTATE_LIST_CMD_H_

#include "daemon/engine.h"

void help_keystate_list_cmd(int sockfd);

int handled_keystate_list_cmd(int sockfd, engine_type* engine, const char *cmd, 
                            ssize_t n);

#endif
