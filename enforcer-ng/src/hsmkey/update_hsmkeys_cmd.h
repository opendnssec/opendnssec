#ifndef _HSMKEY_UPDATE_HSMKEYS_CMD_H_
#define _HSMKEY_UPDATE_HSMKEYS_CMD_H_

#include "daemon/engine.h"

#ifdef __cplusplus
extern "C" {
#endif

void help_update_hsmkeys_cmd(int sockfd);

int handled_update_hsmkeys_cmd(int sockfd, engine_type* engine, const char *cmd,
                           ssize_t n);

#ifdef __cplusplus
}
#endif

#endif
